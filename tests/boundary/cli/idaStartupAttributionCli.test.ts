import { createVerifierHttpServer } from "../../../scripts/lib/verifier-http-server.mjs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { expect } from "vitest";
import { z } from "zod";
import { workspaceCliTest } from "../../support/cli/workspaceCliFixture.js";
import { elf } from "../../../src/domain/binaryTarget.fixture.js";

const tools = [
  "open_database",
  "execute_python",
  "list_databases",
  "close_database",
];
const requestSchema = z.object({
  id: z.union([z.string(), z.number()]).optional(),
  method: z.string(),
  params: z
    .object({
      protocolVersion: z.string().optional(),
      name: z.string().optional(),
      arguments: z.record(z.string(), z.unknown()).optional(),
    })
    .optional(),
});
const opMarker = /^# rea-op:(\w+)\n# rea-args:(\{.*\})\n([\s\S]*)$/u;

type StartupMode =
  | "missing-profile"
  | "connect-timeout"
  | "catalog-timeout"
  | "catalog-refused"
  | "headless-input-mismatch"
  | "instance-inventory"
  | "success";

type StartupServerState = {
  readonly mode: StartupMode;
  readonly calls: string[];
  instanceId: string | undefined;
  input: string | undefined;
};
const handleStartupRequest = async (
  state: StartupServerState,
  request: IncomingMessage,
  response: ServerResponse,
) => {
  if (request.method !== "POST") {
    response.writeHead(405).end();
    return;
  }
  let body = "";
  for await (const chunk of request) body += String(chunk);
  const rpc = requestSchema.parse(JSON.parse(body));
  if (rpc.id === undefined) {
    response.writeHead(202).end();
    return;
  }
  const send = (result: unknown) =>
    response
      .writeHead(200, { "Content-Type": "application/json" })
      .end(JSON.stringify({ jsonrpc: "2.0", id: rpc.id, result }));
  if (rpc.method === "initialize") {
    if (state.mode === "connect-timeout") return;
    send({
      protocolVersion: rpc.params?.protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: "ida-startup-fixture", version: "1" },
    });
    return;
  }
  if (rpc.method === "tools/list") {
    if (state.mode === "catalog-timeout") return;
    if (state.mode === "catalog-refused") {
      response.writeHead(200, { "Content-Type": "application/json" }).end(
        JSON.stringify({
          jsonrpc: "2.0",
          id: rpc.id,
          error: { code: -32603, message: "fixture catalog refused" },
        }),
      );
      return;
    }
    send({
      tools: tools
        .filter(
          (name) =>
            state.mode !== "missing-profile" || name !== "execute_python",
        )
        .map((name) => ({
          name,
          inputSchema: { type: "object", properties: {} },
        })),
    });
    return;
  }
  const name = rpc.params?.name;
  const args = rpc.params?.arguments;
  if (name === undefined || args === undefined)
    throw new Error("Unexpected RPC");
  state.calls.push(name);
  let result: unknown;
  if (name === "open_database") {
    state.input = z.string().parse(args.path);
    state.instanceId = "fixture-instance-1";
    result = {
      instance_id:
        state.mode === "instance-inventory"
          ? "missing-instance"
          : state.instanceId,
      backend: "idalib",
      status: "attached",
      recovery: "none",
      log_path: `${state.input}.log`,
      mcp_id: null,
      hint: null,
    };
  } else if (name === "list_databases")
    result = {
      instances:
        state.instanceId === undefined || state.mode === "instance-inventory"
          ? []
          : [
              {
                path: state.input,
                backend: "idalib",
                status: "attached",
                instance_id: state.instanceId,
                error: null,
              },
            ],
    };
  else if (name === "close_database") {
    result = {
      closed: true,
      final_lease: true,
      idb_path: `${state.input}.i64`,
    };
    state.instanceId = undefined;
  } else if (name === "execute_python") {
    const op = opMarker.exec(z.string().parse(args.code))?.[1];
    if (op === "identity")
      result = {
        result: {
          path:
            state.mode === "headless-input-mismatch"
              ? `${state.input}.other`
              : state.input,
          sha256: null,
          base: "0x1000",
          architecture: "metapc",
          bitness: 64,
        },
        stdout: "",
        stderr: "",
      };
    else if (op === "by_name")
      result = {
        result: { name: "main", start: "0x1000" },
        stdout: "",
        stderr: "",
      };
    else if (op === "pseudocode")
      result = {
        result: { text: "int main(void) { return 42; }" },
        stdout: "",
        stderr: "",
      };
    else throw new Error("Unexpected operation: " + String(op));
  } else throw new Error("Unexpected tool: " + name);
  send({ content: [{ type: "text", text: JSON.stringify(result) }] });
};

const createStartupServer = async (mode: StartupMode) => {
  const state: StartupServerState = {
    mode,
    calls: [],
    instanceId: undefined,
    input: undefined,
  };
  const server = await createVerifierHttpServer((request, response) =>
    handleStartupRequest(state, request, response),
  );
  await new Promise<void>((resolve) => {
    server.server.listen(0, "127.0.0.1", () => resolve());
  });
  return { server, calls: state.calls, state };
};

workspaceCliTest.for([
  "missing-profile",
  "connect-timeout",
  "catalog-timeout",
  "catalog-refused",
  "headless-input-mismatch",
  "instance-inventory",
  "success",
] as const)(
  "attributes selected IDA startup to the public analysis: %s",
  async (mode, { cli, workspace }) => {
    const startup = await createStartupServer(mode);
    const { server, calls, state } = startup;
    try {
      const address = server.server.address();
      if (address === null || typeof address === "string")
        throw new Error("Missing server address");
      const workspaceRoot = await workspace.mkdir("ida-workspaces");
      const registration = await workspace.write(
        "ida.json",
        JSON.stringify({
          url: `http://127.0.0.1:${address.port}/mcp`,
          mode: "headless",
          timeoutMs: 500,
          workspaceRoot,
        }),
      );
      const target = await workspace.write("target.elf", elf(2, 1, 62));
      const result = await cli.run({
        arguments: ["decompile", target, "main", "--provider", "ida", "--json"],
        environment: {
          ...workspace.environment,
          REA_IDA_MCP_CONFIG: registration,
          REA_LOG_LEVEL: "silent",
        },
        timeoutMs: 15000,
      });
      expect(result.stderr).toBe("");
      expect(state.instanceId).toBeUndefined();
      if (mode === "success") {
        expect(result.exitCode).toBe(0);
        expect(result.json).toMatchObject({
          operation: "procedure_pseudo_code",
          normalized_result: "int main(void) { return 42; }",
        });
        expect(calls).toContain("execute_python");
        expect(calls).toContain("close_database");
        return;
      }
      expect(result.exitCode).toBe(1);
      if (mode === "headless-input-mismatch" || mode === "instance-inventory") {
        expect(calls).toContain("close_database");
        expect(result.json).toMatchObject({
          code: "unreadable_output",
          retryable: false,
          message: expect.stringContaining(
            mode === "headless-input-mismatch"
              ? "input identity changed"
              : "database inventory",
          ),
          remediation: {
            action: expect.stringContaining(
              mode === "headless-input-mismatch" ? "reopen" : "lists opened",
            ),
          },
          details: {
            operation: "procedure_pseudo_code",
            diagnostics: {
              identity_check:
                mode === "headless-input-mismatch"
                  ? "headless_input"
                  : "instance_inventory",
              reason: expect.any(String),
              recovery: expect.any(String),
            },
          },
        });
        return;
      }
      expect(calls).toEqual([]);
      expect(result.json).toMatchObject({
        code: mode.endsWith("timeout")
          ? "provider_timeout"
          : "execution_failure",
        details: { operation: "procedure_pseudo_code" },
      });
      if (mode === "catalog-refused")
        expect(result.json).toMatchObject({
          details: { diagnostics: { reason: "fixture catalog refused" } },
        });
      if (mode === "missing-profile")
        expect(result.json).toMatchObject({
          details: {
            diagnostics: {
              missing_tools: ["execute_python"],
              startup_operation: "initialize",
            },
          },
        });
      if (mode.endsWith("timeout"))
        expect(result.json).toMatchObject({
          retryable: true,
          details: {
            timeout_ms: 500,
            captured_output: { stdout: "", stderr: "", truncated: false },
            diagnostics: {
              startup_operation:
                mode === "connect-timeout"
                  ? "ida_mcp_connect"
                  : "ida_mcp_catalog",
            },
          },
        });
    } finally {
      await server.close();
    }
  },
);
