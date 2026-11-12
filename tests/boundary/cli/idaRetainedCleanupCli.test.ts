import { describe, expect } from "vitest";

import { workspaceCliTest } from "../../support/cli/workspaceCliFixture.js";

import { elf } from "../../../src/domain/binaryTarget.fixture.js";

/**
 * An official ida-mcp server that completes the MCP handshake and then leaves
 * every tool call unanswered, as an `open_database` still running
 * auto-analysis would. It exits when REA closes its input.
 */
const UNRESPONSIVE_SERVER = `import { createInterface } from "node:readline";
const tools = ["open_database", "execute_python", "list_databases", "close_database"];
const send = (message) =>
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", ...message }) + "\\n");
for await (const line of createInterface({ input: process.stdin })) {
  const request = JSON.parse(line);
  if (request.method === "initialize")
    send({ id: request.id, result: {
      protocolVersion: request.params.protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: "unresponsive-ida-fixture", version: "1" },
    } });
  else if (request.method === "tools/list")
    send({ id: request.id, result: {
      tools: tools.map((name) => ({ name, inputSchema: { type: "object" } })),
    } });
}
`;

describe("headless IDA timeout through the one-shot CLI", () => {
  workspaceCliTest(
    "exits after a retained-cleanup failure instead of waiting on the supervisor",
    async ({ cli, workspace }) => {
      const server = await workspace.write("server.mjs", UNRESPONSIVE_SERVER);
      const workspaceRoot = await workspace.mkdir("ida-workspaces");
      const registration = await workspace.write(
        "ida-mcp.json",
        JSON.stringify({
          command: process.execPath,
          args: [server],
          mode: "headless",
          timeoutMs: 500,
          workspaceRoot,
        }),
      );
      const target = await workspace.write("target.elf", elf(2, 1, 62));

      const result = await cli.run({
        arguments: ["decompile", target, "main", "--json"],
        environment: {
          ...workspace.environment,
          REA_ANALYSIS_PROVIDER: "ida",
          REA_IDA_MCP_CONFIG: registration,
          REA_LOG_LEVEL: "silent",
        },
        timeoutMs: 30_000,
      });

      expect(result.exitCode).toBe(1);
      expect(result.json).toMatchObject({
        code: "cleanup_incomplete",
        details: {
          cleanup: "incomplete",
          execution_failure: "provider_timeout",
          operation: "procedure_pseudo_code",
          diagnostics: {
            startup_operation: "open_database",
          },
          timeout_ms: 500,
          resources: [expect.stringContaining(workspaceRoot)],
          cleanup_error: {
            code: "cleanup_incomplete",
            details: {
              provider_id: "ida",
              operation: "close",
              diagnostics: {
                upstream_instances: {
                  state: "unverified",
                  instances: [
                    {
                      instance_id: null,
                      backend: "idalib",
                      status: "attached",
                      path: expect.stringContaining(workspaceRoot),
                      error: null,
                    },
                  ],
                },
              },
            },
          },
        },
      });
      // The one-shot CLI exits after its close, so no close_binary retry exists.
      expect(JSON.stringify(result.json)).not.toContain("retry_cleanup");
    },
  );
});
