import { rm, stat } from "node:fs/promises";
import { dirname } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { z } from "zod";
import {
  createIdaTarget,
  RecordingIdaMcp,
  reaOpOf,
} from "../../tests/fixtures/idaMcp.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { createAnalysisProfile } from "../domain/analysisProfile.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { createIdaDiagnosticRedactor } from "./IdaDiagnosticRedactor.js";
import { decodeIdaToolResult } from "./IdaMcpConnection.js";
import { IDA_PROVIDER_IDENTITY } from "./IdaProviderMetadata.js";
import type { AnalysisOperation } from "../application/AnalysisProvider.js";
import { IdaSessionClient } from "./IdaSessionClient.js";

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
});

const session = async (mode: "attached" | "headless" = "headless") => {
  const { root, target } = await createIdaTarget();
  roots.push(root);
  const producer = new RecordingIdaMcp(target, mode);
  const client = new IdaSessionClient(
    {
      command: "fixture",
      args: [],
      env: {},
      mode,
      timeoutMs: 1000,
      workspaceRoot: root,
    },
    target,
    producer,
  );
  return { root, target, producer, client };
};

it("preserves a rejected execute_python diagnostic with completed resolution evidence and releases its owned worker", async () => {
  const { root, target } = await createIdaTarget();
  roots.push(root);
  const producer = new RecordingIdaMcp(target, "headless");
  const reason =
    "Invalid params: unexpected parameters: ['offset', 'max_lines']";
  const config = {
    url: "http://127.0.0.1:12345/mcp",
    headers: {
      Authorization: "Token custom-fixture-token",
      Cookie: "session=cookie-fixture-secret",
    },
    mode: "headless" as const,
    timeoutMs: 1000,
    workspaceRoot: root,
  };
  const redactor = createIdaDiagnosticRedactor(config);
  producer.beforeCall = async (name, args) => {
    if (name === "execute_python" && reaOpOf(args.code) === "pseudocode")
      decodeIdaToolResult(
        {
          isError: true,
          content: [
            {
              type: "text",
              text: reason + " (custom-fixture-token / cookie-fixture-secret)",
            },
          ],
        },
        redactor,
      );
  };
  const safeReason =
    reason +
    " ([redacted transport credential] / [redacted transport credential])";
  const client = new IdaSessionClient(config, target, producer);
  try {
    const result = await client.execute("procedure_pseudo_code", {
      procedure: "main",
    });
    if (result.ok) throw new Error("Expected the upstream rejection");
    expect(projectAnalysisError(result.error)).toMatchObject({
      code: "unreadable_output",
      details: {
        diagnostics: { reason: safeReason },
        partial_observation: {
          provider: { id: "ida" },
          operation: "procedure_pseudo_code",
          normalized_result: {
            status: "partial",
            observations: [expect.objectContaining({ tool: "execute_python" })],
            target_binding: {
              status: "not_verified",
              reason: "IDA MCP tool failed: \n" + safeReason,
            },
          },
        },
      },
    });
    expect(JSON.stringify(projectAnalysisError(result.error))).not.toContain(
      "custom-fixture-token",
    );
    expect(JSON.stringify(projectAnalysisError(result.error))).not.toContain(
      "cookie-fixture-secret",
    );
  } finally {
    const database = producer.database;
    expect((await client.close()).ok).toBe(true);
    expect(
      producer.calls.filter(({ name }) => name === "close_database"),
    ).toEqual([{ name: "close_database", args: { instance_id: database } }]);
    expect(producer.closes).toBe(1);
    await expect(stat(dirname(producer.inputPath))).rejects.toMatchObject({
      code: "ENOENT",
    });
  }
});

describe("headless IDA partial operation evidence", () => {
  it("retains completed rows when post-operation target identity changes", async () => {
    const { producer, client } = await session();
    let identityReads = 0;
    producer.overrideCall = (name, args) => {
      if (name !== "execute_python") return undefined;
      if (reaOpOf(args.code) === "identity") {
        identityReads += 1;
        if (identityReads === 2)
          return {
            result: {
              path: "/different/target.elf",
              sha256: "b".repeat(64),
              base: "0x1000",
              architecture: "metapc",
              bitness: 64,
            },
            stdout: "",
            stderr: "",
          };
      }
      return undefined;
    };
    try {
      const result = await client.execute("list_procedures", {});
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.message).toContain("identity changed");
        expect(result.error.partialObservation).toMatchObject({
          normalized_result: {
            status: "partial",
            observations: [expect.objectContaining({ tool: "execute_python" })],
            target_binding: {
              status: "not_verified",
              reason: expect.stringContaining("identity changed"),
            },
          },
          raw_result: {
            post_operation_identity_check: "started",
          },
        });
      }
    } finally {
      expect((await client.close()).ok).toBe(true);
    }
  });

  it("retains completed replies when cancellation arrives after a reply", async () => {
    const { producer, client } = await session();
    const controller = new AbortController();
    producer.beforeCall = async (name, args) => {
      if (name === "execute_python" && reaOpOf(args.code) === "inventory")
        controller.abort();
    };
    try {
      const result = await client.execute(
        "list_procedures",
        {},
        { signal: controller.signal },
      );
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error._tag).toBe("AnalysisCancelledError");
        expect(result.error.cause).toBe(controller.signal.reason);
        expect(result.error.partialObservation).toMatchObject({
          analysis_profile: null,
          normalized_result: {
            status: "partial",
            observations: [expect.objectContaining({ tool: "execute_python" })],
          },
        });
      }
    } finally {
      expect((await client.close()).ok).toBe(true);
    }
  });
});

it("retains the session analysis profile when an operation fails after a completed reply", async () => {
  const { root, producer, client } = await session();
  producer.beforeCall = async (name, args) => {
    if (name === "execute_python" && reaOpOf(args.code) === "pseudocode")
      decodeIdaToolResult({
        isError: true,
        content: [{ type: "text", text: "Decompiler failed" }],
      });
  };
  const profile = createAnalysisProfile(IDA_PROVIDER_IDENTITY, {
    mode: "headless",
    compatibility_profile: "hexrays-ida-mcp",
    database_revision: null,
    cache_policy: "live",
    registration_digest: "a".repeat(64),
  });
  const bound = new IdaSessionClient(
    {
      command: "fixture",
      args: [],
      env: {},
      mode: "headless",
      timeoutMs: 1000,
      workspaceRoot: root,
    },
    producer.target,
    producer,
    profile,
  );
  try {
    const result = await bound.execute("procedure_pseudo_code", {
      procedure: "main",
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.partialObservation).toMatchObject({
        analysis_profile: profile,
        normalized_result: {
          status: "partial",
          observations: [expect.objectContaining({ tool: "execute_python" })],
        },
      });
    }
  } finally {
    expect((await bound.close()).ok).toBe(true);
    await client.close();
  }
});

describe("headless IDA operation failures", () => {
  it.each<{
    op: string;
    operation: AnalysisOperation;
    parameters: Readonly<Record<string, JsonValue>>;
    reply: JsonValue;
  }>([
    {
      op: "pseudocode",
      operation: "procedure_pseudo_code",
      parameters: { procedure: "main" },
      reply: { text: 5 },
    },
    {
      op: "xrefs",
      operation: "xrefs",
      parameters: { address: "0x1000" },
      reply: { to: [{ from: "0x1004", type: "sideways" }] },
    },
    {
      op: "callees",
      operation: "procedure_callees",
      parameters: { procedure: "main" },
      reply: { callees: [{ name: "puts" }] },
    },
  ])(
    "fails closed on malformed $op data through $operation",
    async ({ op, operation, parameters, reply }) => {
      const { producer, client } = await session();
      producer.overrideCall = (name, args) =>
        name === "execute_python" && reaOpOf(args.code) === op
          ? { result: reply, stdout: "", stderr: "" }
          : undefined;
      try {
        const result = await client.execute(operation, parameters);
        expect(result.ok).toBe(false);
        if (!result.ok) {
          expect(result.error._tag).toBe("AnalysisOutputError");
          expect(result.error.partialObservation).toMatchObject({
            provider: { id: "ida" },
            operation,
            parameters,
            normalized_result: {
              status: "partial",
              failed_operation: operation,
              observations: expect.arrayContaining([
                expect.objectContaining({ tool: "execute_python" }),
              ]),
              metadata_before: expect.any(Object),
            },
            locations: expect.arrayContaining([
              { kind: "artifact-path", path: producer.target.path },
            ]),
          });
        }
      } finally {
        expect((await client.close()).ok).toBe(true);
      }
    },
  );
});

describe("headless IDA procedure lookup failures", () => {
  it.each([
    ["procedure_pseudo_code", "main"],
    ["procedure_address", "main"],
    ["analyze_function", "main"],
    ["read_function_instructions", "main"],
    ["procedure_pseudo_code", "0x1000"],
    ["procedure_assembly", "_missing"],
    ["procedure_pseudo_code", "main\nsecond line"],
  ] as const)(
    "reports an unresolved %s selector for %s as an invalid request naming the procedure",
    async (operation, procedure) => {
      const { producer, client } = await session();
      producer.overrideCall = (name, args) =>
        name === "execute_python" &&
        (reaOpOf(args.code) === "by_name" ||
          reaOpOf(args.code) === "containing")
          ? { result: null, stdout: "", stderr: "" }
          : undefined;
      try {
        const result = await client.execute(operation, { procedure });
        if (result.ok) throw new Error("expected invalid input");
        expect(result.error._tag, "the caller's procedure is the fault").toBe(
          "AnalysisInputError",
        );
        const projected = projectAnalysisError(result.error);
        expect(projected.code, "the public code is invalid_request").toBe(
          "invalid_request",
        );
        expect(projected.retryable).toBe(false);
        const expected = procedure.startsWith("0x")
          ? "not a function"
          : "not found";
        expect(projected.details).toMatchObject({
          operation,
          issues: [
            {
              path: [],
              reason: "invalid_value",
              message: `IDA could not resolve procedure ${JSON.stringify(procedure)}: ${expected}.`,
            },
          ],
        });
        expect(
          (result.error as AnalysisInputError).issues
            .map(({ message }) => message ?? "")
            .join(""),
          "a control character in the query is carried JSON-escaped, never raw",
        ).not.toContain("\n");
      } finally {
        expect((await client.close()).ok).toBe(true);
      }
    },
  );

  it.each([
    ["a malformed function entry", { name: 5, start: "0x1000" }],
    ["neither a function nor null", {}],
  ])("keeps %s as unreadable output", async (_label, answer) => {
    const { producer, client } = await session();
    producer.overrideCall = (name, args) =>
      name === "execute_python" && reaOpOf(args.code) === "by_name"
        ? { result: answer, stdout: "", stderr: "" }
        : undefined;
    try {
      const result = await client.execute("procedure_pseudo_code", {
        procedure: "main",
      });
      if (result.ok) throw new Error("expected unreadable output");
      expect(result.error._tag, "a producer fault, not caller input").toBe(
        "AnalysisOutputError",
      );
      expect(projectAnalysisError(result.error).code).toBe("unreadable_output");
    } finally {
      expect((await client.close()).ok).toBe(true);
    }
  });
});

describe("provider-derived procedure selectors", () => {
  it("reports a derived selector the producer cannot resolve as a producer fault", async () => {
    const { producer, client } = await session();
    producer.overrideCall = (name, args) => {
      const op = reaOpOf(args.code);
      if (name !== "execute_python") return undefined;
      if (op === "by_name" || op === "containing")
        return { result: null, stdout: "", stderr: "" };
      return undefined;
    };
    try {
      const result = await client.execute(
        "procedure_callees",
        { procedure: "0x2000" },
        { selectorOrigin: "provider" },
      );
      if (result.ok) throw new Error("expected a producer fault");
      expect(result.error._tag, "not the caller's mistake").toBe(
        "AnalysisProtocolError",
      );
      expect(projectAnalysisError(result.error).code).toBe("unreadable_output");
    } finally {
      expect((await client.close()).ok).toBe(true);
    }
  });
});

it("leaves an MCP error reply for an unknown name as unreadable output", async () => {
  const { producer, client } = await session("attached");
  producer.beforeCall = async (name, args) => {
    if (name === "execute_python" && reaOpOf(args.code) === "by_name")
      decodeIdaToolResult({
        content: [{ type: "text", text: "Function not found: main" }],
        isError: true,
      });
  };
  try {
    const result = await client.execute("procedure_pseudo_code", {
      procedure: "main",
    });
    if (result.ok) throw new Error("expected unreadable output");
    expect(result.error._tag).toBe("AnalysisProtocolError");
    expect(projectAnalysisError(result.error).code).toBe("unreadable_output");
  } finally {
    expect((await client.close()).ok).toBe(true);
  }
});
