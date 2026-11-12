import { createIdaMcpConnection } from "./IdaMcpConnection.js";
import { readdir, readFile, rm, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import {
  createIdaTarget,
  RecordingIdaMcp,
  reaOpOf,
} from "../../tests/fixtures/idaMcp.js";
import { IdaSessionClient } from "./IdaSessionClient.js";
import {
  DEFAULT_REGEX_MATCHING_DEADLINE,
  REGEX_MATCHING_DEADLINE_SETTING,
} from "../config/regexMatchingDeadline.js";
import { functionDossierSchema } from "../domain/native/functionDossier.js";
import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";
import {
  AnalysisProtocolError,
  AnalysisResourceConstraintError,
  AnalysisCancelledError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { WindowsPrivateRuntime } from "../windows/WindowsPrivateRuntime.js";

const roots: string[] = [];
const windowsRuntimes = new Set<WindowsPrivateRuntime>();
beforeEach(() => {
  if (process.platform !== "win32") return;
  const create = WindowsPrivateRuntime.create;
  vi.spyOn(WindowsPrivateRuntime, "create").mockImplementation(
    (parent, prefix) => {
      const runtime = create(parent, prefix);
      windowsRuntimes.add(runtime);
      return runtime;
    },
  );
});
afterEach(async () => {
  try {
    // These pure producer fixtures spawn no IDA worker. After the retention
    // assertions, release only the actual native owners this test created.
    for (const runtime of windowsRuntimes) {
      await runtime.close();
      windowsRuntimes.delete(runtime);
    }
    for (const root of roots.splice(0))
      await rm(root, { recursive: true, force: true });
  } finally {
    vi.restoreAllMocks();
  }
});

/** A failed close whose diagnostic names exactly these unverified instances. */
const reportsInstances = (...instances: readonly object[]) => ({
  error: {
    diagnostics: { upstream_instances: { state: "unverified", instances } },
  },
});

const fixture = async (
  mode: "attached" | "headless" = "attached",
  timeoutMs = 1000,
) => {
  const { root, target } = await createIdaTarget();
  roots.push(root);
  const producer = new RecordingIdaMcp(target, mode);
  const client = new IdaSessionClient(
    {
      command: "fixture",
      args: [],
      env: {},
      mode,
      timeoutMs,
      workspaceRoot: root,
    },
    target,
    producer,
  );
  return { root, target, producer, client };
};

const executeOp = (op: string, reply: JsonValue): JsonValue => ({
  result: reply,
  stdout: "",
  stderr: "",
});
const opCall = (
  producer: RecordingIdaMcp,
  op: string,
  reply: (args: Readonly<Record<string, JsonValue>>) => JsonValue | undefined,
) => {
  const inner = producer.overrideCall;
  producer.overrideCall = (name, args) =>
    name === "execute_python" && reaOpOf(args.code) === op
      ? executeOp(op, reply(args) ?? { unexpected: true })
      : (inner?.(name, args) ?? undefined);
};

it.each([
  new Error("HTTP 404: fixture response"),
  new ProviderAdapterError("ida", "transport", {
    diagnostics: { reason: "fixture response" },
  }),
  new AnalysisTimeoutError("ida_mcp_connect", 1000),
  new AnalysisProtocolError("Malformed MCP response"),
  new AnalysisResourceConstraintError(
    "ida_mcp_connect",
    "transport",
    "fixture limit",
    { max_response_bytes: 1 },
  ),
])(
  "retains the selected HTTP endpoint on a connection failure",
  async (cause) => {
    const { root, target } = await createIdaTarget();
    roots.push(root);
    const producer = new RecordingIdaMcp(target, "attached");
    vi.spyOn(producer, "connect").mockRejectedValue(cause);
    const selected = "HTTP://LOCALHOST:01234/mcp?cursor=kept";
    const client = new IdaSessionClient(
      {
        url: selected,
        headers: { Authorization: "Bearer fixture-secret" },
        mode: "attached",
        timeoutMs: 1000,
      },
      target,
      producer,
    );
    const result = await client.execute("list_procedures", {});
    if (result.ok) throw new Error("Expected connection failure");
    expect(result.error.diagnostics).toMatchObject({ endpoint: selected });
    expect(JSON.stringify(projectAnalysisError(result.error))).not.toContain(
      "fixture-secret",
    );
    await client.close();
  },
);

it.each([
  "fixture-secret",
  "fixture%2Dsecret",
  "fixture%2dsecret",
  "%66%69%78%74%75%72%65-secret",
])(
  "redacts a known transport credential in the selected endpoint: %s",
  async (encoded) => {
    const { root, target } = await createIdaTarget();
    roots.push(root);
    const producer = new RecordingIdaMcp(target, "attached");
    vi.spyOn(producer, "connect").mockRejectedValue(
      new Error("fixture failure"),
    );
    const client = new IdaSessionClient(
      {
        url: `http://localhost:1234/mcp?token=${encoded}&cursor=keep`,
        headers: { Authorization: "Bearer fixture-secret" },
        mode: "attached",
        timeoutMs: 1000,
      },
      target,
      producer,
    );
    const result = await client.execute("list_procedures", {});
    if (result.ok) throw new Error("Expected connection failure");
    const output = JSON.stringify(projectAnalysisError(result.error));
    expect(output).not.toContain("fixture-secret");
    expect(output).not.toContain(encoded);
    expect(output).toContain("http://localhost:1234/mcp?token=");
    expect(output).toContain("&cursor=keep");
    await client.close();
  },
);

it.each(["initialize", "transport"])(
  "preserves producer outcome facts when attributing a cached %s failure",
  async (operation) => {
    const { producer, client } = await fixture();
    const primary = new AnalysisCancelledError("provider_startup");
    const source = new ProviderAdapterError("ida", operation, {
      cleanupPrimary: primary,
      limit: {
        setting: "regex.matching_deadline_ms",
        effective_value: 100,
        unit: "ms",
        minimum: 1,
        maximum: 1000,
        applies_at: "next_operation",
        agent_editable: true,
        scope: "rea-runtime",
        update_mode: "runtime",
        pending_restart: false,
      },
      diagnostics: { producer_fact: "retained" },
    });
    const connect = vi.spyOn(producer, "connect").mockRejectedValue(source);
    for (const requested of ["list_procedures", "list_strings"] as const) {
      const result = await client.execute(requested, {});
      if (result.ok) throw new Error("Expected startup failure");
      expect(result.error).toBeInstanceOf(ProviderAdapterError);
      expect(result.error).toMatchObject({
        operation: requested,
        limit: source.limit,
        cleanupPrimary: { operation: requested },
        diagnostics: { producer_fact: "retained" },
      });
      expect(result.error.cleanupPrimary).toBeInstanceOf(
        AnalysisCancelledError,
      );
    }
    expect(connect).toHaveBeenCalledTimes(1);
    expect(source.operation).toBe(operation);
    expect(source.cleanupPrimary).toBe(primary);
    await client.close();
  },
);

describe("attached IDA readiness and queued cancellation", () => {
  it("allows ready-only work after an attached provider has initialized", async () => {
    const { producer, client } = await fixture("attached");
    await expect(client.executeIfReady("list_procedures", {})).resolves.toBe(
      undefined,
    );

    const startup = await client.execute("list_procedures", {});
    if (!startup.ok) throw startup.error;
    const result = await client.executeIfReady("list_procedures", {});
    if (result === undefined)
      throw new Error("expected ready attached IDA dispatch");
    if (!result.ok) throw result.error;
    expect(result.value.result).toEqual([
      expect.objectContaining({ address: "0x1000", value: "main" }),
    ]);
    expect(
      producer.calls.filter(({ name }) => name === "open_database"),
    ).toHaveLength(1);
    await client.close();
  });

  it("returns cold and pending startup calls immediately, then cancels queued work before dispatch", async () => {
    const { producer, client } = await fixture("headless");
    await expect(client.executeIfReady("list_procedures", {})).resolves.toBe(
      undefined,
    );
    expect(producer.connects).toBe(0);

    let enterOpen: (() => void) | undefined;
    let finishOpen: (() => void) | undefined;
    const openEntered = new Promise<void>((resolve) => {
      enterOpen = resolve;
    });
    const openGate = new Promise<void>((resolve) => {
      finishOpen = resolve;
    });
    producer.beforeCall = async (name) => {
      if (name === "open_database") {
        enterOpen?.();
        await openGate;
      }
    };
    const startup = client.execute("list_procedures", {});
    await openEntered;
    await expect(client.executeIfReady("list_strings", {})).resolves.toBe(
      undefined,
    );
    expect(
      producer.calls.filter(({ name }) => name === "open_database"),
    ).toHaveLength(1);
    finishOpen?.();
    const started = await startup;
    if (!started.ok) throw started.error;
    const warm = await client.executeIfReady("list_procedures", {});
    if (warm === undefined) throw new Error("expected ready IDA dispatch");
    if (!warm.ok) throw warm.error;
    expect(warm.value.result).toEqual([
      expect.objectContaining({ address: "0x1000", value: "main" }),
    ]);

    let enterRead: (() => void) | undefined;
    let finishRead: (() => void) | undefined;
    const readEntered = new Promise<void>((resolve) => {
      enterRead = resolve;
    });
    const readGate = new Promise<void>((resolve) => {
      finishRead = resolve;
    });
    producer.beforeCall = async (name, args) => {
      if (name === "execute_python" && reaOpOf(args.code) === "inventory") {
        enterRead?.();
        await readGate;
      }
    };
    const active = client.execute("list_procedures", {});
    await readEntered;
    const controller = new AbortController();
    const queued = client.executeIfReady(
      "list_strings",
      {},
      {
        signal: controller.signal,
      },
    );
    controller.abort();
    await expect(queued).resolves.toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCancelledError" },
    });
    finishRead?.();
    const activeResult = await active;
    if (!activeResult.ok) throw activeResult.error;
    expect(
      producer.calls.filter(
        ({ name, args }) =>
          name === "execute_python" && reaOpOf(args.code) === "inventory",
      ),
    ).toHaveLength(3);
    await client.close();
  });
});

describe("attached IDA input identity and validation", () => {
  it("rejects an unrelated document before connecting or opening a provider", async () => {
    const { producer, client } = await fixture();
    const result = await client.execute("list_procedures", {
      document: "/unrelated/input",
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error._tag).toBe("AnalysisInputError");
      expect(result.error.message).toContain("list_procedures");
    }
    expect(producer.connects).toBe(0);
    expect(producer.calls).toEqual([]);
    await client.close();
  });

  it("preserves omitted optional arguments and rejects explicit null before connecting", async () => {
    const { producer, client } = await fixture();
    for (const [operation, parameters] of [
      ["list_procedures", { document: null }],
      ["list_strings", { address: null }],
      ["procedure_pseudo_code", { procedure: null }],
    ] as const) {
      const result = await client.execute(operation, parameters);
      expect(result.ok).toBe(false);
      if (!result.ok)
        expect(result.error).toMatchObject({
          _tag: "AnalysisInputError",
          operation,
          issues: [{ path: Object.keys(parameters), reason: "invalid_type" }],
        });
    }
    expect(producer.connects).toBe(0);
    expect(producer.calls).toEqual([]);
    expect((await client.execute("list_procedures", {})).ok).toBe(true);
    expect((await client.execute("list_strings", {})).ok).toBe(true);
    expect(
      (await client.execute("procedure_pseudo_code", { procedure: "main" })).ok,
    ).toBe(true);
    await client.close();
  });
});

describe("attached IDA function observations", () => {
  it("resolves procedures, preserves callers and callees, and reports unknown body evidence", async () => {
    const { producer, client } = await fixture();
    const result = await client.execute("analyze_function", {
      procedure: "0x1004",
    });
    if (!result.ok) throw result.error;
    const dossier = functionDossierSchema.parse(result.value.result);
    expect(dossier.procedure.address).toBe("0x1000");
    expect(dossier.callers.map((caller) => caller.address)).toEqual(["0x1000"]);
    expect(dossier.callees.map((callee) => callee.address)).toEqual(["0x2000"]);
    expect(dossier.procedure.body.available).toBe(false);
    expect(dossier.comments).toEqual([]);
    expect(result.value.rawResult).toMatchObject({
      observations: expect.arrayContaining([
        expect.objectContaining({ tool: "execute_python" }),
      ]),
    });
    expect(result.value.provider.version).toBe("1");
    await client.close();
    expect(producer.calls.some(({ name }) => name === "close_database")).toBe(
      true,
    );
  });
  it("distinguishes literal from regex string search against one inventory", async () => {
    const { client } = await fixture();
    for (const [pattern, mode, count] of [
      ["a.b", "literal", 1],
      ["a+b", "regex", 0],
      ["zz", "literal", 0],
    ] as const) {
      const found = await client.execute("search_strings", { pattern, mode });
      expect(found.ok && found.value.result).toHaveLength(count);
    }
    const invalid = await client.execute("search_strings", {
      pattern: "[",
      mode: "regex",
    });
    if (invalid.ok) throw new Error("Expected invalid-pattern refusal");
    expect(projectAnalysisError(invalid.error)).toMatchObject({
      code: "invalid_request",
      message: expect.stringContaining("Invalid regex pattern"),
    });
    await client.close();
  });
});

describe("attached IDA regex supervision", () => {
  it.each(["search_procedures", "search_strings"] as const)(
    "preserves Unicode case semantics and inventory order in %s",
    async (operation) => {
      const { producer, client } = await fixture();
      const values = ["skip", "ÄPFEL", "äpfel"];
      opCall(
        producer,
        operation === "search_strings" ? "strings" : "inventory",
        () =>
          operation === "search_strings"
            ? {
                strings: values.map((text, index) => ({
                  address: `0x${(0x3000 + index).toString(16)}`,
                  length: text.length,
                  text,
                })),
              }
            : {
                functions: values.map((name, index) => ({
                  name,
                  start: `0x${(0x1000 + index).toString(16)}`,
                  end: `0x${(0x1010 + index).toString(16)}`,
                })),
              },
      );
      try {
        for (const case_sensitive of [false, true]) {
          const found = await client.execute(operation, {
            pattern: "^ä",
            mode: "regex",
            case_sensitive,
          });
          expect(found.ok && found.value.result).toEqual(
            values.flatMap((value, index) =>
              index === 0 || (case_sensitive && index === 1)
                ? []
                : [
                    {
                      address: `0x${((operation === "search_strings" ? 0x3000 : 0x1000) + index).toString(16)}`,
                      value,
                    },
                  ],
            ),
          );
        }
      } finally {
        await client.close();
      }
    },
  );

  it.each(["search_procedures", "search_strings"] as const)(
    "cancels CPU-bound %s matching and keeps the session usable",
    async (operation) => {
      const { producer, client } = await fixture();
      const value = "a".repeat(26) + "!";
      opCall(
        producer,
        operation === "search_strings" ? "strings" : "inventory",
        () =>
          operation === "search_strings"
            ? {
                strings: [
                  { address: "0x3000", length: value.length, text: value },
                ],
              }
            : {
                functions: [
                  {
                    name: value,
                    start: "0x1000",
                    end: "0x1020",
                  },
                ],
              },
      );
      await client.execute("health", {});
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 50);
      try {
        const result = await client.execute(
          operation,
          { pattern: "^(a+)+$", mode: "regex" },
          { signal: controller.signal },
        );
        expect(result.ok).toBe(false);
        if (!result.ok)
          expect(result.error._tag).toBe("AnalysisCancelledError");
        const recovered = await client.execute(operation, {
          pattern: "!",
          mode: "literal",
        });
        expect(recovered.ok && recovered.value.result).toHaveLength(1);
      } finally {
        clearTimeout(timer);
        await client.close();
      }
    },
    15_000,
  );

  it("bounds regex matching without caller cancellation and preserves subsequent searches", async () => {
    const { producer, client } = await fixture();
    const value = "a".repeat(40) + "!";
    opCall(producer, "strings", () => ({
      strings: [{ address: "0x3000", length: value.length, text: value }],
    }));
    try {
      const result = await client.execute("search_strings", {
        pattern: "^(a+)+$",
        mode: "regex",
      });
      expect(result.ok).toBe(false);
      if (
        result.ok ||
        !(result.error instanceof AnalysisResourceConstraintError)
      )
        throw new Error("Expected a supervised regex deadline");
      expect(result.error).toMatchObject({
        operation: "search_strings",
        resource: "cpu",
        reportedLimits: {
          matching_deadline_ms: DEFAULT_REGEX_MATCHING_DEADLINE.deadlineMs,
          matching_deadline_source: DEFAULT_REGEX_MATCHING_DEADLINE.source,
        },
      });
      expect(result.error.message).toContain(REGEX_MATCHING_DEADLINE_SETTING);
      const recovered = await client.execute("search_strings", {
        pattern: "!$",
        mode: "regex",
      });
      expect(recovered.ok && recovered.value.result).toEqual([
        expect.objectContaining({ address: "0x3000", value }),
      ]);
      if (recovered.ok)
        expect(recovered.value.limitations.join("\n")).toContain(
          REGEX_MATCHING_DEADLINE_SETTING,
        );
    } finally {
      await client.close();
    }
  }, 15_000);
});

describe("attached IDA identity refusals", () => {
  it("rejects a SHA-256 mismatch rather than returning a successful observation", async () => {
    const { producer, client, target } = await fixture();
    producer.inputSha256 = "a".repeat(64);
    const mismatch = await client.execute("health", {});
    expect(mismatch.ok).toBe(false);
    if (!mismatch.ok) {
      expect(projectAnalysisError(mismatch.error)).toMatchObject({
        code: "unreadable_output",
        retryable: false,
        message: expect.stringContaining("SHA-256"),
        remediation: { action: expect.stringContaining("headless mode") },
        details: {
          operation: "health",
          diagnostics: {
            identity_check: "attached_sha256",
            reason: expect.stringContaining(target.path),
          },
        },
      });
    }
    await client.close();
  });

  it("rejects a changed image base during the session", async () => {
    const { producer, client } = await fixture();
    producer.beforeCall = async (name, args) => {
      if (name === "execute_python" && reaOpOf(args.code) === "pseudocode")
        producer.imageBase = "0x2000";
    };
    const changed = await client.execute("procedure_pseudo_code", {
      procedure: "main",
    });
    expect(changed.ok).toBe(false);
    if (!changed.ok) expect(changed.error.message).toContain("changed");
    await client.close();
  });

  it("refuses a headless worker when attached mode requires the IDA GUI", async () => {
    const { producer, client } = await fixture();
    producer.overrideCall = (name) => {
      if (name !== "open_database") return undefined;
      return {
        instance_id: "fixture-instance-headless",
        backend: "idalib",
        status: "attached",
      };
    };
    const result = await client.execute("health", {});
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(projectAnalysisError(result.error).message).toContain("GUI");
      expect(projectAnalysisError(result.error).details).toMatchObject({
        diagnostics: { identity_check: "attached_backend" },
      });
    }
    await client.close();
  });
});

describe("attached and headless malformed producer data", () => {
  it.each(["attached", "headless"] as const)(
    "fails closed on a malformed inventory reply in %s mode",
    async (mode) => {
      const { producer, client } = await fixture(mode);
      opCall(producer, "inventory", () => ({ functions: [{ name: "main" }] }));
      const malformed = await client.execute("list_procedures", {});
      expect(malformed.ok).toBe(false);
      if (!malformed.ok)
        expect(malformed.error._tag).toBe("AnalysisOutputError");
      await client.close();
    },
  );

  it("fails closed on a non-JSON execute_python failure reply", async () => {
    const { producer, client } = await fixture("headless");
    const inner = producer.overrideCall;
    producer.overrideCall = (name, args) => {
      if (name === "execute_python" && reaOpOf(args.code) === "inventory")
        return "Traceback (most recent call last): engine refused";
      return inner?.(name, args) ?? undefined;
    };
    const result = await client.execute("list_procedures", {});
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error._tag).toBe("AnalysisProtocolError");
      expect(result.error.message).toContain("Traceback");
    }
    await client.close();
  });
});

describe("IDA compatibility profile mismatch", () => {
  it("names every missing tool so the caller can identify the upstream server", async () => {
    const { producer, client } = await fixture("headless");
    producer.tools = ["open_database", "execute_python", "list_databases"];
    const result = await client.execute("health", {});
    expect(result.ok, "an incomplete server cannot serve analysis").toBe(false);
    if (result.ok) return;
    expect(projectAnalysisError(result.error).details).toMatchObject({
      provider_id: "ida",
      diagnostics: {
        mode: "headless",
        expected_profile: "hexrays",
        missing_tools: ["close_database"],
      },
    });
    expect(producer.calls).toEqual([]);
  });
});

describe("attached and headless lifecycle", () => {
  it("shares an in-flight close across concurrent cleanup callers", async () => {
    const { producer, client } = await fixture("headless");
    expect((await client.execute("health", {})).ok).toBe(true);

    let release: (() => void) | undefined;
    let notify: (() => void) | undefined;
    const closeStarted = new Promise<void>((resolve) => {
      notify = resolve;
    });
    producer.beforeCall = async (name) => {
      if (name !== "close_database") return;
      notify?.();
      await new Promise<void>((resolve) => {
        release = resolve;
      });
    };

    const first = client.close();
    await closeStarted;
    const second = client.close();
    release?.();
    const results = await Promise.all([first, second]);

    expect(results.every((result) => result.ok)).toBe(true);
    expect(
      producer.calls.filter(({ name }) => name === "close_database"),
    ).toHaveLength(1);
    expect(producer.closes).toBe(1);
  });

  it("retains the workspace after an unconfirmed open, even when inventory is empty, and never retries startup implicitly", async () => {
    const { producer, client, root } = await fixture("headless");
    producer.beforeCall = async (name) => {
      if (name === "open_database")
        throw new Error("Timed out while the worker may still be opening");
    };
    expect((await client.execute("health", {})).ok).toBe(false);
    expect((await client.execute("health", {})).ok).toBe(false);
    expect(
      producer.calls.filter(({ name }) => name === "open_database"),
    ).toHaveLength(1);
    const closed = await client.close();
    expect(closed.ok).toBe(false);
    if (!closed.ok) expect(closed.error.cleanupIncomplete).toBe(true);
    expect(
      (await readdir(root)).some((name) => name.startsWith("rea-ida-")),
    ).toBe(true);
    expect(producer.closes).toBe(0);
  });

  it("opens a private digest-verified copy, scopes requests, closes its instance, and removes only its workspace", async () => {
    const { producer, client, root, target } = await fixture("headless");
    const original = await readFile(target.path);
    const result = await client.execute("analyze_function", {
      procedure: "main",
    });
    if (!result.ok) throw result.error;
    expect(producer.inputPath).not.toBe(target.path);
    expect(Buffer.compare(await readFile(producer.inputPath), original)).toBe(
      0,
    );
    const opened = producer.calls.find(({ name }) => name === "open_database");
    expect(opened?.args).toMatchObject({ set_current: true });
    for (const call of producer.calls.filter(
      ({ name }) => name === "execute_python",
    ))
      expect(call.args.instance_id).toBe(producer.database);
    expect((await client.close()).ok).toBe(true);
    expect(
      producer.calls.find(({ name }) => name === "close_database")?.args,
    ).toEqual({ instance_id: producer.database ?? expect.any(String) });
    expect(await readdir(root)).toEqual(["target.elf"]);
    expect(Buffer.compare(await readFile(target.path), original)).toBe(0);
  });

  it("retains the private workspace and reports cleanup failure when worker release is unverified", async () => {
    const { producer, client, root } = await fixture("headless");
    await client.execute("health", {});
    const instanceId = producer.database;
    producer.failClose = true;
    const result = await client.close();
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.cleanupIncomplete).toBe(true);
    expect(result).toMatchObject(
      reportsInstances({
        instance_id: instanceId,
        backend: "idalib",
        status: "attached",
        path: producer.inputPath,
      }),
    );
    expect(
      (await readdir(root)).some((name) => name.startsWith("rea-ida-")),
    ).toBe(true);
    await expect(stat(dirname(producer.inputPath))).resolves.toBeDefined();
  });
});

describe("headless release verification", () => {
  it("retries failed worker release through the retained connection before removing its workspace", async () => {
    const { producer, client, root } = await fixture("headless");
    expect((await client.execute("health", {})).ok).toBe(true);
    producer.failClose = true;
    expect((await client.close()).ok).toBe(false);
    expect(producer.closes).toBe(0);
    expect(
      (await readdir(root)).some((name) => name.startsWith("rea-ida-")),
    ).toBe(true);
    producer.failClose = false;
    expect((await client.close()).ok).toBe(true);
    expect(
      producer.calls.filter(({ name }) => name === "close_database"),
    ).toHaveLength(2);
    expect(producer.closes).toBe(1);
    expect(await readdir(root)).toEqual(["target.elf"]);
  });

  it("retains cleanup when a live peer on the private input outlives the released instance", async () => {
    const { producer, client, root } = await fixture("headless");
    expect((await client.execute("health", {})).ok).toBe(true);
    let released = false;
    producer.beforeCall = async (name) => {
      if (name === "close_database") released = true;
    };
    const inner = producer.overrideCall;
    producer.overrideCall = (name) => {
      if (name === "list_databases" && released)
        return {
          instances: [
            {
              path: producer.inputPath,
              backend: "idalib",
              status: "attached",
              instance_id: "unrelated-live-peer",
              error: null,
            },
          ],
        };
      return inner?.(name, {}) ?? undefined;
    };

    const result = await client.close();
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.cleanupIncomplete).toBe(true);
    expect(result).toMatchObject(
      reportsInstances({
        instance_id: "unrelated-live-peer",
        backend: "idalib",
        status: "attached",
        path: producer.inputPath,
      }),
    );
    expect(
      (await readdir(root)).some((name) => name.startsWith("rea-ida-")),
    ).toBe(true);
  });

  it("releases when the inventory reports the closed instance as unavailable with an upstream error", async () => {
    const { producer, client, root } = await fixture("headless");
    expect((await client.execute("health", {})).ok).toBe(true);
    let released = false;
    producer.beforeCall = async (name) => {
      if (name === "close_database") released = true;
    };
    const inner = producer.overrideCall;
    producer.overrideCall = (name) => {
      if (name === "list_databases" && released)
        return {
          instances: [
            {
              path: producer.inputPath,
              backend: "idalib",
              status: "unavailable",
              instance_id: producer.database ?? null,
              error: "worker crashed during teardown",
            },
          ],
        };
      return inner?.(name, {}) ?? undefined;
    };

    expect((await client.close()).ok).toBe(true);
    expect(await readdir(root)).toEqual(["target.elf"]);
  });

  it("does not name a worker whose close was confirmed when inventory then fails", async () => {
    const { producer, client } = await fixture("headless");
    expect((await client.execute("health", {})).ok).toBe(true);
    producer.beforeCall = async (name) => {
      if (name === "list_databases") throw new Error("inventory unavailable");
    };

    const result = await client.close();
    expect(result.ok).toBe(false);
    expect(producer.calls.map(({ name }) => name)).toContain("close_database");
    expect(result).toMatchObject(reportsInstances());
  });
});

it("refuses a headless input swap after target admission", async () => {
  const { producer, client } = await fixture("headless");
  expect((await client.execute("health", {})).ok).toBe(true);
  producer.beforeCall = async (name, args) => {
    if (name === "execute_python" && reaOpOf(args.code) === "inventory")
      producer.inputPath = "/different/target.elf";
  };
  const result = await client.execute("list_procedures", {});
  expect(result.ok).toBe(false);
  if (!result.ok) {
    expect(projectAnalysisError(result.error).details).toMatchObject({
      diagnostics: { identity_check: "headless_input" },
    });
    expect(result.error.message).toContain("identity changed");
  }
  await client.close();
});

it("drains in-flight read-only work on cancellation before closing its proxy", async () => {
  const { producer, client } = await fixture();
  await client.execute("health", {});
  let release: (() => void) | undefined;
  let notify: (() => void) | undefined;
  const started = new Promise<void>((resolve) => {
    notify = resolve;
  });
  producer.beforeCall = async (name, args) => {
    if (name === "execute_python" && reaOpOf(args.code) === "pseudocode") {
      notify?.();
      await new Promise<void>((resolve) => {
        release = resolve;
      });
    }
  };
  const controller = new AbortController();
  const call = client.execute(
    "procedure_pseudo_code",
    { procedure: "main" },
    { signal: controller.signal },
  );
  await started;
  controller.abort();
  const close = client.close();
  expect(producer.closes).toBe(0);
  release?.();
  const result = await call;
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.error._tag).toBe("AnalysisCancelledError");
  expect((await close).ok).toBe(true);
  expect(producer.closes).toBe(1);
});

it("retains transport diagnostics on a cancellation regardless of stderr", async () => {
  const { producer, client } = await fixture();
  await client.execute("health", {});
  const controller = new AbortController();
  producer.beforeCall = async (name, args) => {
    if (name === "execute_python" && reaOpOf(args.code) === "inventory") {
      controller.abort();
      throw new AnalysisCancelledError("execute_python", {
        cause: controller.signal.reason,
        diagnostics: { reason: "upstream closed after cancellation" },
        capturedOutput: {
          stdout: "",
          stderr: "shutdown diagnostic",
          truncated: false,
        },
      });
    }
  };
  const result = await client.execute(
    "list_procedures",
    {},
    { signal: controller.signal },
  );
  if (result.ok) throw new Error("expected cancellation");
  expect(projectAnalysisError(result.error)).toMatchObject({
    code: "cancelled",
    details: {
      diagnostics: { reason: "upstream closed after cancellation" },
      captured_output: { stderr: "shutdown diagnostic" },
    },
  });
  await client.close();
});

it("binds retained transport diagnostics to the requested operation and recovery", async () => {
  const { producer, client } = await fixture("attached");
  await client.execute("health", {});
  producer.beforeCall = async (name, args) => {
    if (name === "execute_python" && reaOpOf(args.code) === "inventory")
      throw new ProviderAdapterError("ida", "transport", {
        diagnostics: { reason: "upstream closed" },
        capturedOutput: {
          stdout: "",
          stderr: "IDA diagnostic",
          truncated: false,
        },
      });
  };
  const result = await client.execute("list_procedures", {});
  if (result.ok) throw new Error("expected upstream failure");
  expect(projectAnalysisError(result.error)).toMatchObject({
    details: {
      operation: "list_procedures",
      diagnostics: {
        reason: "upstream closed",
        recovery: expect.stringContaining("docs/providers/ida-provider.md"),
      },
      captured_output: { stderr: "IDA diagnostic" },
    },
  });
  await client.close();
});

it.each(["close_database", "list_databases", "connection_close"])(
  "preserves transport stderr through cleanup at %s",
  async (stage) => {
    const { producer, client } = await fixture("headless");
    expect((await client.execute("health", {})).ok).toBe(true);
    const failure = new ProviderAdapterError("ida", "transport", {
      diagnostics: {
        reason: "upstream transport closed",
      },
      capturedOutput: {
        stdout: "",
        stderr: "IDA shutdown diagnostic",
        truncated: false,
      },
    });
    const originalClose = producer.close.bind(producer);
    producer.beforeCall = async (name) => {
      if (name === stage) throw failure;
    };
    if (stage === "connection_close")
      producer.close = async () => {
        throw failure;
      };
    try {
      const result = await client.close();
      if (result.ok) throw new Error("expected cleanup failure");
      expect(result.error.capturedOutput?.stderr).toBe(
        "IDA shutdown diagnostic",
      );
      expect(result.error.diagnostics).toMatchObject({
        failure_reason: "upstream transport closed",
      });
      expect(result.error.cleanupIncomplete).toBe(true);
    } finally {
      delete producer.beforeCall;
      producer.close = originalClose;
      await client.close();
    }
  },
);

it.each(["before", "during"] as const)(
  "preserves the exact caller abort reason %s an IDA operation",
  async (phase) => {
    const { producer, client } = await fixture(
      phase === "before" ? "attached" : "headless",
    );
    const controller = new AbortController();
    const reason = { caller: "selected opaque cancellation" };
    if (phase === "before") controller.abort(reason);
    else
      producer.beforeCall = async (name, args) => {
        if (name === "execute_python" && reaOpOf(args.code) === "inventory")
          controller.abort(reason);
      };
    const result = await client.execute(
      "list_procedures",
      {},
      { signal: controller.signal },
    );
    if (result.ok) throw new Error("Expected cancellation");
    expect(result.error).toBeInstanceOf(AnalysisCancelledError);
    expect(result.error.cause).toBe(reason);
    if (phase === "before") expect(producer.connects).toBe(0);
    else
      expect(result.error.partialObservation).toMatchObject({
        operation: "list_procedures",
      });
    await client.close();
  },
);

it("keeps the session cleanup owner until an ignored-abort HTTP acquisition and body settle", async () => {
  const { root, target } = await createIdaTarget();
  roots.push(root);
  let deliver!: (response: Response) => void;
  let entered!: () => void;
  const started = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const response = new Promise<Response>((resolve) => {
    deliver = resolve;
  });
  let release!: () => void;
  const bodyCleanup = new Promise<void>((resolve) => {
    release = resolve;
  });
  const cancel = vi.fn(() => bodyCleanup);
  vi.stubGlobal(
    "fetch",
    vi.fn(() => {
      entered();
      return response;
    }),
  );
  const config = {
    url: "http://127.0.0.1:12345/mcp",
    headers: {},
    mode: "attached" as const,
    timeoutMs: 30,
  };
  const client = new IdaSessionClient(
    config,
    target,
    createIdaMcpConnection(config, {}),
  );
  const executing = client.execute("health", {});
  try {
    await started;
    const result = await executing;
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisTimeoutError" },
    });
    const firstClose = await client.close();
    expect(firstClose).toMatchObject({
      ok: false,
      error: { cleanupIncomplete: true },
    });
    deliver(new Response(new ReadableStream<Uint8Array>({ cancel })));
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(await client.close()).toMatchObject({
      ok: false,
      error: { cleanupIncomplete: true },
    });
    expect(cancel).toHaveBeenCalledOnce();
    release();
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(await client.close()).toMatchObject({ ok: true });
    if (firstClose.ok) throw new Error("Expected retained outer cleanup");
    expect(firstClose.error.cleanupIncomplete).toBe(false);
  } finally {
    deliver(new Response(null, { status: 500 }));
    release();
    await executing;
    await new Promise<void>((resolve) => setImmediate(resolve));
    await client.close();
    vi.unstubAllGlobals();
  }
});
