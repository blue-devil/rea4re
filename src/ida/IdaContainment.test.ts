import { IDA_COMPATIBILITY_PROFILES } from "./IdaConfiguration.js";
import { rm } from "node:fs/promises";
import { afterEach, describe, expect, it } from "vitest";
import type { JsonValue } from "../domain/jsonValue.js";
import {
  createIdaTarget,
  RecordingIdaMcp,
  reaOpOf,
} from "../../tests/fixtures/idaMcp.js";
import { idaCapabilities } from "./IdaProviderCapabilities.js";
import { IdaSessionClient } from "./IdaSessionClient.js";

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
});

const session = async (
  mode: "headless" | "attached" = "headless",
  upstream: {
    /** A distinct source alias of the admitted target, as for an app bundle. */
    readonly sourcePath?: string;
    /** Report a different input from the second identity read on. */
    readonly identityChangesAfterOperation?: boolean;
    /** Replace the containing reply; default serves the fixture database. */
    readonly containingReply?: JsonValue;
  } = {},
) => {
  const created = await createIdaTarget("x86_64");
  const { root } = created;
  const target =
    upstream.sourcePath === undefined
      ? created.target
      : { ...created.target, sourcePath: upstream.sourcePath };
  roots.push(root);
  const producer = new RecordingIdaMcp(target, mode);
  let identityReads = 0;
  producer.overrideCall = (name, args) => {
    if (name !== "execute_python") return undefined;
    const op = reaOpOf(args.code);
    if (op === "identity" && upstream.identityChangesAfterOperation) {
      identityReads += 1;
      if (identityReads === 2) producer.inputPath = "/different/target.elf";
    }
    if (op === "containing" && upstream.containingReply !== undefined)
      return { result: upstream.containingReply, stdout: "", stderr: "" };
    return undefined;
  };
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
  return { client, producer, target };
};

const containing = async (
  client: IdaSessionClient,
  address: string,
  options?: Parameters<IdaSessionClient["execute"]>[2],
) => client.execute("resolve_containing_procedure", { address }, options);

describe("IDA containment capabilities", () => {
  it("declares document identity and address resolution in both profiles", () => {
    for (const profile of [
      IDA_COMPATIBILITY_PROFILES.attached,
      IDA_COMPATIBILITY_PROFILES.headless,
    ]) {
      const declared = idaCapabilities(profile, false)
        .filter(
          ({ operation }) =>
            operation === "resolve_containing_procedure" ||
            operation === "list_documents",
        )
        .map(({ operation, available }) => ({ operation, available }));
      expect(declared).toEqual([
        { operation: "resolve_containing_procedure", available: true },
        { operation: "list_documents", available: true },
      ]);
    }
  });
});

describe.each(["attached", "headless"] as const)(
  "IDA %s containing procedure",
  (mode) => {
    it("returns the canonical entry for an interior address", async () => {
      const { client } = await session(mode);
      try {
        const result = await containing(client, "0x1010");
        if (!result.ok) throw result.error;
        expect(result.value.result).toEqual({
          query_address: "0x1010",
          found: true,
          procedure: {
            address: "0x1000",
            name: "main",
            symbol: null,
            classification: null,
            body: {
              available: false,
              reason: expect.stringMatching(
                /does not report complete function body ranges/iu,
              ),
            },
          },
        });
      } finally {
        expect((await client.close()).ok).toBe(true);
      }
    });

    it("reports an address no function contains as not in a procedure", async () => {
      const { client } = await session(mode);
      try {
        const result = await containing(client, "0x4000");
        if (!result.ok) throw result.error;
        expect(result.value.result).toEqual({
          query_address: "0x4000",
          found: false,
          procedure: null,
          reason: "not_in_procedure",
        });
      } finally {
        expect((await client.close()).ok).toBe(true);
      }
    });

    it("treats a malformed containing reply as unreadable output", async () => {
      const { client } = await session(mode, {
        containingReply: { name: 5 },
      });
      try {
        const result = await containing(client, "0x1000");
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.error._tag).toBe("AnalysisOutputError");
      } finally {
        expect((await client.close()).ok).toBe(true);
      }
    });

    it("rejects an address that is not hexadecimal and a document that is not the admitted target", async () => {
      const { client, producer } = await session(mode);
      try {
        const badAddress = await containing(client, "main");
        const badDocument = await client.execute(
          "resolve_containing_procedure",
          { address: "0x1000", document: "/somewhere/else" },
        );
        for (const result of [badAddress, badDocument]) {
          expect(result.ok).toBe(false);
          if (!result.ok) expect(result.error._tag).toBe("AnalysisInputError");
        }
        expect(producer.calls).toEqual([]);
      } finally {
        expect((await client.close()).ok).toBe(true);
      }
    });
  },
);

describe("headless IDA document identity", () => {
  it("accepts an explicit admitted document and rejects an unknown one for the same operations", async () => {
    const { client, target, producer } = await session();
    try {
      const admitted = await client.execute("resolve_containing_procedure", {
        address: "0x4000",
        document: target.path,
      });
      const unknownContainment = await client.execute(
        "resolve_containing_procedure",
        { address: "0x4000", document: "/somewhere/else" },
      );
      const unknownListing = await client.execute("list_documents", {
        document: "/somewhere/else",
      });

      expect(admitted.ok, "the admitted program is accepted").toBe(true);
      for (const rejected of [unknownContainment, unknownListing]) {
        expect(rejected.ok).toBe(false);
        if (!rejected.ok)
          expect(rejected.error._tag).toBe("AnalysisInputError");
      }
      expect(
        producer.calls.filter(({ name }) => name === "execute_python"),
        "identity before and after plus the containing probe",
      ).toHaveLength(3);
    } finally {
      expect((await client.close()).ok).toBe(true);
    }
  });

  it("lists the admitted path, not its source alias or the private copy", async () => {
    const { client, target, producer } = await session("headless", {
      sourcePath: "/Applications/Fixture.app",
    });
    try {
      const result = await client.execute("list_documents", {});

      if (!result.ok) throw result.error;
      expect(result.value.result).toEqual([target.path]);
      expect(
        producer.calls.filter(({ name }) => name === "execute_python"),
        "the target identity is checked before and after the local answer",
      ).toHaveLength(2);
    } finally {
      expect((await client.close()).ok).toBe(true);
    }
  });

  it("fails when the target identity changes during the operation", async () => {
    const { client } = await session("headless", {
      identityChangesAfterOperation: true,
    });
    try {
      const result = await client.execute("list_documents", {});
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.message).toContain("identity");
    } finally {
      expect((await client.close()).ok).toBe(true);
    }
  });

  it("stops without dispatching when the request is already cancelled", async () => {
    const controller = new AbortController();
    controller.abort();
    const { client, producer } = await session();
    try {
      const result = await client.execute(
        "list_documents",
        {},
        { signal: controller.signal },
      );
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error._tag).toBe("AnalysisCancelledError");
        expect(result.error.cause).toBe(controller.signal.reason);
      }
      expect(producer.calls).toEqual([]);
    } finally {
      expect((await client.close()).ok).toBe(true);
    }
  });
});
