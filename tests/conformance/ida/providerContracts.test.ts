import { IDA_COMPATIBILITY_PROFILES } from "../../../src/ida/IdaConfiguration.js";
import { STDIO_DEFAULT_MAX_BUFFER_SIZE } from "@modelcontextprotocol/server";
import { rm } from "node:fs/promises";
import { afterEach, describe, expect, it } from "vitest";
import { createIdaTarget, RecordingIdaMcp } from "../../fixtures/idaMcp.js";
import { IdaSessionClient } from "../../../src/ida/IdaSessionClient.js";
import { idaCapabilities } from "../../../src/ida/IdaProviderCapabilities.js";
import { IDA_OPERATIONS } from "../../../src/ida/IdaProviderMetadata.js";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { createEvidence } from "../../../src/domain/evidence.js";
import type { JsonValue } from "../../../src/domain/jsonValue.js";
import { createToolResultDelivery } from "../../../src/server/toolResult.js";

const delivery = createToolResultDelivery(STDIO_DEFAULT_MAX_BUFFER_SIZE);

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
});

const parametersFor = (
  operation: string,
): Readonly<Record<string, JsonValue>> => {
  if (operation.startsWith("search_")) return { pattern: "a.b" };
  if (operation === "xrefs" || operation === "resolve_containing_procedure")
    return { address: "0x1000" };
  if (operation.startsWith("list_")) return {};
  return { procedure: "main" };
};

describe.each(["attached", "headless"] as const)(
  "IDA %s caller-visible contracts",
  (mode) => {
    it("includes the baseline operations needed by this contract matrix", () => {
      expect(IDA_OPERATIONS).toContain("list_procedures");
      expect(IDA_OPERATIONS).toContain("resolve_containing_procedure");
    });
    it.each([...IDA_OPERATIONS])(
      "serializes %s against its named advertised output contract",
      async (operation) => {
        const { root, target } = await createIdaTarget();
        roots.push(root);
        const producer = new RecordingIdaMcp(target, mode);
        const client = new IdaSessionClient(
          {
            command: "fixture",
            args: [],
            env: {},
            mode,
            workspaceRoot: root,
            timeoutMs: 1000,
          },
          target,
          producer,
        );
        try {
          const parameters = parametersFor(operation);
          const execution = await client.execute(operation, parameters);
          const descriptor = idaCapabilities(
            IDA_COMPATIBILITY_PROFILES[mode],
            true,
          ).find((capability) => capability.operation === operation);
          // execute_python reads the attached database; it never navigates the GUI.
          expect(descriptor?.effects.mayShowUi).toBe(false);
          if (!execution.ok) throw execution.error;
          const evidence = createEvidence(target, execution.value.provider, {
            operation,
            parameters,
            result: execution.value.result,
            rawResult: execution.value.rawResult,
            locations: execution.value.locations,
            limitations: execution.value.limitations,
          });
          const contract = toolContract(operation);
          const serialized = delivery.toEvidenceToolResult(
            evidence,
            contract,
            undefined,
          );
          expect(
            contract.outputSchema.safeParse(serialized.structuredContent)
              .success,
          ).toBe(true);
          expect(serialized.content[0]).toEqual({
            type: "text",
            text: JSON.stringify(serialized.structuredContent),
          });
        } finally {
          expect((await client.close()).ok).toBe(true);
        }
      },
    );
  },
);
