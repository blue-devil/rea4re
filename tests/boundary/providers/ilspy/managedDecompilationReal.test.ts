import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import {
  ManagedTestFixture,
  verifyManagedAssemblyProvenance,
} from "../../../fixtures/managedAssemblyProvenance.js";
import { createManagedBinarySession } from "../../../../src/composition/binary.js";
import { managedDecompilationResultSchema } from "../../../../src/domain/managed/managedDecompilation.js";

const ilspyBin = process.env.REA_ILSPY_MCP_TEST_BIN;
const fixturePath = process.env.REA_ILSPY_MCP_TEST_FIXTURE;
// Real-provider lane: bring your own ILSpy-MCP server binary and the pinned
// fixture DLL; without both the lane skips instead of downloading anything.
const byoProviderMissing = ilspyBin === undefined || fixturePath === undefined;

describe("real ILSpy MCP provider (requires REA_ILSPY_MCP_TEST_BIN and REA_ILSPY_MCP_TEST_FIXTURE)", () => {
  const openSession = async () => {
    const provenance = await verifyManagedAssemblyProvenance(fixturePath!);
    if (!provenance.ok) throw provenance.error;
    const directory = await createTestTempDirectory("rea-ilspy-real-");
    const configPath = join(directory, "ilspy-mcp.json");
    await writeFile(
      configPath,
      JSON.stringify({ type: "stdio", command: ilspyBin! }),
    );
    const session = createManagedBinarySession({
      ilspyMcpConfigPath: configPath,
    });
    const opened = await session.open(fixturePath!);
    if (!opened.ok) throw opened.error;
    return { session };
  };

  it.skipIf(byoProviderMissing)(
    "decompiles the pinned fixture through the real provider and joins reconstruction evidence",
    async () => {
      const { session } = await openSession();
      try {
        const executed = await session.execute(
          "decompile_managed_members",
          {
            assembly_path: fixturePath!,
            declaring_type: ManagedTestFixture.declaringType,
          },
          {},
        );
        expect(executed).toMatchObject({ ok: true });
        if (!executed.ok) throw executed.error;
        const body = managedDecompilationResultSchema.parse(
          executed.value.result,
        );
        const reconstructed = body.methods.filter(
          (method) => method.status === "reconstructed",
        );
        expect(reconstructed.length).toBeGreaterThanOrEqual(1);
        expect(reconstructed[0]).toMatchObject({
          name: ManagedTestFixture.memberName,
          declaring_type: ManagedTestFixture.declaringType,
        });
        expect(body.reconstruction?.reconstruction_id).toMatch(/^mre_/);
      } finally {
        await session.close();
      }
    },
  );

  it.skipIf(byoProviderMissing)(
    "refuses a deliberately mismatched member name, naming the requested member",
    async () => {
      const { session } = await openSession();
      try {
        const executed = await session.execute(
          "decompile_managed_members",
          {
            assembly_path: fixturePath!,
            declaring_type: ManagedTestFixture.declaringType,
            member_names: ["NoSuchRealMember"],
          },
          {},
        );
        expect(executed).toMatchObject({
          ok: false,
          error: {
            message: expect.stringContaining("NoSuchRealMember"),
          },
        });
      } finally {
        await session.close();
      }
    },
  );
});
