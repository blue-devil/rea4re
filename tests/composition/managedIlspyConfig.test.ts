import { join } from "node:path";
import { writeFile } from "node:fs/promises";
import { expect, it } from "vitest";

import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { buildManagedPeFixture } from "../../src/dotnet/ManagedPe.fixture.js";
import { parseBinaryTarget } from "../../src/application/BinaryTargetResolver.js";
import type { ManagedStaticProvider } from "../../src/dotnet/ManagedStaticProvider.js";
import { auxiliaryAnalysisProviderDeclarations } from "../../src/composition/auxiliaryAnalysisProviders.js";
import { createManagedBinarySession } from "../../src/composition/binary.js";
import { MANAGED_STATIC_PROVIDER } from "../../src/domain/investigationProviders.js";

const writePeFixture = async (root: string) => {
  const path = join(root, "fixture.dll");
  await writeFile(path, buildManagedPeFixture());
  return path;
};

it("passes ilspyMcpConfigPath to the managed workflow through the composed session", async () => {
  const root = await createTestTempDirectory("rea-managed-ilspy-config-");
  const path = await writePeFixture(root);
  const configPath = join(root, "ilspy-mcp.json");
  await writeFile(configPath, "not-json");
  const session = createManagedBinarySession({
    ilspyMcpConfigPath: configPath,
  });
  try {
    const opened = await session.open(path);
    if (!opened.ok) throw opened.error;
    const executed = await session.execute(
      "decompile_managed_members",
      { assembly_path: path, declaring_type: "System.Example" },
      {},
    );
    // The workflow read our config file; its malformed content proves the path arrived.
    expect(executed).toMatchObject({
      ok: false,
      error: {
        _tag: "ConfigurationError",
        message: expect.stringContaining(
          "REA_ILSPY_MCP_CONFIG must contain valid JSON.",
        ),
      },
    });
  } finally {
    await session.close();
  }
});

it("fails closed naming REA_ILSPY_MCP_CONFIG when the auxiliary provider has no config", async () => {
  const root = await createTestTempDirectory("rea-managed-ilspy-config-");
  const path = await writePeFixture(root);
  const [declaration] = auxiliaryAnalysisProviderDeclarations(
    process.env,
    process.platform,
    undefined,
    {},
  ).filter(({ identity }) => identity === MANAGED_STATIC_PROVIDER);
  if (declaration === undefined)
    throw new Error("managed static provider declaration missing");
  const provider = (await declaration.load()) as ManagedStaticProvider;
  const target = await parseBinaryTarget(path);
  if (!target.ok) throw target.error;
  const client = provider.createClient(target.value);
  try {
    const executed = await client.execute("decompile_managed_members", {
      assembly_path: path,
      declaring_type: "System.Example",
    });
    expect(executed).toMatchObject({
      ok: false,
      error: {
        _tag: "ConfigurationError",
        message: expect.stringContaining(
          "REA_ILSPY_MCP_CONFIG is not configured",
        ),
      },
    });
  } finally {
    await client.close();
  }
});
