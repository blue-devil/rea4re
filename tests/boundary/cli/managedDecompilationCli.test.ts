import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";

import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

cliTest(
  "decompile-managed-members maps CLI arguments to the workflow and refuses relative assembly paths",
  async ({ cli }) => {
    const directory = await createTestTempDirectory("rea-managed-decompile-");
    const assembly = join(directory, "fixture.dll");
    await writeFile(assembly, "");
    const configPath = join(directory, "ilspy-mcp.json");
    await writeFile(configPath, "not-json");
    const valid = await cli.run({
      arguments: [
        "decompile-managed-members",
        assembly,
        "System.Example",
        "--member-names",
        "ToString",
        "--member-names",
        "GetHashCode",
        "--output-kind",
        "decompiled-il",
        "--json",
      ],
      environment: { REA_ILSPY_MCP_CONFIG: configPath },
    });
    expect(valid.exitCode, valid.stderr).toBe(1);
    // The workflow read the registration selected by REA_ILSPY_MCP_CONFIG;
    // its malformed content proves the CLI passed the arguments and config path.
    expect(valid.json).toMatchObject({
      message: expect.stringContaining(
        "REA_ILSPY_MCP_CONFIG must contain valid JSON.",
      ),
    });

    const relative = await cli.run({
      arguments: [
        "decompile-managed-members",
        "fixture.dll",
        "System.Example",
        "--json",
      ],
    });
    expect(relative.exitCode, relative.stderr).toBe(1);
    expect(relative.json).toMatchObject({
      code: "VALIDATION_ERROR",
      fieldErrors: [
        expect.objectContaining({
          path: "assemblyPath",
          message: expect.stringContaining(
            "must be an absolute local filesystem path",
          ),
        }),
      ],
    });
  },
);
