#!/usr/bin/env node
// Real ILSpy-MCP provider lane. Bring your own server binary
// (REA_ILSPY_MCP_TEST_BIN) and the pinned fixture DLL
// (REA_ILSPY_MCP_TEST_FIXTURE); REA downloads neither. With both set, this
// verifies the fixture digest, runs the focused boundary suite, and prints a
// verdict. Without them it prints the fetch instructions and exits non-zero.
// --generate-fixture PATH writes the pinned fixture DLL from source instead.
import { execFile } from "node:child_process";
import { stat } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs, promisify } from "node:util";

const exec = promisify(execFile);
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const { values } = parseArgs({
  options: { "generate-fixture": { type: "string" } },
});

const provenance = await import(
  pathToFileURL(join(root, "tests/fixtures/managedAssemblyProvenance.ts")).href
);
const { ILSpyMcpRelease, ManagedTestFixture } = provenance;

const generateFixture = async (path) => {
  if (!isAbsolute(path)) {
    console.error("--generate-fixture needs an absolute path");
    process.exit(1);
  }
  await exec(join(root, "node_modules", ".bin", "tsx"), [
    join(root, "scripts/lib/write-managed-fixture.mjs"),
    path,
  ]);
  const verified = await provenance.verifyManagedAssemblyProvenance(path);
  if (!verified.ok) throw verified.error;
  console.log(
    `wrote pinned fixture ${path} (sha256 ${ManagedTestFixture.sha256})`,
  );
  process.exit(0);
};

if (values["generate-fixture"] !== undefined)
  await generateFixture(values["generate-fixture"]);

const bin = process.env.REA_ILSPY_MCP_TEST_BIN;
const fixture = process.env.REA_ILSPY_MCP_TEST_FIXTURE;
if (bin === undefined || fixture === undefined) {
  console.error(`Real ILSpy-MCP lane prerequisites missing.

1. Download the pinned release asset:
   ${ILSpyMcpRelease.releaseUrl}
   asset: ${ILSpyMcpRelease.asset}
   expected sha256: ${ILSpyMcpRelease.assetSha256}
   Extract the archive anywhere outside this repository (it is a
   self-contained publish of ILSpy.Mcp; no managed DLL ships inside).
2. REA_ILSPY_MCP_TEST_BIN=<absolute path to the extracted ILSpy.Mcp executable>
3. Generate the pinned fixture:
   node scripts/verify-real-ilspy-mcp.mjs --generate-fixture /tmp/rea-ilspy-fixture.dll
   REA_ILSPY_MCP_TEST_FIXTURE=<that path> (sha256 ${ManagedTestFixture.sha256})
4. Re-run: npm run verify:real:ilspy`);
  process.exit(1);
}

if (!isAbsolute(bin) || !isAbsolute(fixture)) {
  console.error(
    "REA_ILSPY_MCP_TEST_BIN and REA_ILSPY_MCP_TEST_FIXTURE must be absolute paths",
  );
  process.exit(1);
}
for (const path of [bin, fixture]) {
  if (!(await stat(path)).isFile()) {
    console.error(`prerequisite is not a regular file: ${path}`);
    process.exit(1);
  }
}
const verified = await provenance.verifyManagedAssemblyProvenance(fixture);
if (!verified.ok) {
  console.error(verified.error.message);
  process.exit(1);
}

try {
  const { stdout } = await exec(
    process.execPath,
    [
      join(root, "node_modules/vitest/vitest.mjs"),
      "run",
      "tests/boundary/providers/ilspy/managedDecompilationReal.test.ts",
    ],
    { env: { ...process.env } },
  );
  console.log(stdout.trimEnd());
  console.log(
    `VERDICT: real ILSpy-MCP lane passed (fixture sha256 ${ManagedTestFixture.sha256})`,
  );
} catch (cause) {
  const { stdout, stderr, code } = cause;
  if (stdout) console.log(stdout.trimEnd());
  if (stderr) console.error(stderr.trimEnd());
  console.error(`VERDICT: real ILSpy-MCP lane FAILED (exit ${code ?? "?"})`);
  process.exit(typeof code === "number" ? code : 1);
}
