import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

/**
 * Pinned ILSpy-MCP release provenance. The v1.2.1 archives are self-contained
 * native publishes and ship no managed DLL, so the lane regenerates the
 * fixture instead of extracting one; nothing here downloads or commits bytes.
 * Kept free of repo imports and TS-only syntax so plain Node can load it.
 */
export const ILSpyMcpRelease = {
  repository: "cervonwong/ILSpy-MCP",
  tag: "v1.2.1",
  releaseUrl: "https://github.com/cervonwong/ILSpy-MCP/releases/tag/v1.2.1",
  asset: "ilspy-mcp-linux-arm64.tar.gz",
  assetSha256:
    "f070ea973233ae9318df60fe17d1126cf0f58729cbfe2540221e69ed682f09db",
} as const;

/**
 * Pinned real-provider fixture: the deterministic synthetic managed PE built
 * by `buildManagedPeFixture()` defaults (`Fixture.Program.Main`). Regenerate
 * with `node scripts/verify-real-ilspy-mcp.mjs --generate-fixture <path>`.
 */
export const ManagedTestFixture = {
  origin: "src/dotnet/ManagedPe.fixture.ts buildManagedPeFixture() defaults",
  declaringType: "Fixture.Program",
  memberName: "Main",
  sha256: "c96cd66659210492a76543a1760925838463c48b626c71ad6a560bfa699b2f63",
} as const;

/** Typed refusal: the file at `path` is not the pinned fixture assembly. */
export class ManagedAssemblyProvenanceError extends Error {
  readonly path: string;
  readonly expectedSha256: string;
  readonly actualSha256: string;

  constructor(path: string, expectedSha256: string, actualSha256: string) {
    super(
      `Managed assembly provenance mismatch for ${path}: expected sha256 ${expectedSha256}, observed ${actualSha256}. Regenerate the pinned fixture with "node scripts/verify-real-ilspy-mcp.mjs --generate-fixture <path>".`,
    );
    this.name = "ManagedAssemblyProvenanceError";
    this.path = path;
    this.expectedSha256 = expectedSha256;
    this.actualSha256 = actualSha256;
  }
}

export type ManagedAssemblyProvenance =
  | { readonly ok: true }
  | { readonly ok: false; readonly error: ManagedAssemblyProvenanceError };

/** Hash the file at `path` and refuse on digest mismatch with the pinned fixture. */
export const verifyManagedAssemblyProvenance = async (
  path: string,
): Promise<ManagedAssemblyProvenance> => {
  const actualSha256 = createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
  return actualSha256 === ManagedTestFixture.sha256
    ? { ok: true }
    : {
        ok: false,
        error: new ManagedAssemblyProvenanceError(
          path,
          ManagedTestFixture.sha256,
          actualSha256,
        ),
      };
};
