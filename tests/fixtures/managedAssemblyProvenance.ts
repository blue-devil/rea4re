import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

/**
 * Pinned ILSpy-MCP release provenance. The archives are self-contained
 * native publishes (no managed DLL inside), so the decompilation fixture
 * comes from the pinned NuGet package below; nothing here downloads or
 * commits bytes. Kept free of repo imports and TS-only syntax so plain Node
 * (type stripping) can load it from the operator script.
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
 * Pinned real managed assembly fixture: Newtonsoft.Json 13.0.3 from NuGet
 * (MIT). Fetch the package URL below, `unzip -p` the in-package DLL path to
 * an absolute location, and point REA_ILSPY_MCP_TEST_FIXTURE at it.
 */
export const ManagedTestFixture = {
  packageId: "Newtonsoft.Json",
  packageVersion: "13.0.3",
  packageUrl: "https://www.nuget.org/api/v2/package/Newtonsoft.Json/13.0.3",
  inPackagePath: "lib/net6.0/Newtonsoft.Json.dll",
  declaringType: "Newtonsoft.Json.JsonConvert",
  memberName: "SerializeObjectInternal",
  sha256: "22c649f75fce5be7c7ccda8880473b634ef69ecf33f5d1ab8ad892caf47d5a07",
} as const;

/** Typed refusal: the file at `path` is not the pinned fixture assembly. */
export class ManagedAssemblyProvenanceError extends Error {
  readonly path: string;
  readonly expectedSha256: string;
  readonly actualSha256: string;

  constructor(path: string, expectedSha256: string, actualSha256: string) {
    super(
      `Managed assembly provenance mismatch for ${path}: expected sha256 ${expectedSha256} (the pinned ${ManagedTestFixture.packageId} ${ManagedTestFixture.packageVersion} DLL at ${ManagedTestFixture.inPackagePath} inside ${ManagedTestFixture.packageUrl}), observed ${actualSha256}.`,
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
