import { createHash } from "node:crypto";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  ILSpyMcpRelease,
  verifyIlspyServerBinaryProvenance,
} from "./managedAssemblyProvenance.js";

describe("verifyIlspyServerBinaryProvenance", () => {
  it("accepts a non-asset filename without hashing it", async () => {
    const root = await mkdtemp(join(tmpdir(), "rea-ilspy-bin-"));
    const path = join(root, "ILspy.Mcp");
    await writeFile(path, "not the archive");
    await expect(verifyIlspyServerBinaryProvenance(path)).resolves.toEqual({
      ok: true,
    });
  });

  it("refuses a file claiming the pinned asset name with the wrong digest", async () => {
    const root = await mkdtemp(join(tmpdir(), "rea-ilspy-bin-"));
    const path = join(root, ILSpyMcpRelease.asset);
    await writeFile(path, "pretending to be the pinned archive");
    const outcome = await verifyIlspyServerBinaryProvenance(path);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error("expected refusal");
    expect(outcome.error).toBeInstanceOf(Error);
    expect(outcome.error.expectedSha256).toBe(ILSpyMcpRelease.assetSha256);
    expect(outcome.error.actualSha256).toBe(
      createHash("sha256")
        .update("pretending to be the pinned archive")
        .digest("hex"),
    );
  });
});
