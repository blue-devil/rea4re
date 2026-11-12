import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { expect, it } from "vitest";

const execute = promisify(execFile);

it.each([{ protocol: "attached" }, { protocol: "headless" }])(
  "admits a valid $protocol registration up to target admission",
  async ({ protocol }) => {
    const root = await mkdtemp(join(tmpdir(), "rea-ida-verifier-options-"));
    try {
      const config = join(root, "ida.json");
      await writeFile(
        config,
        JSON.stringify({
          url: "http://127.0.0.1:13337/mcp",
          mode: protocol,
        }),
      );
      // The absent target stops accepted option sets at admission, before any provider call.
      await expect(
        execute(
          process.execPath,
          ["scripts/verify-real-ida.mjs", "--target", join(root, "absent")],
          {
            cwd: process.cwd(),
            env: { ...process.env, REA_IDA_MCP_CONFIG: config },
            timeout: 10_000,
          },
        ),
      ).rejects.toMatchObject({
        stderr: "",
        stdout: expect.stringContaining('"failed_phase": "target admission"'),
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);
