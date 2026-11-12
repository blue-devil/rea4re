import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { copyFile, mkdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { expect, it } from "vitest";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";

it.skipIf(process.platform === "win32")(
  "binds relative Hopper launchers once for availability and profile",
  async () => {
    const root = await createTestTempDirectory("rea-hopper-relative-launcher-");
    const away = join(root, "away");
    await mkdir(away);
    await mkdir(join(root, "physical/child"), { recursive: true });
    await symlink(join(root, "physical/child"), join(root, "link"));
    const target = join(root, "target");
    await copyFile("/usr/bin/true", target);
    const script = `#!/bin/sh\nexit 0\n`;
    for (const path of [
      join(root, "my-hopper"),
      join(root, "physical/my-hopper"),
    ])
      await writeFile(path, script, { mode: 0o700 });
    await writeFile(join(away, "my-hopper"), "#!/bin/sh\nexit 87\n", {
      mode: 0o700,
    });
    const module = (path: string) =>
      new URL(`../../../../src/${path}.ts`, import.meta.url).href;
    const source = `
      import { HopperProvider } from ${JSON.stringify(module("hopper/HopperProvider"))};
      import { parseConfig } from ${JSON.stringify(module("config/parseConfig"))};
      import { parseBinaryTarget } from ${JSON.stringify(module("application/BinaryTargetResolver"))};
      import { silentLogger } from ${JSON.stringify(module("logger"))};
      const root = ${JSON.stringify(root)};
      const target = await parseBinaryTarget(${JSON.stringify(target)}, { cwd: root, hostArchitecture: process.arch });
      if (!target.ok) throw target.error;
      const results = [];
      for (const selected of ['my-hopper', './my-hopper', 'link/../my-hopper']) {
        process.chdir(root);
        const config = parseConfig({ HOPPER_LAUNCHER_PATH: selected, REA_HOPPER_STARTUP_TIMEOUT_MS: '3000' });
        if (!config.ok) throw config.error;
        const provider = new HopperProvider(config.value, silentLogger, {}, 'linux');
        process.chdir(${JSON.stringify(away)});
        const availability = provider.inspectAvailability();
        const profile = await provider.resolveAnalysisProfile(target.value);
        results.push({ selected, availability, profile: profile.ok ? profile.value.profile.provider.version : false });
        const released = await provider.closeOwnedResources();
        if (!released.ok) throw released.error;
      }
      console.log(JSON.stringify(results));
    `;
    const { stdout } = await promisify(execFile)(
      process.execPath,
      [
        "--import",
        import.meta.resolve("tsx"),
        "--input-type=module",
        "--eval",
        source,
      ],
      { cwd: root, timeout: 20_000 },
    );
    expect(JSON.parse(stdout)).toEqual(
      ["my-hopper", "./my-hopper", "link/../my-hopper"].map((selected) => ({
        selected,
        availability: expect.objectContaining({
          status: "available",
          diagnostics: { launcher_path: selected, platform: "linux" },
        }),
        profile:
          "launcher-sha256:" +
          createHash("sha256").update(script).digest("hex"),
      })),
    );
  },
);
