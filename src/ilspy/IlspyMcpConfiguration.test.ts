import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  ilspyMcpRegistrationSchema,
  readIlspyMcpConfiguration,
} from "./IlspyMcpConfiguration.js";

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
});

const registrationFile = async (content: unknown | string): Promise<string> => {
  const root = await mkdtemp(join(tmpdir(), "ilspy-config-"));
  roots.push(root);
  const path = join(root, "ilspy-mcp.json");
  await writeFile(
    path,
    typeof content === "string" ? content : JSON.stringify(content),
  );
  return path;
};

describe("ILSpy MCP registration configuration", () => {
  it("parses a valid stdio registration and applies defaults", async () => {
    const path = await registrationFile({
      command: "ilspy-mcp",
      args: ["--stdio"],
      env: { DOTNET_ENV: "Production" },
    });
    expect(await readIlspyMcpConfiguration(path)).toMatchObject({
      ok: true,
      value: {
        command: "ilspy-mcp",
        args: ["--stdio"],
        env: { DOTNET_ENV: "Production" },
        timeoutMs: 300_000,
      },
    });
  });

  it("parses loopback http registrations", async () => {
    for (const url of ["http://127.0.0.1:3001/mcp", "http://[::1]:3001"]) {
      const path = await registrationFile({ type: "http", url });
      expect(await readIlspyMcpConfiguration(path)).toMatchObject({
        ok: true,
        value: { url },
      });
    }
  });

  it("refuses non-loopback http URLs without quoting them", async () => {
    const path = await registrationFile({
      type: "http",
      url: "http://192.168.1.10:3001/mcp",
    });
    const result = await readIlspyMcpConfiguration(path);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.message).toContain("REA_ILSPY_MCP_CONFIG");
    expect(result.error.message.toLowerCase()).toContain("loopback");
    expect(result.error.message).not.toContain("192.168.1.10");
    expect(result.error.settings).toEqual([
      expect.objectContaining({ setting: "REA_ILSPY_MCP_CONFIG" }),
    ]);
  });

  it("refuses URLs with credentials without leaking them", async () => {
    const path = await registrationFile({
      type: "http",
      url: "http://user:pass@127.0.0.1:3001",
    });
    const result = await readIlspyMcpConfiguration(path);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.message).not.toContain("user:pass");
    expect(result.error.message).not.toContain("pass");
  });

  it("refuses registration files beyond 64 KiB", async () => {
    const path = await registrationFile(
      JSON.stringify({ command: "ilspy-mcp" }).padEnd(65_537),
    );
    expect(await readIlspyMcpConfiguration(path)).toMatchObject({
      ok: false,
      error: { message: expect.stringContaining("64 KiB") },
    });
  });

  it("refuses non-JSON files naming the setting without raw contents", async () => {
    const path = await registrationFile("this is not json {{");
    const result = await readIlspyMcpConfiguration(path);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.message).toContain("REA_ILSPY_MCP_CONFIG");
    expect(result.error.message).not.toContain("this is not json");
    expect(
      result.error.settings.some(
        (issue) => issue.setting === "REA_ILSPY_MCP_CONFIG",
      ),
    ).toBe(true);
  });

  it("unwraps the mcpServers.ilspy envelope", async () => {
    const path = await registrationFile({
      mcpServers: {
        ilspy: { command: "ilspy-mcp" },
        unrelated: { command: "untouched" },
      },
    });
    expect(await readIlspyMcpConfiguration(path)).toMatchObject({
      ok: true,
      value: { command: "ilspy-mcp" },
    });
  });

  it("round-trips sensitive name lists into the parsed registration", () => {
    const parsed = ilspyMcpRegistrationSchema.parse({
      command: "ilspy-mcp",
      sensitive: { headers: ["Authorization"], env: ["ILSPY_TOKEN"] },
    });
    expect(parsed.sensitive).toEqual({
      headers: ["Authorization"],
      env: ["ILSPY_TOKEN"],
    });
    const bare = ilspyMcpRegistrationSchema.parse({ command: "ilspy-mcp" });
    expect(bare.sensitive).toBeUndefined();
  });
});
