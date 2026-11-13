import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import {
  createIlspyMcpHealthProbe,
  ILSPY_MCP_DOCTOR_SETTINGS,
  inspectIlspyMcpRegistration,
} from "./IlspyDoctor.js";

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
});

const registrationPath = async (registration: unknown): Promise<string> => {
  const root = await mkdtemp(join(tmpdir(), "rea-ilspy-doctor-"));
  roots.push(root);
  const path = join(root, "registration.json");
  await writeFile(path, JSON.stringify(registration));
  return path;
};

it("names the registration setting it reads", () => {
  expect(ILSPY_MCP_DOCTOR_SETTINGS).toEqual(["REA_ILSPY_MCP_CONFIG"]);
});

it("treats an absent registration as a normal observation", async () => {
  const inspection = await inspectIlspyMcpRegistration(undefined);
  expect(inspection).toMatchObject({
    id: "ilspy-mcp",
    configured: false,
    available: false,
    providerVersion: null,
    registrationEnvironment: {},
  });
  const registration = inspection.checks.find(
    ({ name }) => name === "registration",
  );
  expect(registration?.ok).toBe(true);
  expect(registration?.classification).not.toBe("unknown");
  expect(inspection.checks.every(({ ok }) => ok)).toBe(true);
});

it("accepts a valid stdio registration without probing the server", async () => {
  let probes = 0;
  const path = await registrationPath({
    command: "ilspy-mcp-server-must-not-launch",
    args: ["--stdio"],
  });
  const inspection = await inspectIlspyMcpRegistration(path, {
    healthProbe: async () => {
      probes += 1;
      return "9.0.0.0";
    },
  });
  expect(inspection.configured).toBe(true);
  expect(
    inspection.checks.find(({ name }) => name === "registration"),
  ).toMatchObject({ ok: true, code: null });
  // Registration validity never launches the upstream server; only an
  // explicitly supplied probe does, and without one there is no health verdict.
  expect(probes).toBe(1);
  await expect(inspectIlspyMcpRegistration(path)).resolves.toMatchObject({
    available: true,
    checks: [{ name: "registration", ok: true }],
  });
});

it("classifies a malformed registration as config drift without quoting its contents", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-ilspy-doctor-bad-"));
  roots.push(root);
  const path = join(root, "registration.json");
  await writeFile(path, "{ not json fixture-secret");
  const inspection = await inspectIlspyMcpRegistration(path);
  const registration = inspection.checks.find(
    ({ name }) => name === "registration",
  );
  expect(registration).toMatchObject({
    ok: false,
    code: "invalid_configuration",
    classification: "config_drift",
  });
  expect(registration?.detail).toContain("REA_ILSPY_MCP_CONFIG");
  expect(registration?.remediation).toContain("REA_ILSPY_MCP_CONFIG");
  expect(JSON.stringify(inspection)).not.toContain("not json");
});

it("reports an unreachable server as a runtime failure with remediation", async () => {
  const path = await registrationPath({ command: "definitely-unspawnable" });
  const inspection = await inspectIlspyMcpRegistration(path, {
    healthProbe: async () => ({ error: "spawn ENOENT" }),
  });
  expect(inspection.configured).toBe(true);
  const health = inspection.checks.find(({ name }) => name === "health");
  expect(health).toMatchObject({
    ok: false,
    classification: "runtime_failure",
  });
  expect(health?.remediation).toContain("REA_ILSPY_MCP_CONFIG");
});

it("reports the probed server version as an observation", async () => {
  const path = await registrationPath({ command: "ilspy-mcp" });
  const inspection = await inspectIlspyMcpRegistration(path, {
    healthProbe: async () => "9.1.0.7988",
  });
  const health = inspection.checks.find(({ name }) => name === "health");
  expect(health?.ok).toBe(true);
  expect(health?.detail).toContain("9.1.0.7988");
  expect(health?.detail).not.toMatch(/compatib/iu);
  expect(inspection.available).toBe(true);
  expect(inspection.providerVersion).toBe("9.1.0.7988");
});

it("refuses http registrations at use while keeping the registration valid", async () => {
  const path = await registrationPath({
    type: "http",
    url: "http://127.0.0.1:42587/mcp",
  });
  const inspection = await inspectIlspyMcpRegistration(path, {
    healthProbe: async () => "9.1.0.7988",
  });
  expect(
    inspection.checks.find(({ name }) => name === "registration"),
  ).toMatchObject({ ok: true });
  const health = inspection.checks.find(({ name }) => name === "health");
  expect(health?.ok).toBe(false);
  expect(health?.classification).toBe("runtime_failure");
  expect(`${health?.detail} ${health?.remediation}`).toContain("stdio only");
});

it("never leaks sensitive registration values into the inspection", async () => {
  const path = await registrationPath({
    command: "ilspy-mcp",
    env: { API_TOKEN: "fixture-secret" },
    sensitive: { env: ["API_TOKEN"], headers: ["Authorization"] },
  });
  const inspection = await inspectIlspyMcpRegistration(path, {
    healthProbe: async () => ({ error: "fixture-secret must not echo" }),
  });
  expect(JSON.stringify(inspection)).not.toContain("fixture-secret");
});

const probeFakeConnection = (
  overrides: {
    readonly version?: string;
    readonly connectError?: Error;
    readonly closeError?: Error;
  } = {},
) => ({
  connectCalls: 0,
  childAlive: false,
  async connect(): Promise<readonly string[]> {
    this.connectCalls += 1;
    if (overrides.connectError !== undefined) throw overrides.connectError;
    this.childAlive = true;
    return ["decompile_method", "disassemble_method"];
  },
  async call(): Promise<never> {
    throw new Error("health probe never calls tools");
  },
  serverInfo(): unknown {
    return overrides.version === undefined
      ? {}
      : { version: overrides.version };
  },
  detach(): void {},
  async close(): Promise<void> {
    if (overrides.closeError !== undefined) throw overrides.closeError;
    this.childAlive = false;
  },
});

it("default health probe returns the declared server version", async () => {
  const path = await registrationPath({ command: "ilspy-mcp" });
  const fake = probeFakeConnection({ version: "9.1.0" });
  const probe = createIlspyMcpHealthProbe(() => fake as never);
  expect(await probe(path)).toBe("9.1.0");
  expect(fake.connectCalls).toBe(1);
  expect(fake.childAlive).toBe(false);
});

it("default health probe maps failures to fixed error literals", async () => {
  const path = await registrationPath({ command: "ilspy-mcp" });
  const startup = createIlspyMcpHealthProbe(
    () =>
      probeFakeConnection({ connectError: new Error("spawn boom") }) as never,
  );
  expect(await startup(path)).toEqual({ error: "startup" });
  const cleanup = createIlspyMcpHealthProbe(
    () =>
      probeFakeConnection({
        version: "9.1.0",
        closeError: new Error("kill"),
      }) as never,
  );
  expect(await cleanup(path)).toEqual({ error: "cleanup" });
  const invalid = await registrationPath({ command: "ilspy-mcp" });
  await writeFile(invalid, "{ not json", "utf8");
  const registration = createIlspyMcpHealthProbe(
    () => probeFakeConnection() as never,
  );
  expect(await registration(invalid)).toEqual({ error: "registration" });
});

it("default health probe refuses http registrations before connecting", async () => {
  const path = await registrationPath({
    type: "http",
    url: "http://127.0.0.1:42587/mcp",
  });
  let connected = false;
  const probe = createIlspyMcpHealthProbe(() => {
    connected = true;
    return probeFakeConnection() as never;
  });
  expect(await probe(path)).toEqual({
    error:
      "phase one supports stdio only; HTTP registrations validate but are refused at use",
  });
  expect(connected).toBe(false);
});
