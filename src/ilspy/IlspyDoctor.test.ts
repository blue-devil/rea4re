import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import {
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
  // Registration validity never launches the upstream server.
  expect(probes).toBe(1); // only the explicitly supplied health probe ran
  await expect(inspectIlspyMcpRegistration(path)).resolves.toMatchObject({
    available: true,
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
