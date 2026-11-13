import { describe, expect, it } from "vitest";

import { ConfigurationError } from "../domain/configurationErrors.js";
import {
  buildManagedPeFixture,
  managedPeFixtureTarget,
} from "./ManagedPe.fixture.js";
import { ManagedStaticProvider } from "./ManagedStaticProvider.js";

const decompileParameters = {
  assembly_path: "/tmp/fixture.exe",
  declaring_type: "Fixture.Program",
};

describe("ManagedStaticProvider decompile_managed_members dispatch", () => {
  it("admits the operation for a PE target and refuses unconfigured REA_ILSPY_MCP_CONFIG", async () => {
    const bytes = buildManagedPeFixture();
    const client = new ManagedStaticProvider().createClient(
      managedPeFixtureTarget(bytes),
    );
    try {
      const outcome = await client.execute(
        "decompile_managed_members",
        decompileParameters,
      );
      expect(outcome.ok).toBe(false);
      if (outcome.ok) throw new Error("expected refusal");
      expect(outcome.error).toBeInstanceOf(ConfigurationError);
      expect(outcome.error.message).toContain("REA_ILSPY_MCP_CONFIG");
    } finally {
      await client.close();
    }
  });

  it("forwards the typed input refusal from the workflow", async () => {
    const bytes = buildManagedPeFixture();
    const client = new ManagedStaticProvider().createClient(
      managedPeFixtureTarget(bytes),
    );
    try {
      const outcome = await client.execute("decompile_managed_members", {
        ...decompileParameters,
        output_kind: "csharp",
      });
      expect(outcome.ok).toBe(false);
      if (outcome.ok) throw new Error("expected refusal");
      expect(outcome.error.message).toContain(
        "Invalid analysis input for decompile_managed_members",
      );
    } finally {
      await client.close();
    }
  });

  it("refuses a non-PE target before the workflow runs", async () => {
    const bytes = buildManagedPeFixture();
    const client = new ManagedStaticProvider().createClient({
      ...managedPeFixtureTarget(bytes),
      format: "elf",
    });
    try {
      const outcome = await client.execute(
        "decompile_managed_members",
        decompileParameters,
      );
      expect(outcome.ok).toBe(false);
      if (outcome.ok) throw new Error("expected refusal");
      expect(outcome.error.message).toContain("PE target");
    } finally {
      await client.close();
    }
  });
});
