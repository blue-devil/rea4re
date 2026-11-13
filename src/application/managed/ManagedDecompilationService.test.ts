import { createHash } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import type { JsonValue } from "../../domain/jsonValue.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { ConfigurationError } from "../../domain/configurationErrors.js";
import type { Evidence } from "../../domain/evidence.js";
import type { ManagedMemberInspection } from "../../domain/managed/managedArtifact.js";
import type { Result } from "../../domain/result.js";
import {
  buildManagedPeFixture,
  managedPeFixtureTarget,
} from "../../dotnet/ManagedPe.fixture.js";
import { inspectManagedMembersBytes } from "../../dotnet/ManagedMemberInspector.js";
import type { IlspyMcpConnection } from "../../ilspy/IlspyMcpConnection.js";
import { REQUIRED_ILSPY_TOOLS } from "../../ilspy/IlspyMcpSessionClient.js";
import { decompileManagedMembersEvidence } from "./ManagedDecompilationService.js";

/** Programmable fake seam in the IlspyMcpSessionClient.test.ts style. */
class FakeIlspyConnection {
  tools: readonly string[] = [...REQUIRED_ILSPY_TOOLS];
  connectCalls = 0;
  calls: { name: string; args: unknown }[] = [];
  replies: (() => JsonValue)[] = [];
  connectError: Error | undefined;
  closeError: Error | undefined;
  closeCalls = 0;
  childAlive = false;
  serverInfoValue: JsonValue = { version: "9.9.9-test" };
  async connect(): Promise<readonly string[]> {
    this.connectCalls++;
    if (this.connectError !== undefined) throw this.connectError;
    this.childAlive = true;
    return this.tools;
  }
  async call(name: string, args: unknown): Promise<JsonValue> {
    this.calls.push({ name, args });
    return (this.replies[this.calls.length - 1] ?? (() => ""))();
  }
  serverInfo(): JsonValue {
    return this.serverInfoValue;
  }
  detach(): void {}
  async close(): Promise<void> {
    this.closeCalls++;
    if (!this.childAlive) return;
    if (this.closeError !== undefined) throw this.closeError;
    this.childAlive = false;
  }
}

const ASSEMBLY_PATH = "/tmp/rea-ilspy-fixture/assembly.dll";

interface DecompilationResultBody {
  decompiler: { name: string; version: string | null; family: string };
  methods: {
    token: string;
    name: string;
    status: "reconstructed" | "excluded";
    reason: string | null | undefined;
  }[];
  reconstruction?: {
    reconstruction_id: string;
    static_observation: { evidence_id: string };
    decompiler: {
      name: string;
      version: string | null;
      executable_sha256: string | null;
    };
  };
  limitations: string[];
}

/** Narrow an ok outcome to its Evidence and typed result body. */
const evidenceOf = (
  outcome: Result<Evidence, AnalysisError>,
): { evidence: Evidence; body: DecompilationResultBody } => {
  if (!outcome.ok) throw new Error(`expected ok: ${String(outcome.error)}`);
  return {
    evidence: outcome.value,
    body: outcome.value.normalized_result as unknown as DecompilationResultBody,
  };
};

/** Real REA inspection of the fixture PE, scoped to its single declaring type. */
const fixtureInspection = (
  options: Parameters<typeof buildManagedPeFixture>[0],
): ManagedMemberInspection => {
  const bytes = buildManagedPeFixture(options);
  const all = inspectManagedMembersBytes(bytes, managedPeFixtureTarget(bytes));
  const declaringType = all.methods[0]?.declaring_type ?? "";
  return inspectManagedMembersBytes(
    bytes,
    managedPeFixtureTarget(bytes, ASSEMBLY_PATH),
    { typeNames: [declaringType] },
  );
};

const withTruncationFooter = (text: string): string =>
  `${text}\n[pagination:{total:10,returned:5,truncated:true,offset:0}]`;

let configDir: string | undefined;
const configPathWith = async (registration: unknown): Promise<string> => {
  configDir ??= await mkdtemp(join(tmpdir(), "rea-ilspy-config-"));
  const path = join(configDir, `config-${String(Math.random()).slice(2)}.json`);
  await writeFile(
    path,
    JSON.stringify({ mcpServers: { ilspy: registration } }),
  );
  return path;
};

const stdioConfig = () =>
  configPathWith({ type: "stdio", command: process.execPath, args: [] });

const run = async (
  inspection: ManagedMemberInspection,
  connection: FakeIlspyConnection,
  overrides: {
    input?: Record<string, unknown>;
    registration?: unknown;
    signal?: AbortSignal;
  } = {},
): Promise<Result<Evidence, AnalysisError>> =>
  decompileManagedMembersEvidence(
    {
      assembly_path: ASSEMBLY_PATH,
      declaring_type: inspection.methods[0]?.declaring_type ?? "",
      output_kind: "decompiled-csharp",
      ...overrides.input,
    },
    undefined,
    {
      configPath: await (overrides.registration === undefined
        ? stdioConfig()
        : configPathWith(overrides.registration)),
      ...(overrides.signal === undefined ? {} : { signal: overrides.signal }),
      connect: () => connection as unknown as IlspyMcpConnection,
      inspectMembers: async () => ({ ok: true, value: inspection }),
    },
  );

describe("decompileManagedMembersEvidence", () => {
  it("joins two members into reconstruction Evidence with the static inspection attached", async () => {
    const inspection = fixtureInspection({
      methodRowCount: 2,
      distinctMemberNames: true,
    });
    const fake = new FakeIlspyConnection();
    fake.replies = [() => "int Method0() => 1;", () => "int Method1() => 2;"];
    const { evidence, body } = evidenceOf(await run(inspection, fake));
    expect(evidence.predicate_type).toBe("rea.managed-decompilation");
    expect(evidence.provider.id).toBe("rea-dotnet-workflows");
    expect(fake.calls).toHaveLength(2);
    expect(fake.calls.map((call) => call.name)).toEqual([
      "decompile_method",
      "decompile_method",
    ]);
    expect(body.methods).toHaveLength(2);
    expect(body.methods.every((m) => m.status === "reconstructed")).toBe(true);
    expect(body.reconstruction?.reconstruction_id).toMatch(/^mre_/);
    expect(evidence.evidence_links).toEqual([
      body.reconstruction?.static_observation.evidence_id,
    ]);
    expect(evidence.limitations.join(" ")).toContain(
      "Upstream ILSpy MCP server declared version 9.9.9-test",
    );
  });

  it("excludes an overload pair and imports only the unique survivors", async () => {
    const base = fixtureInspection({
      methodRowCount: 3,
      distinctMemberNames: true,
    });
    // One overload pair: rows 2 and 3 share a name; row 1 stays unique.
    const inspection = {
      ...base,
      methods: base.methods.map((method, index) =>
        index === 2 ? { ...method, name: base.methods[1]!.name } : method,
      ),
    } as ManagedMemberInspection;
    const fake = new FakeIlspyConnection();
    fake.replies = [() => "int Method0() => 1;", () => "x", () => "y"];
    const { evidence, body } = evidenceOf(await run(inspection, fake));
    const excluded = body.methods.filter((m) => m.status === "excluded");
    expect(excluded).toHaveLength(2);
    expect(
      excluded.every((m) => m.reason?.includes("ambiguous_member_name")),
    ).toBe(true);
    expect(
      body.methods.filter((m) => m.status === "reconstructed"),
    ).toHaveLength(1);
    expect(body.reconstruction).toBeDefined();
    expect(evidence.limitations.join(" ")).toContain("ambiguous_member_name");
  });

  it("drives disassemble_method with showTokens for decompiled-il output", async () => {
    const inspection = fixtureInspection({
      methodRowCount: 1,
      distinctMemberNames: true,
    });
    const token = inspection.methods[0]!.token;
    const fake = new FakeIlspyConnection();
    fake.replies = [
      () => `.method /* ${token.slice(2)} */ int Method0() { ldarg.0 ret }`,
    ];
    const { body } = evidenceOf(
      await run(inspection, fake, { input: { output_kind: "decompiled-il" } }),
    );
    expect(fake.calls[0]?.name).toBe("disassemble_method");
    expect(fake.calls[0]?.args).toMatchObject({ showTokens: true });
    expect(body.methods[0]?.status).toBe("reconstructed");
  });
});

describe("decompileManagedMembersEvidence refusals", () => {
  it("refuses without importing when no member can be joined", async () => {
    const inspection = fixtureInspection({
      methodRowCount: 2,
      distinctMemberNames: true,
    });
    const fake = new FakeIlspyConnection();
    fake.replies = [
      () => withTruncationFooter("a"),
      () => withTruncationFooter("b"),
    ];
    const outcome = await run(inspection, fake);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error("expected err");
    const refusal = `${outcome.error.message} ${String(outcome.error.userMessage ?? "")}`;
    expect(refusal).toContain("truncated_text");
    expect(refusal).toContain(inspection.methods[0]!.name);
  });

  it("propagates the typed startup refusal naming missing tools", async () => {
    const inspection = fixtureInspection({ methodRowCount: 1 });
    const fake = new FakeIlspyConnection();
    fake.tools = ["decompile_method"];
    const outcome = await run(inspection, fake);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error("expected err");
    expect(JSON.stringify(outcome.error.diagnostics)).toContain(
      "disassemble_method",
    );
    expect(fake.calls).toHaveLength(0);
  });

  it("refuses an http registration as unsupported stdio-only transport", async () => {
    const inspection = fixtureInspection({ methodRowCount: 1 });
    const fake = new FakeIlspyConnection();
    const outcome = await run(inspection, fake, {
      registration: { type: "http", url: "http://127.0.0.1:3000/mcp" },
    });
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error("expected err");
    expect(outcome.error).toBeInstanceOf(ConfigurationError);
    expect(outcome.error.message).toContain("stdio");
  });

  it("refuses with a ConfigurationError naming REA_ILSPY_MCP_CONFIG when unconfigured", async () => {
    const outcome = await decompileManagedMembersEvidence(
      {
        assembly_path: ASSEMBLY_PATH,
        declaring_type: "Fixture.Program",
      },
      undefined,
      { configPath: undefined },
    );
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error("expected err");
    expect(outcome.error).toBeInstanceOf(ConfigurationError);
    expect(outcome.error.message).toContain("REA_ILSPY_MCP_CONFIG");
  });
});

describe("decompileManagedMembersEvidence lifecycle", () => {
  it("keeps the Evidence valid and names retained resources when close fails", async () => {
    const inspection = fixtureInspection({
      methodRowCount: 1,
      distinctMemberNames: true,
    });
    const fake = new FakeIlspyConnection();
    fake.replies = [() => "int Method0() => 1;"];
    fake.closeError = new Error("child refused termination");
    const { evidence } = evidenceOf(await run(inspection, fake));
    expect(evidence.limitations.join(" ")).toContain("Incomplete cleanup");
    expect(evidence.limitations.join(" ")).toContain(
      "ILSpy MCP stdio child process",
    );
  });

  it("cancels between members while still closing the session", async () => {
    const inspection = fixtureInspection({
      methodRowCount: 3,
      distinctMemberNames: true,
    });
    const controller = new AbortController();
    const fake = new FakeIlspyConnection();
    fake.replies = [
      () => "int Method0() => 1;",
      () => {
        controller.abort();
        return "int Method1() => 2;";
      },
      () => "int Method2() => 3;",
    ];
    const outcome = await run(inspection, fake, {
      signal: controller.signal,
    });
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error("expected err");
    expect(fake.calls).toHaveLength(2);
    expect(outcome.error.message).toContain("cancelled");
    expect(fake.closeCalls).toBe(1);
  });

  it("records the observed decompiler identity, not the joiner placeholder", async () => {
    const inspection = fixtureInspection({
      methodRowCount: 1,
      distinctMemberNames: true,
    });
    const fake = new FakeIlspyConnection();
    fake.replies = [() => "int Method0() => 1;"];
    const { body } = evidenceOf(await run(inspection, fake));
    expect(body.decompiler).toEqual({
      name: "ILSpy.Mcp",
      version: "9.9.9-test",
      family: "ilspy",
    });
    expect(body.reconstruction?.decompiler.name).toBe("ILSpy.Mcp");
    expect(body.reconstruction?.decompiler.version).toBe("9.9.9-test");
    expect(body.reconstruction?.decompiler.executable_sha256).toBe(
      createHash("sha256")
        .update(await readFile(process.execPath))
        .digest("hex"),
    );
  });
});
