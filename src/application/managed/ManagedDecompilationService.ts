import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { z } from "zod";

import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisError as TypedAnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
} from "../../domain/analysisErrorCore.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  MANAGED_STATIC_PROVIDER,
  MANAGED_WORKFLOW_PROVIDER,
} from "../../domain/investigationProviders.js";
import type { ManagedMemberInspection } from "../../domain/managed/managedArtifact.js";
import {
  managedDecompilationInputSchema,
  managedDecompilationResultSchema,
} from "../../domain/managed/managedDecompilation.js";
import {
  executeManagedReconstructionImport,
  resolveManagedReconstructionImport,
  type ManagedReconstructionImportRequest,
} from "../../domain/managed/managedReconstruction.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { EvidenceLookup } from "../EvidenceInputResolver.js";
import {
  createIlspyMcpConnection,
  type IlspyMcpConnection,
} from "../../ilspy/IlspyMcpConnection.js";
import type { IlspyMcpRegistration } from "../../ilspy/IlspyMcpConfiguration.js";
import {
  ilspyConfigurationError,
  readIlspyMcpConfiguration,
} from "../../ilspy/IlspyMcpConfiguration.js";
import {
  IlspyCleanupError,
  IlspyMcpSessionClient,
} from "../../ilspy/IlspyMcpSessionClient.js";
import {
  buildIlspyReconstructionRequest,
  ilspyExclusionLines,
  ilspySelectionFromToolReply,
  uniqueNameMethods,
  type IlspyMemberSelection,
} from "../../ilspy/IlspyMemberJoin.js";
import {
  inspectManagedMembersFromPath,
  type ManagedMemberInspectionSource,
} from "./ManagedDecompilationInspection.js";

const OPERATION = "decompile_managed_members";

const REGISTRATION_SUMMARY =
  "REA_ILSPY_MCP_CONFIG stdio registration (values redacted)";

/** Spec trust model: csharp text binds only by upstream name-based selection. */
const CSHARP_TRUST_LIMITATION =
  "Decompiled C# text is selected by upstream method name only; decompiled IL additionally verifies the member metadata token appears in the response before it joins.";

type DecompilationResultBody = Omit<
  z.output<typeof managedDecompilationResultSchema>,
  "limitations"
> & { limitations: readonly string[] };

interface DecompilationOutcome {
  readonly result: DecompilationResultBody;
  readonly staticEvidenceId: string;
}

export interface ManagedDecompilationOptions {
  readonly signal?: AbortSignal;
  /** Path carried by REA_ILSPY_MCP_CONFIG in the composition layer's config. */
  readonly configPath: string | undefined;
  /** Injectable MCP boundary for tests. */
  readonly connect?: (
    registration: IlspyMcpRegistration,
    timeoutMs: number,
    environment: Readonly<NodeJS.ProcessEnv>,
  ) => IlspyMcpConnection;
  /** Injectable REA member inspection for tests. */
  readonly inspectMembers?: ManagedMemberInspectionSource;
}

/** Decompile selected managed members via BYO ILSpy-MCP and return reconstruction Evidence. */
export const decompileManagedMembersEvidence = async (
  rawInput: unknown,
  _lookup?: EvidenceLookup,
  options: ManagedDecompilationOptions = { configPath: undefined },
): Promise<Result<Evidence, AnalysisError>> => {
  const parsed = managedDecompilationInputSchema.safeParse(rawInput);
  if (!parsed.success)
    return err(
      analysisInputErrorFromIssues(OPERATION, parsed.error.issues, rawInput),
    );
  const {
    assembly_path: assemblyPath,
    declaring_type: declaringType,
    member_names: memberNames,
    output_kind: outputKind,
  } = parsed.data;
  const signal = options.signal;
  const registration = await admitIlspyRegistration(options.configPath, signal);
  if (!registration.ok) return registration;
  const inspected = await (
    options.inspectMembers ?? inspectManagedMembersFromPath
  )(assemblyPath, declaringType, signal);
  if (!inspected.ok) return inspected;
  const inspection = inspected.value;
  const selection = selectRequestedMembers(
    inspection,
    memberNames,
    declaringType,
    assemblyPath,
  );
  if (!selection.ok) return selection;
  const { requested, candidateTokens } = selection.value;
  const connect = options.connect ?? createIlspyMcpConnection;
  const client = new IlspyMcpSessionClient(
    connect(registration.value, registration.value.timeoutMs, process.env),
    REGISTRATION_SUMMARY,
  );
  let cleanupLimitation: string | undefined;
  let outcome: Result<DecompilationOutcome, AnalysisError> | undefined;
  try {
    outcome = await runDecompilation(inspection, requested, candidateTokens, {
      outputKind,
      client,
      signal,
      command: registration.value.command,
    });
  } finally {
    try {
      await client.close();
    } catch (cause: unknown) {
      // Cleanup failure is not analysis failure; the Evidence stays valid.
      if (cause instanceof IlspyCleanupError)
        cleanupLimitation = `Incomplete cleanup: ${cause.cleanupResources.join("; ")} retained by the ILSpy MCP session; termination remains retryable.`;
    }
  }
  if (outcome === undefined)
    throw new TypeError("decompile outcome was not produced");
  if (!outcome.ok) return outcome;
  return ok(
    decompilationEvidence(outcome.value, {
      inspection,
      assemblyPath,
      declaringType,
      memberNames,
      outputKind,
      cleanupLimitation,
    }),
  );
};

/** Read and admit the configured registration; http is refused for phase one. */
const admitIlspyRegistration = async (
  configPath: string | undefined,
  signal: AbortSignal | undefined,
): Promise<
  Result<IlspyMcpRegistration & { command: string }, AnalysisError>
> => {
  if (configPath === undefined)
    return err(
      ilspyConfigurationError(
        "REA_ILSPY_MCP_CONFIG is not configured; set REA_ILSPY_MCP_CONFIG to an ILSpy MCP stdio registration file before decompiling managed members.",
      ),
    );
  let registration: Result<IlspyMcpRegistration, AnalysisError>;
  try {
    registration = await readIlspyMcpConfiguration(
      configPath,
      signal === undefined ? {} : { signal },
    );
  } catch (cause: unknown) {
    if (cause instanceof TypedAnalysisError) return err(cause);
    throw cause;
  }
  if (!registration.ok) return registration;
  const admitted = registration.value;
  if (!("command" in admitted))
    return err(
      ilspyConfigurationError(
        "unsupported_transport: phase one supports stdio registrations only; the HTTP registration is validated but refused.",
      ),
    );
  return ok(admitted);
};

/** Intersection of the declaring type's members with the requested names. */
const selectRequestedMembers = (
  inspection: ManagedMemberInspection,
  memberNames: readonly string[] | undefined,
  declaringType: string,
  assemblyPath: string,
): Result<
  {
    readonly requested: readonly ManagedMemberInspection["methods"][number][];
    readonly candidateTokens: ReadonlySet<string>;
  },
  AnalysisError
> => {
  if (inspection.methods.length === 0) {
    const message = `Declaring type ${declaringType} in ${assemblyPath} has no managed members to decompile.`;
    return err(
      new AnalysisInputError(
        OPERATION,
        { userMessage: message, conformsToInputContract: true },
        [{ path: ["declaring_type"], reason: "invalid_value", message }],
      ),
    );
  }
  const requested =
    memberNames === undefined
      ? inspection.methods
      : inspection.methods.filter((method) =>
          memberNames.includes(method.name),
        );
  if (requested.length === 0) {
    const message = `None of the requested member names (${memberNames!.join(", ")}) exist on declaring type ${declaringType}.`;
    return err(
      new AnalysisInputError(
        OPERATION,
        { userMessage: message, conformsToInputContract: true },
        [{ path: ["member_names"], reason: "invalid_value", message }],
      ),
    );
  }
  const candidateTokens = new Set(
    uniqueNameMethods(inspection)
      .filter(
        (method) =>
          memberNames === undefined || memberNames.includes(method.name),
      )
      .map((method) => method.token),
  );
  return ok({ requested, candidateTokens });
};

const decompilationEvidence = (
  outcome: DecompilationOutcome,
  context: {
    readonly inspection: ManagedMemberInspection;
    readonly assemblyPath: string;
    readonly declaringType: string;
    readonly memberNames: readonly string[] | undefined;
    readonly outputKind: "decompiled-csharp" | "decompiled-il";
    readonly cleanupLimitation: string | undefined;
  },
): Evidence => {
  const limitations = [
    ...outcome.result.limitations,
    ...(context.cleanupLimitation === undefined
      ? []
      : [context.cleanupLimitation]),
  ];
  const body = managedDecompilationResultSchema.parse({
    ...outcome.result,
    limitations,
  });
  return createEvidence(
    {
      path: context.assemblyPath,
      sha256: context.inspection.artifact.sha256,
      format: "pe",
    },
    MANAGED_WORKFLOW_PROVIDER,
    {
      predicateType: "rea.managed-decompilation",
      operation: OPERATION,
      parameters: {
        assembly_path: context.assemblyPath,
        declaring_type: context.declaringType,
        output_kind: context.outputKind,
        ...(context.memberNames === undefined
          ? {}
          : { member_names: [...context.memberNames] }),
      },
      result: body,
      rawResult: null,
      confidence: "inferred",
      authority: "analyst-inference",
      environment: null,
      limitations,
      locations: [{ kind: "artifact-path", path: context.assemblyPath }],
      evidenceLinks: [outcome.staticEvidenceId],
    },
  );
};

const runDecompilation = async (
  inspection: ManagedMemberInspection,
  requested: readonly ManagedMemberInspection["methods"][number][],
  candidateTokens: ReadonlySet<string>,
  options: {
    readonly outputKind: "decompiled-csharp" | "decompiled-il";
    readonly client: IlspyMcpSessionClient;
    readonly signal: AbortSignal | undefined;
    readonly command: string;
  },
): Promise<Result<DecompilationOutcome, AnalysisError>> => {
  const { outputKind, client, signal } = options;
  const opened = await client.open();
  if (!opened.ok) return err(opened.error);
  const serverVersion = opened.value.serverVersion;
  const calls = await callUpstreamMembers(
    inspection,
    requested,
    candidateTokens,
    {
      outputKind,
      client,
      signal,
    },
  );
  if (!calls.ok) return calls;
  const { selections, truncatedTexts } = calls.value;
  const { request, excluded } = buildIlspyReconstructionRequest(
    inspection,
    selections,
  );
  const exclusionLines = ilspyExclusionLines(
    requested,
    candidateTokens,
    excluded,
    truncatedTexts,
  );
  if (request.methods.length === 0) {
    const message = `No requested member could be joined for reconstruction: ${exclusionLines.join("; ")}.`;
    return err(
      new AnalysisInputError(
        OPERATION,
        { userMessage: message, conformsToInputContract: true },
        [{ path: ["member_names"], reason: "invalid_value", message }],
      ),
    );
  }
  return assembleDecompilationOutcome(inspection, requested, candidateTokens, {
    outputKind,
    command: options.command,
    serverVersion,
    request,
    excluded,
    truncatedTexts,
    exclusionLines,
  });
};

/** Serial upstream calls, one per unique-name candidate, honoring the signal. */
const callUpstreamMembers = async (
  inspection: ManagedMemberInspection,
  requested: readonly ManagedMemberInspection["methods"][number][],
  candidateTokens: ReadonlySet<string>,
  options: {
    readonly outputKind: "decompiled-csharp" | "decompiled-il";
    readonly client: IlspyMcpSessionClient;
    readonly signal: AbortSignal | undefined;
  },
): Promise<
  Result<
    {
      readonly selections: readonly IlspyMemberSelection[];
      readonly truncatedTexts: ReadonlyMap<string, string>;
    },
    AnalysisError
  >
> => {
  const { outputKind, client, signal } = options;
  const toolName =
    outputKind === "decompiled-il" ? "disassemble_method" : "decompile_method";
  const selections: IlspyMemberSelection[] = [];
  const truncatedTexts = new Map<string, string>();
  for (const method of requested) {
    if (!candidateTokens.has(method.token)) continue;
    if (signal?.aborted === true)
      return err(
        new AnalysisCancelledError(OPERATION, { cause: signal.reason }),
      );
    const call = await client.callTool(toolName, {
      assemblyPath: inspection.artifact.path,
      typeName: method.declaring_type ?? "",
      methodName: method.name,
      ...(outputKind === "decompiled-il" ? { showTokens: true } : {}),
    });
    const selection = ilspySelectionFromToolReply(
      call,
      method.token,
      outputKind,
    );
    if (selection.truncated) truncatedTexts.set(method.token, selection.text);
    selections.push(selection);
  }
  return ok({ selections, truncatedTexts });
};
/** Attach the observed inspection Evidence, import, and per-member rows. */
const assembleDecompilationOutcome = async (
  inspection: ManagedMemberInspection,
  requested: readonly ManagedMemberInspection["methods"][number][],
  candidateTokens: ReadonlySet<string>,
  facts: {
    readonly outputKind: "decompiled-csharp" | "decompiled-il";
    readonly command: string;
    readonly serverVersion: string | null;
    readonly request: ReturnType<
      typeof buildIlspyReconstructionRequest
    >["request"];
    readonly excluded: readonly { token: string; reason: string }[];
    readonly truncatedTexts: ReadonlyMap<string, string>;
    readonly exclusionLines: readonly string[];
  },
): Promise<Result<DecompilationOutcome, AnalysisError>> => {
  const executableSha256 = await sha256OrUndefined(facts.command);
  const declaringType = inspection.methods[0]!.declaring_type ?? "";
  const staticEvidence = createEvidence(
    {
      path: inspection.artifact.path,
      sha256: inspection.artifact.sha256,
      format: "pe",
    },
    MANAGED_STATIC_PROVIDER,
    {
      operation: "inspect_managed_members",
      parameters: { type_names: [declaringType] },
      result: inspection,
      limitations: inspection.limitations,
      locations: [{ kind: "artifact-path", path: inspection.artifact.path }],
    },
  );
  const importRequest: ManagedReconstructionImportRequest = {
    ...facts.request,
    decompiler: {
      name: "ILSpy.Mcp",
      version: facts.serverVersion,
      family: "ilspy",
      executable_sha256: executableSha256 ?? null,
      options: [],
    },
    static_members: staticEvidence,
  };
  const resolved = resolveManagedReconstructionImport(importRequest);
  if (!resolved.ok) return err(resolved.error);
  const importResult = executeManagedReconstructionImport(resolved.value);
  const methods = memberResultRows(
    requested,
    importResult,
    facts.excluded,
    facts.truncatedTexts,
  );
  return ok({
    result: {
      decompiler: {
        name: "ILSpy.Mcp",
        version: facts.serverVersion,
        family: "ilspy" as const,
      },
      assembly: {
        path: inspection.artifact.path,
        sha256: inspection.artifact.sha256,
      },
      methods,
      reconstruction: importResult,
      limitations: [
        ...facts.exclusionLines,
        ...(facts.outputKind === "decompiled-csharp"
          ? [CSHARP_TRUST_LIMITATION]
          : []),
        `Upstream ILSpy MCP server declared version ${facts.serverVersion ?? "(unavailable)"}; recorded as an observation, not a compatibility contract.`,
      ],
    },
    staticEvidenceId: staticEvidence.evidence_id,
  });
};
const memberResultRows = (
  requested: readonly ManagedMemberInspection["methods"][number][],
  importResult: ReturnType<typeof executeManagedReconstructionImport>,
  excluded: readonly { token: string; reason: string }[],
  truncatedTexts: ReadonlyMap<string, string>,
) => {
  const joinedByToken = new Map(
    importResult.methods.map((method) => [method.token, method]),
  );
  const excludedByToken = new Map(
    excluded.map((item) => [item.token, item.reason]),
  );
  return requested.map((method) => {
    const joined = joinedByToken.get(method.token);
    if (joined !== undefined) {
      // The result schema admits the reconstruction record, not its import metrics.
      const {
        text_length: _textLength,
        line_count: _lineCount,
        ...reconstruction
      } = joined.reconstruction;
      return {
        token: method.token,
        declaring_type: method.declaring_type,
        name: method.name,
        status: "reconstructed" as const,
        reason: null,
        reconstruction,
      };
    }
    const reason = excludedByToken.get(method.token) ?? "ambiguous_member_name";
    const raw = truncatedTexts.get(method.token);
    return {
      token: method.token,
      declaring_type: method.declaring_type,
      name: method.name,
      status: "excluded" as const,
      reason: raw === undefined ? reason : `${reason} (raw text: ${raw})`,
    };
  });
};

const sha256OrUndefined = async (path: string): Promise<string | undefined> => {
  try {
    return createHash("sha256")
      .update(await readFile(path))
      .digest("hex");
  } catch {
    return undefined;
  }
};
