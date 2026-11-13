import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisError as TypedAnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisCancelledError } from "../../domain/analysisErrorCore.js";
import type { ManagedMemberInspection } from "../../domain/managed/managedArtifact.js";
import type { BinaryTarget } from "../../domain/binaryTargetTypes.js";
import { err, ok, type Result } from "../../domain/result.js";
import { inspectManagedMembersBytes } from "../../dotnet/ManagedMemberInspector.js";
import { readManagedSnapshot } from "../../dotnet/ManagedSnapshot.js";
import { managedInspectionInputFailure } from "../../dotnet/ManagedReaderFailure.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { MANAGED_STATIC_PROVIDER } from "../../domain/investigationProviders.js";

const OPERATION = "decompile_managed_members";

/** Injectable member-inspection seam; the default is REA's own inspection path. */
export type ManagedMemberInspectionSource = (
  assemblyPath: string,
  declaringType: string,
  signal: AbortSignal | undefined,
) => Promise<Result<ManagedMemberInspection, AnalysisError>>;

/**
 * REA's own member inspection: read the assembly through the shared managed
 * snapshot path and parse only with the existing inspector.
 */
export const inspectManagedMembersFromPath: ManagedMemberInspectionSource =
  async (assemblyPath, declaringType, signal) => {
    try {
      const snapshot = await readManagedSnapshot(
        assemblyPath,
        OPERATION,
        signal === undefined ? {} : { signal },
      );
      // shortcut: the inspector consumes only path and sha256 from the target.
      const target = {
        path: assemblyPath,
        sha256: snapshot.sha256,
        kind: "executable",
        format: "pe",
        architecture: "x86",
        availableArchitectures: ["x86"],
        executableRole: "application",
        managed: true,
      } as unknown as BinaryTarget;
      return ok(
        inspectManagedMembersBytes(snapshot.bytes, target, {
          typeNames: [declaringType],
        }),
      );
    } catch (cause: unknown) {
      if (cause instanceof TypedAnalysisError) return err(cause);
      if (signal?.aborted === true)
        return err(
          new AnalysisCancelledError(OPERATION, { cause: signal.reason }),
        );
      const failure = managedInspectionInputFailure(
        OPERATION,
        assemblyPath,
        cause,
      );
      if (failure !== undefined) return err(failure);
      return err(
        new ProviderAdapterError(MANAGED_STATIC_PROVIDER.id, OPERATION, {
          cause,
        }),
      );
    }
  };
