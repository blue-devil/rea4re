import {
  IDA_PROVIDER_IDENTITY,
  IDA_OPERATIONS,
} from "./IdaProviderMetadata.js";
import type { IdaCompatibilityProfile } from "./IdaConfiguration.js";
import type { CapabilityDescriptor } from "../application/AnalysisProvider.js";

export type IdaOperation = (typeof IDA_OPERATIONS)[number];

/** Shared limitations of observations from an externally mutable analysis database. */
export const IDA_LIMITATIONS = Object.freeze([
  "Provider version identifies the REA IDA adapter. IDA engine and upstream distribution versions are unknown unless separately observed; MCP serverInfo is reported independently.",
  "Results describe the current IDA analysis database. Input identity does not prove an unmodified database; patches, annotations, analysis completeness, and database revision remain unknown.",
  "Live results are never replayed from analysis snapshots. Target checks before and after a request do not provide an atomic lock against external GUI changes.",
  "Caller cancellation drains the in-flight MCP request before cleanup; it does not prove that IDA engine work was interrupted.",
  "Headless workers are released through the upstream database lifecycle. Abrupt termination of REA, its proxy, or the supervisor cannot prove worker cleanup; inspect upstream inventory after an interrupted process.",
  "Complete function body ranges, typed references, unresolved indirect calls, referenced data, and basic blocks are unavailable in this adapter. Empty unsupported dossier facets are unknown, not observed absence.",
]);

/**
 * Advertise live observations truthfully. `execute_python` reads the attached
 * database and never navigates the IDA GUI, so no operation may show UI.
 */
export const idaCapabilities = (
  profile: IdaCompatibilityProfile,
  stdio: boolean,
): readonly CapabilityDescriptor[] => {
  const headless = profile.mode === "headless";
  return IDA_OPERATIONS.map((operation) => ({
    provider: IDA_PROVIDER_IDENTITY,
    operation,
    available: true as const,
    reason: null,
    cachePolicy: "live" as const,
    effects: {
      mutatesArtifact: false,
      launchesProcess: stdio || headless,
      mayShowUi: false,
      mayAccessNetwork: true,
      mayWriteFilesystem: stdio || headless,
      changesPermissions: false,
      requiresRoot: false,
    },
    limitations: [...IDA_LIMITATIONS],
  }));
};
