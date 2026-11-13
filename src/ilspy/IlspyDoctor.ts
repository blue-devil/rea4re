import type {
  DoctorProviderCheck,
  DoctorProviderInspection,
} from "../application/Doctor.js";
import { readIlspyMcpConfiguration } from "./IlspyMcpConfiguration.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";

/** Client settings consulted by this readiness probe. */
export const ILSPY_MCP_DOCTOR_SETTINGS = ["REA_ILSPY_MCP_CONFIG"] as const;

/**
 * Bounded read-only server probe: open, read the declared version, close.
 * Matches the doctor host's optional `ilspyMcpHealth` capability.
 */
export type IlspyMcpHealthProbe = (
  configPath: string,
  signal?: AbortSignal,
) => Promise<string | undefined | { readonly error: string }>;

const STDIO_ONLY =
  "phase one supports stdio only; HTTP registrations validate but are refused at use";

/** Inspect the ILSpy MCP registration; only an explicitly supplied probe launches the server. */
export const inspectIlspyMcpRegistration = async (
  path: string | undefined,
  options: {
    readonly signal?: AbortSignal;
    readonly healthProbe?: IlspyMcpHealthProbe;
  } = {},
): Promise<DoctorProviderInspection> => {
  const parsed =
    path === undefined
      ? undefined
      : await readIlspyMcpConfiguration(path, {
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        });
  const valid = parsed?.ok === true;
  const isHttp = valid !== true || !("command" in parsed.value);
  const health =
    valid && path !== undefined && (isHttp || options.healthProbe !== undefined)
      ? await inspectHealth(path, isHttp, options)
      : undefined;
  return {
    id: "ilspy-mcp",
    configured: path !== undefined,
    available: valid && (health === undefined || health.ok),
    providerVersion: health?.ok === true ? (health.version ?? null) : null,
    registrationEnvironment:
      valid && path !== undefined ? { REA_ILSPY_MCP_CONFIG: path } : {},
    checks: [
      {
        name: "registration",
        ok: path === undefined ? true : valid,
        code: valid || path === undefined ? null : "invalid_configuration",
        detail:
          path === undefined
            ? "ILSpy MCP registration is not configured; set REA_ILSPY_MCP_CONFIG to enable it."
            : valid
              ? "ILSpy MCP registration is valid. This check reads the configuration only; the server is not launched here."
              : parsed?.ok === false
                ? parsed.error.message
                : "",
        remediation:
          valid || path === undefined
            ? null
            : "Set REA_ILSPY_MCP_CONFIG to a valid ILSpy MCP stdio command/args (or loopback url) JSON registration.",
        classification: "config_drift",
      },
      ...(health === undefined ? [] : [health.check]),
    ],
  };
};

const inspectHealth = async (
  path: string,
  isHttp: boolean,
  options: {
    readonly signal?: AbortSignal;
    readonly healthProbe?: IlspyMcpHealthProbe;
  },
): Promise<{ ok: boolean; version?: string; check: DoctorProviderCheck }> => {
  if (isHttp)
    return {
      ok: false,
      check: {
        name: "health",
        ok: false,
        code: "unsupported_transport",
        detail: `The registration selects an HTTP transport; ${STDIO_ONLY}.`,
        remediation: `Set REA_ILSPY_MCP_CONFIG to a stdio command/args registration; ${STDIO_ONLY}.`,
        classification: "runtime_failure",
      },
    };
  let probed: string | undefined | { readonly error: string };
  try {
    probed = await options.healthProbe!(path, options.signal);
  } catch (cause: unknown) {
    if (cause instanceof AnalysisCancelledError) throw cause;
    probed = { error: "unreachable" };
  }
  if (typeof probed === "string")
    return {
      ok: true,
      version: probed,
      check: {
        name: "health",
        ok: true,
        code: null,
        detail: `The upstream ILSpy MCP server declares version ${probed}; reported as an observation only.`,
        remediation: null,
        classification: "runtime_failure",
      },
    };
  // Probe error text can echo registration-derived values; never admit it.
  return {
    ok: false,
    check: {
      name: "health",
      ok: false,
      code: "probe_failed",
      detail:
        "The ILSpy MCP server could not be reached or did not complete the bounded health probe.",
      remediation:
        "Check the command configured under REA_ILSPY_MCP_CONFIG and that the ILSpy MCP server starts, then rerun.",
      classification: "runtime_failure",
    },
  };
};
