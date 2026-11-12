import {
  describeHopperRequestFailure,
  hopperRequestRecovery,
  type HopperRequestFailure,
} from "./HopperDownload.js";
import { HOPPER_LINUX_PRIMARY_FINGERPRINT } from "./HopperReleaseFeed.js";
import type { LinuxPackageInstallFailure } from "./LinuxHopper.js";

export type SetupFailureCode =
  | "unsupported_host"
  | "download_failed"
  | "integrity_mismatch"
  | "authorization_or_package_manager_failed"
  | "launcher_missing"
  | "runtime_dependency_unavailable"
  | "unsupported_hopper_build"
  | "setup_cancelled"
  | "archive_write_failed"
  | "launcher_inspection_failed"
  | "publisher_verification_failed"
  | "skill_install_failed"
  | "cleanup_failed";

export type SetupHopperInstallResult =
  | {
      readonly status: "installed";
      readonly launcherPath: string;
      readonly cleanupFailure?: string;
      readonly warning?: string;
    }
  | {
      readonly status: "failed";
      readonly code: SetupFailureCode;
      readonly remediation: string;
      /** The vendor request whose observed transport failure produced `code`. */
      readonly download?: HopperRequestFailure;
    };

export type SetupHopperInstallFailure = Extract<
  SetupHopperInstallResult,
  { readonly status: "failed" }
>;

export type HopperInstallFailureReason =
  | "unsupported_host"
  | "release_metadata"
  | "download"
  | "integrity"
  | "authorization_or_package_manager"
  | "launcher_missing"
  | "runtime_dependencies"
  | "unsupported_hopper_build"
  | "cancelled"
  | "archive_write"
  | "launcher_inspection"
  | "publisher_verification_failed"
  | "verification_unavailable"
  | "cleanup_failed";

const normalizePackageOutput = (output: string): string =>
  output
    .replace(/\u001b(?:\[[0-9;?]*[ -/]*[@-~]|\([0-9A-Za-z]|[@-Z\\^_])/gu, "")
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/gu, "")
    .replace(/\s+/gu, " ")
    .trim();

const packageOutputExcerpt = (
  failure: LinuxPackageInstallFailure,
  limit = 400,
): string => {
  const output = [failure.stderr, failure.stdout]
    .map(normalizePackageOutput)
    .filter((text) => text !== "")
    .join(" ");
  const suffix = failure.outputTruncated ? " (output truncated)" : "";
  const bodyLimit = limit - suffix.length;
  if (output.length <= bodyLimit) return `${output}${suffix}`;
  const half = Math.floor((bodyLimit - 3) / 2);
  const head = output
    .slice(0, half)
    .replace(/\s+\S*$/u, "")
    .trimEnd();
  const tail = output
    .slice(-half)
    .replace(/^\S*\s+/u, "")
    .trimStart();
  return `${head} … ${tail}${suffix}`;
};

const packageManagerRemediation = (
  failure: LinuxPackageInstallFailure | undefined,
): string => {
  if (failure === undefined)
    return "Allow the system package-manager operation or install the planned Hopper package and Linux runtime dependencies, then rerun rea setup.";
  const status =
    failure.exitCode === null ? "no exit status" : `exit ${failure.exitCode}`;
  const excerpt = packageOutputExcerpt(failure);
  const observed =
    excerpt === "" ? "no output was captured." : `its output: ${excerpt}`;
  return `The system package-manager command failed (${failure.command}; ${status}); ${observed} Resolve the reported problem, grant the authorization the command needs, or install the planned Hopper package and Linux runtime dependencies manually, then rerun rea setup.`;
};

/**
 * Map provider installer failures to stable setup codes and safe recovery. A
 * failed vendor request replaces the stage's generic advice with its observed
 * URL and outcome, and stays structured for programmatic callers.
 */
export const setupInstallFailure = (
  reason: HopperInstallFailureReason,
  context: {
    readonly packageFailure?: LinuxPackageInstallFailure | undefined;
    readonly download?: HopperRequestFailure | undefined;
  } = {},
): SetupHopperInstallFailure => {
  const failure = stageFailure(reason, context.packageFailure);
  return context.download === undefined
    ? failure
    : {
        ...failure,
        remediation: `${describeHopperRequestFailure(context.download)} ${hopperRequestRecovery(context.download)}`,
        download: context.download,
      };
};

const stageFailure = (
  reason: HopperInstallFailureReason,
  packageFailure: LinuxPackageInstallFailure | undefined,
): SetupHopperInstallFailure => {
  switch (reason) {
    case "unsupported_host":
      return {
        status: "failed",
        code: "unsupported_host",
        remediation: "Use a supported host, then rerun rea setup.",
      };
    case "integrity":
      return {
        status: "failed",
        code: "integrity_mismatch",
        remediation:
          "The Hopper download failed integrity verification. Retry setup; if it repeats, update REA before installing.",
      };
    case "authorization_or_package_manager":
      return {
        status: "failed",
        code: "authorization_or_package_manager_failed",
        remediation: packageManagerRemediation(packageFailure),
      };
    case "launcher_missing":
      return {
        status: "failed",
        code: "launcher_missing",
        remediation:
          "The package operation completed but Hopper is not runnable. Run rea doctor and repair the reported launcher issue.",
      };
    case "runtime_dependencies":
      return {
        status: "failed",
        code: "runtime_dependency_unavailable",
        remediation:
          "Hopper's required runtime could not be verified. Inspect rea doctor --provider hopper; on a supported system use rea setup --install-hopper to repair its dependencies.",
      };
    case "unsupported_hopper_build":
      return {
        status: "failed",
        code: "unsupported_hopper_build",
        remediation:
          "The installed Hopper launcher does not match the authenticated vendor package. Check HOPPER_LAUNCHER_PATH and reinstall the official Hopper demo through rea setup.",
      };
    case "cancelled":
      return {
        status: "failed",
        code: "setup_cancelled",
        remediation:
          "Setup was cancelled. Run rea doctor to inspect the current state before retrying.",
      };
    case "archive_write":
      return {
        status: "failed",
        code: "archive_write_failed",
        remediation:
          "The Hopper download completed, but REA could not stage its local archive. Check the reported path, permissions and free space, then retry setup.",
      };
    case "launcher_inspection":
      return {
        status: "failed",
        code: "launcher_inspection_failed",
        remediation:
          "REA could not verify the installed Hopper launcher. Repair the reported inspection failure before retrying; launcher absence has not been established.",
      };
    case "publisher_verification_failed":
      return {
        status: "failed",
        code: "publisher_verification_failed",
        remediation: `The Hopper package signature did not verify under the pinned primary PGP fingerprint ${HOPPER_LINUX_PRIMARY_FINGERPRINT}; the package manager was not run. Download the official package and retry setup.`,
      };
    case "verification_unavailable":
      return {
        status: "failed",
        code: "publisher_verification_failed",
        remediation:
          "REA could not authenticate or retain the signed Hopper package. Check vendor access, native package inspection tools and caller-owned cache permissions, then retry setup.",
      };
    case "cleanup_failed":
      return {
        status: "failed",
        code: "cleanup_failed",
        remediation:
          "Hopper publisher verification retained temporary cleanup ownership. Retry cleanup before running setup again.",
      };
    default:
      return {
        status: "failed",
        code: "download_failed",
        remediation:
          "REA could not download or unpack the official Hopper package. Check network and filesystem access, then retry setup.",
      };
  }
};
