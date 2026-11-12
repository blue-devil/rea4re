import {
  linuxHopperLauncherCandidates,
  REA_MANAGED_LINUX_HOPPER_LAUNCHER,
} from "./LinuxHopper.js";

/**
 * Where automatic Hopper discovery looks on one platform. Runtime configuration
 * and doctor both read it, so doctor checks the same candidates, in the same
 * order, as CLI/MCP startup.
 */
export interface HopperLauncherDiscovery {
  /** Fixed launcher paths, probed in order. */
  readonly candidates: readonly string[];
  /** Launcher runtime configures when no candidate is executable. */
  readonly fallback: string;
}

/** Select the automatic Hopper launcher candidates for one platform. */
export const hopperLauncherDiscovery = (
  platform: NodeJS.Platform,
  homeDirectory: string,
): HopperLauncherDiscovery =>
  platform === "linux"
    ? {
        candidates: linuxHopperLauncherCandidates(homeDirectory),
        fallback: REA_MANAGED_LINUX_HOPPER_LAUNCHER,
      }
    : { candidates: [], fallback: REA_MANAGED_LINUX_HOPPER_LAUNCHER };
