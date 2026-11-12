import { expect, it } from "vitest";

import type { HopperLauncherOutcome } from "../domain/hopperErrors.js";
import { hopperLauncherReportedApplicationNotFound } from "./HopperProcessDiagnostic.js";

// Captured from Hopper 6's unmodified helper with Spotlight indexing disabled.
const notFound: HopperLauncherOutcome = {
  exit_code: 3,
  signal: null,
  stdout: { text: "", bytes: 0, retained_bytes: 0 },
  stderr: {
    text: "Hopper has not been found.\nPlease make sure that Spotlight is active in order for this tool to find Hopper's executable.\n",
    bytes: 121,
    retained_bytes: 121,
  },
  output_closed: true,
  diagnostic_truncated: false,
};

it("recognizes the native helper's complete Spotlight not-found report", () => {
  expect(hopperLauncherReportedApplicationNotFound(notFound)).toBe(true);
});

it.each([
  { stdout: { text: "wrapper output\n", bytes: 15, retained_bytes: 15 } },
  { stdout: { text: "", bytes: 1, retained_bytes: 0 } },
  { output_closed: false },
  { diagnostic_truncated: true },
  { signal: "SIGTERM", exit_code: null },
  { exit_code: 2 },
  {
    stderr: {
      ...notFound.stderr,
      text: `${notFound.stderr.text}another failure\n`,
    },
  },
])("rejects other not-found diagnostic shapes: %j", (change) => {
  expect(
    hopperLauncherReportedApplicationNotFound({ ...notFound, ...change }),
  ).toBe(false);
});
