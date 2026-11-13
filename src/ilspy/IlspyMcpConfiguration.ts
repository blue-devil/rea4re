import { z } from "zod";
import { jsonRecordSchema } from "../domain/jsonRecord.js";
import { ConfigurationError } from "../domain/configurationErrors.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import type { AnalysisInputIssue } from "../domain/analysisErrorCore.js";
import { projectInputIssues } from "../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  withOwnedRegularFile,
  regularFileCancellation,
} from "../filesystem/OwnedRegularFile.js";
import {
  NonRegularFileReadError,
  RegularFileOperationCancelled,
} from "../filesystem/RegularFile.js";
import { readBoundedFileBytes } from "../process/BoundedFileBytes.js";

/** Omitted registration `timeoutMs` for each upstream ILSpy MCP request. */
export const DEFAULT_ILSPY_REQUEST_TIMEOUT_MS = 300_000;
/** Shortest valid registration request timeout. */
const MIN_ILSPY_REQUEST_TIMEOUT_MS = 1;
/** Node timer ceiling. Larger registration values would be clamped instead of honored. */
const MAX_ILSPY_REQUEST_TIMEOUT_MS = 2_147_483_647;
/** Loopback host names accepted for the phase-one refused HTTP transport. */
const LOCAL_ILSPY_HTTP_HOSTS = ["localhost", "127.0.0.1", "[::1]"];

const common = {
  sensitive: z
    .strictObject({
      headers: z.array(z.string().min(1)).default([]),
      env: z.array(z.string().min(1)).default([]),
    })
    .optional(),
  timeoutMs: z
    .int()
    .min(MIN_ILSPY_REQUEST_TIMEOUT_MS)
    .max(MAX_ILSPY_REQUEST_TIMEOUT_MS)
    .default(DEFAULT_ILSPY_REQUEST_TIMEOUT_MS),
};

/** One ILSpy MCP registration: stdio command or loopback HTTP URL. */
export const ilspyMcpRegistrationSchema = z.union([
  z
    .object({
      ...common,
      type: z.literal("stdio").optional(),
      command: z.string().min(1),
      args: z.array(z.string()).default([]),
      env: jsonRecordSchema(z.string()).default({}),
    })
    .strict(),
  z
    .object({
      ...common,
      type: z.literal("http").optional(),
      url: z.url().refine((value) => {
        const url = new URL(value);
        return (
          ["http:", "https:"].includes(url.protocol) &&
          LOCAL_ILSPY_HTTP_HOSTS.includes(url.hostname) &&
          url.username === "" &&
          url.password === ""
        );
      }, "ILSpy MCP HTTP transport requires a loopback URL without credentials"),
    })
    .strict(),
]);

/** An upstream ILSpy MCP registration. */
export type IlspyMcpRegistration = z.infer<typeof ilspyMcpRegistrationSchema>;

/** Render only schema-owned constraints, never rejected registration values. */
const registrationConstraint = (
  issue: AnalysisInputIssue,
): string | undefined => {
  if (issue.path.length === 1 && issue.path[0] === "timeoutMs")
    return `timeoutMs must be an integer from ${String(MIN_ILSPY_REQUEST_TIMEOUT_MS)} to ${String(MAX_ILSPY_REQUEST_TIMEOUT_MS)} milliseconds`;
  return issue.message === undefined
    ? undefined
    : `${issue.path.join(".") || "registration"}: ${issue.message}`;
};

/** A REA_ILSPY_MCP_CONFIG rejection that names the setting it concerns. */
export const ilspyConfigurationError = (
  constraint: string,
  cause?: unknown,
): ConfigurationError =>
  new ConfigurationError(constraint, {
    ...(cause === undefined ? {} : { cause }),
    settings: [{ setting: "REA_ILSPY_MCP_CONFIG", constraint }],
  });

const MAXIMUM_REGISTRATION_BYTES = 65_536;
const registrationTooLarge = () =>
  ilspyConfigurationError(
    "REA_ILSPY_MCP_CONFIG exceeds the 64 KiB registration size.",
  );

/** Read one explicit ILSpy MCP registration without starting the server. */
export const readIlspyMcpConfiguration = (
  path: string,
  options: { readonly signal?: AbortSignal } = {},
): Promise<Result<IlspyMcpRegistration, ConfigurationError>> =>
  (async () => {
    try {
      const text = await withOwnedRegularFile<string>(
        path,
        options.signal === undefined ? {} : { signal: options.signal },
        async ({ handle, initial: metadata }) => {
          if (metadata.size > MAXIMUM_REGISTRATION_BYTES)
            throw registrationTooLarge();
          const bytes = await readBoundedFileBytes(
            handle,
            MAXIMUM_REGISTRATION_BYTES,
            {
              signal: options.signal,
              cancellationFailure: (reason) =>
                new RegularFileOperationCancelled(reason),
            },
          );
          if (bytes === undefined) throw registrationTooLarge();
          return bytes.toString("utf8");
        },
      );
      let input: unknown;
      try {
        input = JSON.parse(text);
      } catch (cause: unknown) {
        throw ilspyConfigurationError(
          "REA_ILSPY_MCP_CONFIG must contain valid JSON.",
          cause,
        );
      }
      const envelope = z
        .object({ mcpServers: z.object({ ilspy: z.unknown() }) })
        .safeParse(input);
      const registration = envelope.success
        ? envelope.data.mcpServers.ilspy
        : input;
      const parsed = ilspyMcpRegistrationSchema.safeParse(registration);
      if (parsed.success) return ok(parsed.data);
      // Only schema-authored correction text is admitted; Zod's aggregate
      // message can contain registration values, including credentials.
      const constraints = projectInputIssues(
        parsed.error.issues,
        registration,
      ).flatMap((issue) => {
        const constraint = registrationConstraint(issue);
        return constraint === undefined ? [] : [constraint];
      });
      if (constraints.length === 0)
        return err(
          ilspyConfigurationError(
            "REA_ILSPY_MCP_CONFIG must contain an ILSpy MCP command/args or loopback url registration.",
            parsed.error,
          ),
        );
      return err(
        new ConfigurationError(
          `REA_ILSPY_MCP_CONFIG: ${constraints.join("; ")}.`,
          {
            cause: parsed.error,
            settings: constraints.map((constraint) => ({
              setting: "REA_ILSPY_MCP_CONFIG",
              constraint,
            })),
          },
        ),
      );
    } catch (cause: unknown) {
      if (cause instanceof ConfigurationError) return err(cause);
      if (cause instanceof NonRegularFileReadError)
        return err(
          ilspyConfigurationError(
            `REA_ILSPY_MCP_CONFIG must select a regular JSON file: ${path}`,
            cause,
          ),
        );
      if (cause instanceof AnalysisCancelledError) throw cause;
      const cancellation = regularFileCancellation(cause);
      if (cancellation !== undefined)
        throw new AnalysisCancelledError("ilspy:registration", {
          cause: cancellation.reason,
        });
      return err(
        ilspyConfigurationError(
          `Cannot read ILSpy MCP registration ${path}; provide a readable JSON configuration.`,
          cause,
        ),
      );
    }
  })();
