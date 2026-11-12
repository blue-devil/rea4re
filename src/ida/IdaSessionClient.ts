import type { AppConfig } from "../config/types.js";
import { z } from "zod";
import { ABORTED, waitForAbortable } from "../process/AbortablePromise.js";
import {
  createAnalysisExecution,
  type AnalysisClient,
  type AnalysisOperation,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisProtocolError,
  AnalysisOutputError,
  AnalysisInputError,
  AnalysisTimeoutError,
  AnalysisResourceConstraintError,
} from "../domain/analysisErrorCore.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { AnalysisProfileCommitment } from "../domain/analysisProfile.js";
import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";
import { err, ok, type Result } from "../domain/result.js";
import type { IdaConfiguration } from "./IdaConfiguration.js";
import { createIdaDiagnosticRedactor } from "./IdaDiagnosticRedactor.js";
import type { IdaMcpConnection } from "./IdaMcpConnection.js";
import { IdaOperationRunner } from "./IdaOperationRunner.js";
import {
  IDA_LIMITATIONS,
  type IdaOperation,
} from "./IdaProviderCapabilities.js";
import {
  IDA_OPERATIONS,
  IDA_PROVIDER_IDENTITY,
} from "./IdaProviderMetadata.js";
import {
  closeDatabaseResultSchema,
  databaseInstancesSchema,
  parseExecutePythonResult,
  HEXRAYS_IDA_TOOLS,
  identityResultSchema,
  idaHexraysCode,
  openDatabaseResultSchema,
  type DatabaseInstance,
} from "./IdaHexraysProtocol.js";
import {
  idaFileDigest,
  IdaWorkspace,
  sameIdaHostPath,
} from "./IdaWorkspace.js";
import { parseIdaInput } from "./IdaInput.js";
import { createEvidence } from "../domain/evidence.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import {
  artifactFilePrimaryFacts,
  artifactFileCancellationCause,
  bindArtifactFileCleanup,
} from "../artifacts/ArtifactFileOperation.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import {
  analysisClientFailureContext,
  analysisClientFailureForOperation,
} from "../providers/AnalysisClientFailure.js";

const operationSet: ReadonlySet<string> = new Set(IDA_OPERATIONS);

const isIdaOperation = (operation: string): operation is IdaOperation =>
  operationSet.has(operation);
const wasCancelled = (options: ExecutionOptions | undefined): boolean =>
  options?.signal?.aborted === true;
const timeoutSeconds = (timeoutMs: number): number =>
  Math.max(1, Math.floor(timeoutMs / 1000));

interface IdaOperationFailureContext {
  runner: IdaOperationRunner | undefined;
  metadataBefore: JsonValue | undefined;
  metadataAfter: JsonValue | undefined;
  postOperationIdentityCheck: "not_attempted" | "started" | "verified";
  parameters: Readonly<Record<string, JsonValue>>;
}

/** Upstream database instances of inventory rows, omitting unreported ones. */
interface UpstreamInstance {
  readonly instance_id: string | null;
  readonly backend: DatabaseInstance["backend"];
  readonly status: DatabaseInstance["status"];
  /** Last inventoried input binding; null until upstream reports it. */
  readonly path: string | null;
  readonly error: string | null;
}

/** A failed cleanup retains its private workspace and reports the remaining resource. */
class IdaCleanupError extends ProviderAdapterError {
  constructor(
    path: string,
    cause: unknown,
    instances?: readonly UpstreamInstance[],
  ) {
    super("ida", "close", {
      cause,
      cleanup: {
        reason:
          "IDA connection or private workspace cleanup remains unverified.",
        resources: [path],
      },
      capturedOutput:
        cause instanceof AnalysisError ? cause.capturedOutput : undefined,
      diagnostics: {
        ...(cause instanceof AnalysisError ? cause.diagnostics : undefined),
        reason:
          "IDA cleanup could not be verified; the remaining connection or private workspace is retained for retry.",
        failure_reason:
          cause instanceof AnalysisError
            ? (cause.diagnostics?.reason ?? cause.message)
            : cause instanceof Error
              ? cause.message
              : String(cause),
        workspace: path,
        ...(instances === undefined
          ? {}
          : {
              upstream_instances: {
                state: "unverified",
                instances: instances.map(
                  ({ instance_id, backend, status, path, error }) => ({
                    instance_id,
                    backend,
                    status,
                    path,
                    error,
                  }),
                ),
                reason:
                  "Release of upstream database instances matching the requested instance ID or private input was not confirmed; path preserves the last observed binding and is null when no inventory has reported it. An instance with status available, attached or current blocks release; unavailable rows carry their upstream error and are reported without blocking. A headless worker may keep running until it finishes and reaches its idle timeout; exiting REA does not stop it. A gui instance belongs to an IDA instance REA does not control. A null instance_id means upstream reported none; an empty list means the requested instance's close was confirmed but no inventory has identified any remaining instance.",
              },
            }),
      },
    });
  }
}

/** Format-owner facts for a refused database/target binding, before any operation replies exist. */
class IdaIdentityRefusal extends AnalysisProtocolError {
  constructor(
    readonly reason: string,
    readonly recovery: string,
    check: string,
  ) {
    super(reason, { diagnostics: { identity_check: check, reason, recovery } });
  }
}

/** Serial read-only session over one official ida-mcp database instance. */
export class IdaSessionClient implements AnalysisClient {
  #tail: Promise<void> = Promise.resolve();
  #startup: Promise<void> | undefined;
  #closed = false;
  #closing = false;
  #closePromise: Promise<Result<null, AnalysisError>> | undefined;
  #closeFailures: WeakRef<IdaCleanupError>[] = [];
  #workspace: IdaWorkspace | undefined;
  #instanceId: string | undefined;
  #instanceCloseCompleted = false;
  #openAttempted = false;
  #openCompleted = false;
  #ready = false;
  #blockingInstances: readonly UpstreamInstance[] | undefined;
  #initialIdentity: string | undefined;
  #metadata: JsonValue = null;
  #lifecycle: JsonValue[] = [];

  constructor(
    private readonly config: IdaConfiguration,
    private readonly target: BinaryTarget,
    private readonly connection: IdaMcpConnection,
    private readonly profile?: AnalysisProfileCommitment,
    private readonly regexSettings?: Pick<
      AppConfig,
      "regexMatchingDeadline" | "regexWorkerHeapRequest"
    >,
  ) {}

  execute(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    options?: ExecutionOptions,
  ) {
    const call = this.#tail.then(() =>
      this.#execute(operation, parameters, options),
    );
    this.#tail = call.then(
      () => undefined,
      () => undefined,
    );
    return call;
  }

  async executeIfReady(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    options?: ExecutionOptions,
  ) {
    if (!this.#ready || this.#closed || this.#closing)
      return Promise.resolve(undefined);
    const call = this.#tail.then(() => {
      if (!this.#ready || this.#closed || this.#closing) return undefined;
      if (wasCancelled(options))
        return err(
          new AnalysisCancelledError(operation, {
            cause: options?.signal?.reason,
          }),
        );
      return this.#execute(operation, parameters, options, true);
    });
    this.#tail = call.then(
      () => undefined,
      () => undefined,
    );
    const result = await waitForAbortable(call, options?.signal);
    return result === ABORTED
      ? err(
          new AnalysisCancelledError(operation, {
            cause: options?.signal?.reason,
          }),
        )
      : result;
  }

  async #execute(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    options?: ExecutionOptions,
    readyOnly = false,
  ) {
    if (this.#closed || this.#closing)
      return err(
        new AnalysisProtocolError(
          "IDA session is closing or closed; reopen the target.",
        ),
      );
    if (wasCancelled(options))
      return err(
        new AnalysisCancelledError(operation, {
          cause: options?.signal?.reason,
        }),
      );
    if (operation !== "health" && !isIdaOperation(operation))
      return err(
        new AnalysisCapabilityUnavailableError(
          "ida",
          operation,
          "This integration admits read-only analysis operations only.",
        ),
      );
    if (operation !== "health") {
      const parsed = parseIdaInput(operation, parameters);
      if (!parsed.ok) return parsed;
      parameters = parsed.value;
    }
    const document = parameters.document;
    if (
      document !== undefined &&
      (typeof document !== "string" ||
        (!sameIdaHostPath(document, this.target.path) &&
          (this.target.sourcePath === undefined ||
            !sameIdaHostPath(document, this.target.sourcePath))))
    )
      return err(
        new AnalysisInputError(operation, undefined, [
          {
            path: ["document"],
            reason: "invalid_value",
            expected: this.target.path,
            message:
              "IDA document must be the REA-bound target; omit document or use its admitted path.",
          },
        ]),
      );
    const failureContext: IdaOperationFailureContext = {
      runner: undefined,
      metadataBefore: undefined,
      metadataAfter: undefined,
      postOperationIdentityCheck: "not_attempted",
      parameters,
    };
    try {
      if (!readyOnly) await this.#start(operation);
      const before = await this.#observe(options);
      failureContext.metadataBefore = before;
      if (wasCancelled(options))
        throw new AnalysisCancelledError(operation, {
          cause: options?.signal?.reason,
        });
      if (operation === "health") return this.#health(before);
      if (!isIdaOperation(operation))
        throw new AnalysisProtocolError(
          "IDA operation changed after validation.",
        );
      const runner = this.#runner(options);
      failureContext.runner = runner;
      const result = await runner.run(operation, parameters);
      if (wasCancelled(options))
        throw new AnalysisCancelledError(operation, {
          cause: options?.signal?.reason,
        });
      failureContext.postOperationIdentityCheck = "started";
      const after = await this.#observe(
        options,
        (observed) => (failureContext.metadataAfter = observed),
      );
      failureContext.postOperationIdentityCheck = "verified";
      if (wasCancelled(options))
        throw new AnalysisCancelledError(operation, {
          cause: options?.signal?.reason,
        });
      return ok(
        createAnalysisExecution(result, IDA_PROVIDER_IDENTITY, {
          rawResult: {
            upstream: this.connection.serverInfo(),
            metadata_before: before,
            metadata_after: after,
            observations: jsonValueSchema.parse(runner.raw),
          },
          limitations: [...IDA_LIMITATIONS, ...runner.limitations],
          ...(runner.relationshipCoverage === undefined
            ? {}
            : { relationshipCoverage: runner.relationshipCoverage }),
          locations: [
            { kind: "artifact-path", path: this.target.path },
            ...runner.locations,
          ],
          ...(this.profile === undefined
            ? {}
            : { analysisProfile: this.profile }),
        }),
      );
    } catch (cause: unknown) {
      return this.#failure(operation, cause, options, failureContext);
    }
  }

  #runner(options: ExecutionOptions | undefined): IdaOperationRunner {
    return new IdaOperationRunner(this.connection, this.#instanceId, {
      regexMatchingDeadline: this.regexSettings?.regexMatchingDeadline,
      regexWorkerHeapRequest: this.regexSettings?.regexWorkerHeapRequest,
      signal: options?.signal,
      selectorOrigin: options?.selectorOrigin,
      admittedDocument: this.target.path,
      timeoutSeconds: timeoutSeconds(this.config.timeoutMs),
    });
  }

  #health(metadata: JsonValue) {
    return ok(
      createAnalysisExecution(
        {
          ready: true,
          mode: this.config.mode,
          instance: this.#instanceId ?? null,
          upstream: this.connection.serverInfo(),
          metadata,
          lifecycle: this.#lifecycle,
        },
        IDA_PROVIDER_IDENTITY,
        {
          limitations: IDA_LIMITATIONS,
          ...(this.profile === undefined
            ? {}
            : { analysisProfile: this.profile }),
        },
      ),
    );
  }

  #failure(
    operation: string,
    cause: unknown,
    options: ExecutionOptions | undefined,
    context: IdaOperationFailureContext,
  ) {
    const artifactFailure =
      cause instanceof ArtifactReaderFailure ? cause : undefined;
    // The validated registration owns the exact endpoint spelling. Apply the
    // same credential exclusions used for upstream transport diagnostics.
    const endpoint =
      artifactFailure === undefined && "url" in this.config
        ? {
            endpoint: createIdaDiagnosticRedactor(this.config).url(
              this.config.url,
            ),
          }
        : {};
    if (artifactFailure !== undefined)
      cause = artifactFilePrimaryFacts(artifactFailure).cause;
    let failure: AnalysisError;
    if (cause instanceof IdaIdentityRefusal) {
      failure = new AnalysisOutputError(operation, cause.reason, {
        cause,
        userMessage: cause.reason,
        remediationAction: cause.recovery,
        diagnostics: cause.diagnostics,
      });
    } else if (artifactFailure?.reason === "cancelled") {
      failure = new AnalysisCancelledError(operation, {
        cause: artifactFileCancellationCause(artifactFailure),
      });
    } else if (cause instanceof AnalysisCancelledError) {
      failure = new AnalysisCancelledError(operation, {
        cause:
          cause.cause === undefined ? options?.signal?.reason : cause.cause,
        capturedOutput: cause.capturedOutput,
        diagnostics: { ...cause.diagnostics, ...endpoint },
        partialObservation: cause.partialObservation,
        cleanup:
          cause.cleanup ??
          (cause.cleanupIncomplete
            ? { reason: cause.message, resources: cause.cleanupResources }
            : undefined),
      })
        .bindCleanupDependencies([cause])
        .bindCleanupResourceOwner(cause);
    } else if (
      (cause instanceof AnalysisTimeoutError ||
        cause instanceof AnalysisResourceConstraintError) &&
      cause.operation === operation &&
      cause.diagnostics?.startup_operation !== undefined
    ) {
      // #start has already attributed this failure and its endpoint; wrapping
      // it again would replace the original producer cause with an intermediate.
      failure = cause;
    } else if (
      cause instanceof AnalysisTimeoutError ||
      cause instanceof AnalysisResourceConstraintError
    ) {
      failure = analysisClientFailureForOperation(
        cause,
        "ida",
        operation,
        endpoint,
      ).bindCleanupResourceOwner(cause);
    } else if (
      cause instanceof ProviderAdapterError &&
      cause.operation === "transport"
    )
      failure = analysisClientFailureForOperation(cause, "ida", operation, {
        ...endpoint,
        recovery:
          "Check the configured upstream MCP registration and selected target; see docs/providers/ida-provider.md.",
      }).bindCleanupResourceOwner(cause);
    else if (cause instanceof AnalysisProtocolError && "endpoint" in endpoint)
      failure = new AnalysisProtocolError(cause.message, {
        ...analysisClientFailureContext(cause, "ida", operation),
        diagnostics: { ...cause.diagnostics, ...endpoint },
      }).bindCleanupResourceOwner(cause);
    else if (cause instanceof AnalysisError) failure = cause;
    else if (cause instanceof z.ZodError)
      failure = new AnalysisOutputError(
        operation,
        `IDA MCP returned malformed or unsupported producer data: ${cause.issues.map((issue) => `${issue.path.join(".") || "$"}: ${issue.message}`).join("; ")}`,
        { cause },
      );
    else
      failure = new ProviderAdapterError("ida", operation, {
        cause,
        diagnostics: {
          ...endpoint,
          reason:
            cause instanceof Error ? cause.message : "Unknown upstream failure",
          recovery:
            "Check the configured upstream MCP registration and selected target; see docs/providers/ida-provider.md.",
        },
      });
    if (artifactFailure?.cleanup !== undefined) {
      const cleanup = new ProviderCleanupError(
        "ida",
        artifactFailure.cleanup.resources,
        { reason: artifactFailure.cleanup.reason },
        { operation, cause: artifactFailure },
      );
      bindArtifactFileCleanup(artifactFailure, cleanup);
      failure = analysisErrorWithCleanupFailure(
        failure,
        cleanup,
        operation,
      ).bindCleanupDependencies([cleanup]);
    }
    // Only operation calls made after target identity/readiness validation can
    // become partial Evidence. The failing call itself is absent from `raw`
    // when its transport or MCP envelope could not be decoded.
    const { runner, metadataBefore, metadataAfter } = context;
    if (
      runner !== undefined &&
      runner.raw.length > 0 &&
      metadataBefore !== undefined
    ) {
      const observations = jsonValueSchema.parse(runner.raw);
      const upstream = this.connection.serverInfo();
      const binding =
        context.postOperationIdentityCheck !== "verified"
          ? {
              status: "not_verified",
              reason:
                cause instanceof Error
                  ? cause.message
                  : "Post-operation target identity was not observed.",
            }
          : { status: "verified" };
      failure.retainPartialObservation(
        createEvidence(this.target, IDA_PROVIDER_IDENTITY, {
          predicateType: "analysis-observation",
          operation,
          parameters: context.parameters,
          result: {
            status: "partial",
            failed_operation: operation,
            observations,
            metadata_before: metadataBefore,
            target_binding: binding,
            ...(metadataAfter === undefined
              ? {}
              : { metadata_after: metadataAfter }),
          },
          rawResult: {
            upstream,
            observations,
            metadata_before: metadataBefore,
            ...(metadataAfter === undefined
              ? {}
              : { metadata_after: metadataAfter }),
            post_operation_identity_check: context.postOperationIdentityCheck,
          },
          confidence: "observed",
          authority: "external-service",
          limitations: [
            ...IDA_LIMITATIONS,
            ...runner.limitations,
            "The requested IDA operation failed after these completed upstream replies; the partial Evidence does not establish a complete result.",
            "Replies are bound to the selected target only by the pre-operation identity check unless post_operation_identity_check is verified.",
          ],
          locations: [
            { kind: "artifact-path", path: this.target.path },
            ...runner.locations,
          ],
          ...(this.profile === undefined
            ? {}
            : { analysisProfile: this.profile }),
        }),
      );
    }
    return err(failure);
  }

  async #start(operation: string): Promise<void> {
    this.#startup ??= this.#initialize();
    try {
      await this.#startup;
    } catch (cause: unknown) {
      if (
        !(cause instanceof AnalysisTimeoutError) &&
        !(cause instanceof AnalysisResourceConstraintError) &&
        !(cause instanceof ProviderAdapterError)
      )
        throw cause;
      // Transport adapters already receive caller attribution in #failure.
      if (
        cause instanceof ProviderAdapterError &&
        cause.operation === "transport"
      )
        throw cause;
      // Startup is shared, but each accepted operation owns its attribution.
      // The shared boundary preserves typed outcome and cleanup facts without
      // mutating the cached startup failure.
      throw analysisClientFailureForOperation(cause, "ida", operation, {
        startup_operation: cause.operation,
        ...("url" in this.config
          ? {
              endpoint: createIdaDiagnosticRedactor(this.config).url(
                this.config.url,
              ),
            }
          : {}),
      }).bindCleanupResourceOwner(cause);
    }
  }

  async #initialize(): Promise<void> {
    const tools = new Set(await this.connection.connect());
    const missing = HEXRAYS_IDA_TOOLS.filter((name) => !tools.has(name));
    if (missing.length > 0) {
      const summary = `IDA MCP is missing required official ida-mcp tools: ${missing.join(", ")}. See docs/providers/ida-provider.md.`;
      // The caller cannot act on a profile mismatch it never sees, so the
      // missing names travel as adapter diagnostics rather than a bare message.
      throw new ProviderAdapterError("ida", "initialize", {
        userMessage: summary,
        diagnostics: {
          reason: summary,
          mode: this.config.mode,
          expected_profile: "hexrays",
          missing_tools: [...missing],
          recovery:
            "Install the official HexRaysSA/ida-mcp server; see docs/providers/ida-provider.md.",
        },
      });
    }
    if (this.config.mode === "headless") {
      this.#workspace = await IdaWorkspace.allocate(
        this.target,
        this.config.workspaceRoot,
      );
      await this.#workspace.copyInput();
      this.#openAttempted = true;
      const raw = await this.connection.call("open_database", {
        path: this.#workspace.inputPath,
        set_current: true,
      });
      this.#openCompleted = true;
      this.#lifecycle.push(raw);
      const opened = openDatabaseResultSchema.parse(raw);
      if (opened.backend === "gui")
        throw new IdaIdentityRefusal(
          "IDA opened the private input in a GUI instance instead of a headless worker.",
          "Configure headless mode against an ida-mcp server that runs headless workers, or open the original target in the IDA GUI and use attached mode.",
          "headless_backend",
        );
      this.#instanceId = opened.instance_id;
      const inventory = databaseInstancesSchema.parse(
        await this.connection.call("list_databases", {}),
      );
      this.#lifecycle.push(jsonValueSchema.parse(inventory));
      const workspace = this.#workspace;
      this.#recordBlockingInstances(
        inventory.instances.filter(
          (entry) =>
            entry.status !== "unavailable" &&
            sameIdaHostPath(entry.path, workspace.inputPath),
        ),
      );
      const entry = inventory.instances.find(
        ({ instance_id }) => instance_id === opened.instance_id,
      );
      if (
        entry === undefined ||
        entry.status === "unavailable" ||
        entry.backend !== opened.backend ||
        !sameIdaHostPath(entry.path, workspace.inputPath)
      )
        throw new IdaIdentityRefusal(
          "IDA did not report the opened headless instance in its database inventory.",
          "Use an ida-mcp server that lists opened databases. Confirm retained cleanup before reopening the target.",
          "instance_inventory",
        );
    } else {
      const raw = await this.connection.call("open_database", {
        path: this.target.path,
        set_current: true,
      });
      this.#openCompleted = true;
      this.#openAttempted = true;
      this.#lifecycle.push(raw);
      const opened = openDatabaseResultSchema.parse(raw);
      if (opened.backend !== "gui")
        throw new IdaIdentityRefusal(
          `The ida-mcp server opened ${this.target.path} in a headless worker instead of attaching to the IDA GUI.`,
          "Open the selected target in the IDA GUI, or configure headless mode and reopen the target through REA.",
          "attached_backend",
        );
      this.#instanceId = opened.instance_id;
    }
    this.#ready = true;
  }

  async #observe(
    options?: ExecutionOptions,
    onObserved?: (metadata: JsonValue) => void,
  ): Promise<JsonValue> {
    if (this.#instanceId === undefined)
      throw new IdaIdentityRefusal(
        "IDA session has no database instance binding.",
        "Close the REA analysis session and reopen the selected target through the configured ida-mcp server.",
        "instance_binding",
      );
    const args = {
      code: idaHexraysCode.identity(),
      instance_id: this.#instanceId,
      timeout: timeoutSeconds(this.config.timeoutMs),
    };
    const raw = parseExecutePythonResult(
      await this.connection.call("execute_python", args, {
        signal: options?.signal,
      }),
    );
    const metadata = identityResultSchema.parse(raw);
    const observed: JsonValue = jsonValueSchema.parse(metadata);
    this.#metadata = observed;
    onObserved?.(observed);
    let identity: string;
    if (this.config.mode === "attached") {
      if (
        metadata.sha256 === null ||
        metadata.sha256.toLowerCase() !== this.target.sha256.toLowerCase()
      )
        throw new IdaIdentityRefusal(
          `The attached IDA input SHA-256 does not match the selected target ${this.target.path}; open that target in IDA or use headless mode.`,
          "Open the selected original input in IDA, or configure headless mode and reopen the target through REA.",
          "attached_sha256",
        );
      identity = JSON.stringify([
        metadata.path,
        metadata.sha256.toLowerCase(),
        metadata.base,
      ]);
    } else {
      if (this.#workspace === undefined)
        throw new IdaIdentityRefusal(
          "IDA headless session has no private workspace binding.",
          "Close the REA analysis session, confirm private-worker cleanup, then reopen the selected original target.",
          "headless_input",
        );
      if (
        !sameIdaHostPath(metadata.path, this.#workspace.inputPath) ||
        (await idaFileDigest(this.#workspace.inputPath)) !==
          this.#workspace.inputSha256
      )
        throw new IdaIdentityRefusal(
          "IDA headless input identity changed after target admission.",
          "Close the REA analysis session, confirm private-worker cleanup, then reopen the selected original target.",
          "headless_input",
        );
      identity = JSON.stringify([
        this.#instanceId,
        metadata.path,
        metadata.base,
      ]);
    }
    if (
      this.#initialIdentity !== undefined &&
      identity !== this.#initialIdentity
    )
      throw new IdaIdentityRefusal(
        "The IDA target or image base changed during the REA session; reopen the target.",
        "Close the REA analysis session and reopen the selected target after confirming the intended input and image base in IDA.",
        "session_identity",
      );
    this.#initialIdentity = identity;
    return this.#metadata;
  }

  async close(): Promise<Result<null, AnalysisError>> {
    if (this.#closePromise !== undefined) return this.#closePromise;
    const closing = this.#closeOnce();
    const shared = closing.finally(() => {
      if (this.#closePromise === shared) this.#closePromise = undefined;
    });
    this.#closePromise = shared;
    return shared;
  }

  /**
   * Upstream instances whose release cleanup has not confirmed: the entries
   * the latest successful inventory found blocking release; else the
   * requested headless instance until its close is confirmed, and then none
   * known.
   */
  #unreleasedInstances(): readonly UpstreamInstance[] | undefined {
    if (this.#blockingInstances !== undefined) return this.#blockingInstances;
    if (!this.#openAttempted || this.config.mode !== "headless")
      return undefined;
    return this.#instanceCloseCompleted
      ? []
      : [
          {
            instance_id: this.#instanceId ?? null,
            backend: "idalib",
            status: "attached",
            path: this.#workspace?.inputPath ?? null,
            error: null,
          },
        ];
  }

  /** Drop an instance whose release upstream confirmed, keeping other blockers. */
  #forgetReleasedInstance(instanceId: string): void {
    const remaining = this.#blockingInstances?.filter(
      ({ instance_id }) => instance_id !== instanceId,
    );
    this.#blockingInstances =
      remaining !== undefined && remaining.length > 0 ? remaining : undefined;
  }

  /** Replace blocker evidence from a successful inventory; true when blocked. */
  #recordBlockingInstances(entries: readonly DatabaseInstance[]): boolean {
    const blocking = entries.filter(({ status }) => status !== "unavailable");
    this.#blockingInstances =
      blocking.length > 0
        ? blocking.map(({ instance_id, backend, status, path, error }) => ({
            instance_id: instance_id ?? null,
            backend,
            status,
            path,
            error: error ?? null,
          }))
        : undefined;
    return blocking.length > 0;
  }

  /**
   * Close one instance. A `closed: false` reply is not itself a failure: the
   * instance may already have been reaped. Release is proven afterwards by
   * the inventory absence check, so only transport and malformed replies fail
   * here.
   */
  async #closeInstance(instanceId: string): Promise<void> {
    closeDatabaseResultSchema.parse(
      await this.connection.call("close_database", { instance_id: instanceId }),
    );
  }

  async #closeOnce(): Promise<Result<null, AnalysisError>> {
    this.#closing = true;
    await this.#tail;
    if (this.#closed) return ok(null);
    try {
      if (this.config.mode === "headless" && this.#openAttempted) {
        if (this.#instanceId === undefined) {
          // A completed open whose reply could not be decoded may still own a
          // worker: only an inventory without a live private-input instance
          // proves otherwise. An unavailable inventory keeps the workspace.
          const inventory = databaseInstancesSchema.parse(
            await this.connection.call("list_databases", {}),
          );
          const workspace = this.#workspace;
          if (
            workspace !== undefined &&
            this.#recordBlockingInstances(
              inventory.instances.filter(
                (entry) =>
                  entry.status !== "unavailable" &&
                  sameIdaHostPath(entry.path, workspace.inputPath),
              ),
            )
          )
            throw new AnalysisProtocolError(
              "A live instance still matches the private input without a verified instance binding; the workspace was retained.",
            );
          if (this.#openCompleted)
            throw new AnalysisProtocolError(
              "IDA open returned without a verified instance binding. An empty inventory does not prove the worker exited; the private workspace was retained.",
            );
        } else {
          if (!this.#instanceCloseCompleted) {
            await this.#closeInstance(this.#instanceId);
            this.#instanceCloseCompleted = true;
            this.#forgetReleasedInstance(this.#instanceId);
          }
          const inventory = databaseInstancesSchema.parse(
            await this.connection.call("list_databases", {}),
          );
          const instanceId = this.#instanceId;
          if (
            this.#recordBlockingInstances(
              inventory.instances.filter(
                (entry) =>
                  entry.status !== "unavailable" &&
                  (entry.instance_id === instanceId ||
                    (this.#workspace !== undefined &&
                      sameIdaHostPath(entry.path, this.#workspace.inputPath))),
              ),
            )
          )
            throw new AnalysisProtocolError(
              "IDA worker remains registered after close.",
            );
          this.#instanceId = undefined;
        }
        if (!this.#openCompleted)
          throw new AnalysisProtocolError(
            "IDA database open did not return a completed response. Worker inventory cannot prove that the request has stopped; the private workspace was retained.",
          );
        this.#openAttempted = false;
      } else if (this.#instanceId !== undefined) {
        // Attached mode: release REA's lease only. The GUI database stays open
        // (upstream contract), and save_database is never called.
        await this.#closeInstance(this.#instanceId);
        this.#instanceId = undefined;
      }
      await this.connection.close();
      await this.#workspace?.remove();
      this.#closed = true;
      for (const failure of this.#closeFailures)
        failure.deref()?.resolveCleanup();
      this.#closeFailures = [];
      return ok(null);
    } catch (cause: unknown) {
      this.connection.detach();
      const path = this.#workspace?.directory ?? "IDA MCP connection";
      const failure = new IdaCleanupError(
        path,
        cause,
        this.#unreleasedInstances(),
      );
      const client = this;
      failure.bindCleanupResourceOwner({
        get cleanupResources() {
          return client.#closed ? [] : [path];
        },
      });
      this.#closeFailures = [
        ...this.#closeFailures.filter(
          (reference) => reference.deref() !== undefined,
        ),
        new WeakRef(failure),
      ];
      return err(failure);
    }
  }
}
