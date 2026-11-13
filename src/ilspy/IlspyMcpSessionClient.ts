import type { JsonValue } from "../domain/jsonValue.js";
import { err, ok, type Result } from "../domain/result.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import type { IlspyMcpConnection } from "./IlspyMcpConnection.js";

/** The live tools/list catalog is the only compatibility check; no version logic. */
export const REQUIRED_ILSPY_TOOLS = [
  "decompile_method",
  "disassemble_method",
] as const;

/** open() failed: transport failure at startup or the live catalog lacks required tools. */
export class IlspyStartupError extends ProviderAdapterError {
  constructor(
    message: string,
    options: {
      readonly cause?: unknown;
      readonly registration?: string;
      readonly missingTools?: readonly string[];
    } = {},
  ) {
    super("ilspy", "open", {
      ...(options.cause === undefined ? {} : { cause: options.cause }),
      diagnostics: {
        reason: message,
        ...(options.registration === undefined
          ? {}
          : { registration: options.registration }),
        ...(options.missingTools === undefined ||
        options.missingTools.length === 0
          ? {}
          : { missing_tools: [...options.missingTools] }),
      },
    });
    this.message = message;
  }
}

/** callTool() was refused before any upstream request was sent. */
export class IlspyCallError extends ProviderAdapterError {
  constructor(message: string, registration: string) {
    super("ilspy", "call", {
      diagnostics: { reason: message, registration },
    });
    this.message = message;
  }
}

/** close() could not prove the spawned child terminated; ownership is retained. */
export class IlspyCleanupError extends ProviderCleanupError {
  constructor(
    cleanupResources: readonly string[],
    cause: unknown,
    registration: string,
  ) {
    super(
      "ilspy",
      cleanupResources,
      {
        reason:
          "ILSpy MCP child termination could not be verified; the retained process is reported for retry.",
        registration,
      },
      { cause, operation: "ilspy_mcp_close" },
    );
  }
}

/** Serial session over one spawned ILSpy-MCP stdio child, catalog-admitted at open. */
export class IlspyMcpSessionClient {
  #tail: Promise<unknown> = Promise.resolve();
  #openPromise:
    | Promise<
        Result<
          { serverVersion: string | null; tools: string[] },
          IlspyStartupError
        >
      >
    | undefined;
  #catalog: ReadonlySet<string> | undefined;
  #closed = false;

  constructor(
    private readonly connection: IlspyMcpConnection,
    private readonly registrationSummary: string,
  ) {}

  /** Connect once and admit the live tools/list catalog; never retries. */
  open(): Promise<
    Result<{ serverVersion: string | null; tools: string[] }, IlspyStartupError>
  > {
    this.#openPromise ??= this.#open();
    return this.#openPromise;
  }

  async #open() {
    let tools: readonly string[];
    try {
      tools = await this.connection.connect();
    } catch (cause: unknown) {
      return err(
        new IlspyStartupError(
          "ILSpy MCP startup failed; the tools/list catalog could not be read.",
          { cause, registration: this.registrationSummary },
        ),
      );
    }
    const missing = REQUIRED_ILSPY_TOOLS.filter(
      (name) => !tools.includes(name),
    );
    if (missing.length > 0)
      return err(
        new IlspyStartupError(
          "ILSpy MCP live catalog does not admit the required tools; failing closed before any member call.",
          { registration: this.registrationSummary, missingTools: missing },
        ),
      );
    this.#catalog = new Set(tools);
    const info = this.connection.serverInfo();
    const serverVersion =
      typeof info === "object" &&
      info !== null &&
      "version" in info &&
      typeof info.version === "string"
        ? info.version
        : null;
    return ok({ serverVersion, tools: [...tools] });
  }

  /** Admit only catalog names; calls serialize (one in-flight call at a time). */
  callTool(
    name: string,
    args: unknown,
  ): Promise<Result<unknown, IlspyCallError>> {
    const call = this.#tail.then(() => this.#callTool(name, args));
    this.#tail = call.then(
      () => undefined,
      () => undefined,
    );
    return call;
  }

  async #callTool(
    name: string,
    args: unknown,
  ): Promise<Result<unknown, IlspyCallError>> {
    if (this.#catalog === undefined)
      return err(
        new IlspyCallError(
          "ILSpy MCP session is not open; no tool call is admitted.",
          this.registrationSummary,
        ),
      );
    if (!this.#catalog.has(name))
      return err(
        new IlspyCallError(
          `ILSpy MCP tool ${name} is not in the admitted catalog; failing closed.`,
          this.registrationSummary,
        ),
      );
    return ok(
      await this.connection.call(
        name,
        args as Readonly<Record<string, JsonValue>>,
      ),
    );
  }

  /** Terminate the spawned child and verify; a second close is a no-op. */
  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    try {
      await this.connection.close();
    } catch (cause: unknown) {
      // Retain ownership: unref so the surviving child cannot hold the host open.
      this.connection.detach();
      throw new IlspyCleanupError(
        ["ILSpy MCP stdio child process (termination unverified)"],
        cause,
        this.registrationSummary,
      );
    }
  }
}
