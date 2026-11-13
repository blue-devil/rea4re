import { StructuredContentMcpClient } from "../providers/StructuredContentMcpClient.js";
import {
  mcpToolResultSchema,
  mcpTextBlocks,
  parseMcpJsonOrText,
} from "../providers/McpToolResult.js";
import {
  DEFAULT_INHERITED_ENV_VARS,
  StdioClientTransport,
} from "@modelcontextprotocol/client/stdio";
import type { Stream } from "node:stream";
import { ChildProcess } from "node:child_process";
import { Socket } from "node:net";
import {
  jsonObjectSchema,
  jsonValueSchema,
  type JsonValue,
} from "../domain/jsonValue.js";
import {
  ilspyConfigurationError,
  type IlspyMcpRegistration,
} from "./IlspyMcpConfiguration.js";
import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
/** Drain piped child stderr so server logs cannot backpressure-block the child. */
export const drainIlspyStderr = (stream: Stream | null | undefined): void => {
  stream?.on("data", () => {});
};

/** Largest admitted stdio reply; the SDK default would fail large decompile bodies. */
const ILSPY_STDIO_MAX_MESSAGE_BYTES = 64 * 1024 * 1024;

/** Injectable MCP boundary for the ILSpy provider and its tests. */
export interface IlspyMcpConnection {
  connect(): Promise<readonly string[]>;
  call(
    name: string,
    args: Readonly<Record<string, JsonValue>>,
    options?: {
      readonly timeoutMs?: number | undefined;
      readonly signal?: AbortSignal | undefined;
    },
  ): Promise<JsonValue>;
  serverInfo(): JsonValue;
  close(): Promise<void>;
  /** Unref the retained child after failed cleanup so it cannot hold the host open. */
  detach(): void;
}

/** Decode a structured or single-text MCP tool result without dropping producer dictionaries. */
const decodeIlspyToolResult = (input: unknown): JsonValue => {
  const result = mcpToolResultSchema.parse(input);
  if (result.isError === true)
    throw new Error("ILSpy MCP tool failed; no result was returned.");
  if (result.structuredContent !== undefined)
    return jsonObjectSchema.parse(result.structuredContent);
  const blocks = mcpTextBlocks(result.content);
  if (blocks.length !== 1)
    throw new Error(
      "ILSpy MCP omitted a single structured or text result; unsupported content cannot establish an empty observation.",
    );
  return parseMcpJsonOrText(blocks[0]!);
};

/** Create the standard SDK connection to one admitted stdio registration. */
export const createIlspyMcpConnection = (
  registration: IlspyMcpRegistration,
  timeoutMs: number,
  environment: Readonly<NodeJS.ProcessEnv>,
): IlspyMcpConnection => {
  if (!("command" in registration))
    throw ilspyConfigurationError(
      "REA_ILSPY_MCP_CONFIG: phase one supports stdio registrations only; the HTTP registration is validated but refused.",
    );
  const client = new StructuredContentMcpClient({
    name: "rea-ilspy-provider",
    version: "1",
  });
  const transport = new StdioClientTransport({
    command: registration.command,
    args: registration.args,
    env: {
      // The SDK always merges ambient defaults; empty values suppress them.
      ...Object.fromEntries(DEFAULT_INHERITED_ENV_VARS.map((key) => [key, ""])),
      ...Object.fromEntries(
        Object.entries(snapshotEnvironment(environment)).filter(
          (entry): entry is [string, string] => entry[1] !== undefined,
        ),
      ),
      ...registration.env,
    },
    maxBufferSize: ILSPY_STDIO_MAX_MESSAGE_BYTES,
    stderr: "pipe",
  });
  return {
    async connect() {
      await client.connect(transport, { timeout: timeoutMs });
      // The piped stderr PassThrough is otherwise unread and blocks the child.
      drainIlspyStderr(transport.stderr);
      const catalog = await client.listTools(undefined, { timeout: timeoutMs });
      return catalog.tools.map(({ name }) => name);
    },
    async call(name, args, options) {
      const requestTimeoutMs = Math.min(
        timeoutMs,
        options?.timeoutMs ?? timeoutMs,
      );
      return decodeIlspyToolResult(
        await client.callTool(
          { name, arguments: args },
          { timeout: requestTimeoutMs },
        ),
      );
    },
    serverInfo() {
      // The declared version is an observation only, never a compatibility check.
      const info: unknown = client.getServerVersion();
      return jsonValueSchema.parse({
        version:
          typeof info === "object" &&
          info !== null &&
          "version" in info &&
          typeof info.version === "string"
            ? info.version
            : null,
      });
    },
    async close() {
      await client.close();
    },
    detach() {
      // The SDK exposes only the child's pid, not the handles it holds.
      const child: unknown = Reflect.get(transport, "_process");
      if (!(child instanceof ChildProcess)) return;
      child.unref();
      for (const stream of [child.stdin, child.stdout, child.stderr])
        if (stream instanceof Socket) stream.unref();
    },
  };
};
