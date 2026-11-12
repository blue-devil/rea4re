import { createHash } from "node:crypto";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { BinaryTarget } from "../../src/domain/binaryTargetTypes.js";
import type { JsonValue } from "../../src/domain/jsonValue.js";
import type { IdaMcpConnection } from "../../src/ida/IdaMcpConnection.js";
import { elf } from "../../src/domain/binaryTarget.fixture.js";

/** ELF machine numbers for the architectures a fixture target can declare. */
const ELF_MACHINE = { x86_64: 62, arm64: 183 } as const;

/** Create a test-owned executable and workspace parent without invoking an engine. */
export const createIdaTarget = async (
  architecture: keyof typeof ELF_MACHINE = "x86_64",
  availableArchitectures: readonly (keyof typeof ELF_MACHINE)[] = [
    architecture,
  ],
) => {
  const root = await mkdtemp(join(tmpdir(), "rea-ida-test-"));
  const path = join(root, "target.elf");
  const bytes = elf(2, 1, ELF_MACHINE[architecture]);
  await writeFile(path, bytes);
  const target: BinaryTarget = {
    path,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    kind: "executable",
    format: "elf",
    architecture,
    availableArchitectures: [...availableArchitectures],
  };
  return { root, target };
};

/** The official HexRaysSA/ida-mcp tool surface REA requires. */
export const hexraysIdaTools = [
  "open_database",
  "execute_python",
  "list_databases",
  "close_database",
] as const;

const hex = (value: number) => `0x${value.toString(16)}`;

interface FixtureFunction {
  readonly name: string;
  readonly start: number;
  readonly end: number;
  readonly instructions: readonly { ea: number; text: string }[];
}

/** Default in-memory ida-domain-like database the fixture serves. */
const defaultFunctions: FixtureFunction[] = [
  {
    name: "main",
    start: 0x1000,
    end: 0x1020,
    instructions: [{ ea: 0x1000, text: "ret" }],
  },
];

const defaultStrings = [{ address: 0x3000, length: 5, text: "a.b\nC" }];

const opMarker = /^# rea-op:(\w+)\n# rea-args:(\{.*\})\n([\s\S]*)$/u;

/** The operation tag REA embeds in every execute_python program. */
export const reaOpOf = (code: unknown): string => {
  if (typeof code !== "string") return "";
  return opMarker.exec(code)?.[1] ?? "";
};

/**
 * Stateful producer fixture at the real connection seam; no module mocking.
 * `execute_python` dispatches on the `# rea-op:<name>` marker the REA
 * builders embed, against a small in-memory ida-domain-like database.
 */
export class RecordingIdaMcp implements IdaMcpConnection {
  readonly calls: {
    name: string;
    args: Readonly<Record<string, JsonValue>>;
  }[] = [];
  connects = 0;
  closes = 0;
  detaches = 0;
  inputSha256: string;
  inputPath: string;
  architecture = "metapc";
  bitness = 64;
  imageBase = "0x1000";
  pseudocode = "int main(void) { return 42; }";
  /** Whether the private-input binding survives idaFileDigest re-verification. */
  workspaceIntact = true;
  failClose = false;
  database: string | undefined;
  beforeCall?: (
    name: string,
    args: Readonly<Record<string, JsonValue>>,
  ) => Promise<void>;
  overrideCall?: (
    name: string,
    args: Readonly<Record<string, JsonValue>>,
  ) => JsonValue | undefined;
  /** Tool names the fake server advertises; defaults to the required set. */
  tools?: readonly string[];
  /** Functions by name; the default database serves one `main` at 0x1000. */
  functions: FixtureFunction[] = defaultFunctions.map((fn) => ({ ...fn }));
  /** Names `db.names` yields in addition to function names. */
  names: { address: number; name: string }[] = [];
  stringsBuilt = 0;

  #instances = new Map<
    string,
    { path: string; backend: "gui" | "idalib"; status: string }
  >();
  #nextInstance = 0;

  constructor(
    readonly target: BinaryTarget,
    readonly mode: "attached" | "headless" = "attached",
  ) {
    this.inputSha256 = target.sha256;
    this.inputPath = target.path;
  }
  async connect() {
    this.connects += 1;
    return this.tools ?? hexraysIdaTools;
  }
  serverInfo() {
    return { name: "ida", version: "fixture-ida-mcp" };
  }
  async close() {
    this.closes += 1;
  }
  detach() {
    this.detaches += 1;
  }
  async call(
    name: string,
    args: Readonly<Record<string, JsonValue>>,
  ): Promise<JsonValue> {
    this.calls.push({ name, args: structuredClone(args) });
    await this.beforeCall?.(name, args);
    const overridden = this.overrideCall?.(name, args);
    if (overridden !== undefined) return overridden;
    if (["open_database", "list_databases", "close_database"].includes(name))
      return this.lifecycle(name, args);
    if (name === "execute_python") return this.execute(args);
    throw new Error(`Unimplemented producer tool ${name}`);
  }

  private lifecycle(
    name: string,
    args: Readonly<Record<string, JsonValue>>,
  ): JsonValue {
    switch (name) {
      case "open_database": {
        if (typeof args.path !== "string")
          throw new Error("Missing open_database path");
        this.inputPath = args.path;
        const instance_id = `fixture-instance-${++this.#nextInstance}`;
        this.#instances.set(instance_id, {
          path: args.path,
          backend: this.mode === "attached" ? "gui" : "idalib",
          status: "attached",
        });
        this.database = instance_id;
        return {
          instance_id,
          backend: this.mode === "attached" ? "gui" : "idalib",
          status: "attached",
          recovery: "none",
          log_path: `${args.path}.log`,
          mcp_id: null,
          hint: null,
        };
      }
      case "list_databases":
        return {
          instances: [...this.#instances].map(
            ([instance_id, { path, backend, status }]) => ({
              path,
              backend,
              status,
              instance_id,
              error: null,
            }),
          ),
        };
      case "close_database": {
        if (this.failClose) throw new Error("Instance release failed");
        const instanceId = args.instance_id;
        if (typeof instanceId !== "string")
          return { closed: false, final_lease: false, idb_path: null };
        const entry = this.#instances.get(instanceId);
        if (entry === undefined)
          return { closed: false, final_lease: false, idb_path: null };
        this.#instances.delete(instanceId);
        if (this.database === instanceId) this.database = undefined;
        return {
          closed: true,
          final_lease: true,
          idb_path: `${entry.path}.i64`,
        };
      }
      default:
        throw new Error(`Unimplemented producer tool ${name}`);
    }
  }

  private containing(address: number) {
    return (
      this.functions.find(
        ({ start, end }) => address >= start && address < end,
      ) ?? null
    );
  }

  private execute(args: Readonly<Record<string, JsonValue>>): JsonValue {
    const parsed =
      typeof args.code === "string" ? opMarker.exec(args.code) : null;
    if (parsed === null)
      throw new Error("Fixture execute_python without a rea-op marker");
    const op = parsed[1]!;
    const opArgs = JSON.parse(parsed[2]!) as {
      address?: string;
      name?: string;
    };
    const address = opArgs.address === undefined ? NaN : Number(opArgs.address);
    const reply = (): JsonValue => {
      switch (op) {
        case "identity":
          return {
            path: this.inputPath,
            sha256: this.inputSha256,
            base: this.imageBase,
            architecture: this.architecture,
            bitness: this.bitness,
          };
        case "inventory":
          return {
            functions: this.functions.map(({ name, start, end }) => ({
              name,
              start: hex(start),
              end: hex(end),
            })),
          };
        case "by_name": {
          const name = opArgs.name ?? "";
          const direct = this.functions.find((f) => f.name === name);
          if (direct !== undefined)
            return { name: direct.name, start: hex(direct.start) };
          const alias = this.names.find((n) => n.name === name);
          const resolved =
            alias === undefined
              ? undefined
              : this.functions.find((f) => f.start === alias.address);
          return resolved === undefined
            ? null
            : { name: resolved.name, start: hex(resolved.start) };
        }
        case "strings": {
          this.stringsBuilt += 1;
          return {
            strings: defaultStrings.map(({ address, length, text }) => ({
              address: hex(address),
              length,
              text,
            })),
          };
        }
        case "containing": {
          const fn = this.containing(address);
          return {
            match: fn === null ? null : { name: fn.name, start: hex(fn.start) },
            outside: Number.isNaN(address),
          };
        }
        case "pseudocode":
          return { text: this.pseudocode };
        case "assembly":
          return {
            lines:
              this.containing(address)?.instructions.map(({ text }) => text) ??
              [],
          };
        case "instructions":
          return {
            instructions:
              this.containing(address)?.instructions.map(({ ea, text }) => ({
                address: hex(ea),
                text,
              })) ?? [],
          };
        case "callers":
          return {
            callers: [
              {
                from: hex(0x1004),
                caller: { name: "main", start: hex(0x1000) },
              },
            ],
          };
        case "callees":
          return { callees: [{ name: "puts", start: hex(0x2000) }] };
        case "xrefs":
          return { to: [{ from: hex(0x1004), type: "call" }], from: [] };
        default:
          throw new Error(`Unimplemented fixture operation ${op}`);
      }
    };
    return { result: reply(), stdout: "", stderr: "" };
  }
}
