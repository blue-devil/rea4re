import { z } from "zod";
import { jsonValueSchema } from "../domain/jsonValue.js";
import { AnalysisProtocolError } from "../domain/analysisErrorCore.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { idaAddressSchema } from "./IdaProtocolValues.js";

/**
 * Result schemas for the official HexRaysSA/ida-mcp server
 * (serverInfo.name "ida"). Every observation is fail-closed: a malformed
 * producer reply rejects instead of being interpreted.
 */

/** `open_database` reply: one attached database instance. */
export const openDatabaseResultSchema = z
  .object({
    instance_id: z.string().min(1),
    backend: z.enum(["gui", "idalib", "idat"]),
    status: z.enum(["attached", "current"]),
    recovery: z.string().nullish(),
    log_path: z.string().nullish(),
    mcp_id: z.string().nullish(),
    hint: z.string().nullish(),
  })
  .passthrough();
export type OpenDatabaseResult = z.infer<typeof openDatabaseResultSchema>;

/** One `list_databases` inventory row. */
export const databaseInstanceSchema = z
  .object({
    path: z.string(),
    backend: z.enum(["gui", "idalib", "idat"]),
    status: z.enum(["available", "attached", "current", "unavailable"]),
    instance_id: z.string().nullish(),
    error: z.string().nullish(),
  })
  .passthrough();
export const databaseInstancesSchema = z
  .object({ instances: z.array(databaseInstanceSchema) })
  .passthrough();
export type DatabaseInstance = z.infer<typeof databaseInstanceSchema>;

/** `close_database` reply; `closed` is the only release proof. */
export const closeDatabaseResultSchema = z
  .object({
    closed: z.boolean(),
    final_lease: z.boolean().nullish(),
    idb_path: z.string().nullish(),
  })
  .passthrough();

/** `execute_python` reply; the trailing expression arrives in `result`. */
export const executePythonResultSchema = z
  .object({
    result: jsonValueSchema,
    stdout: z.string().nullish(),
    stderr: z.string().nullish(),
  })
  .passthrough();

/** Identity probe: the live database's recorded input facts. */
export const identityResultSchema = z.object({
  path: z.string().min(1),
  sha256: z
    .string()
    .regex(/^[0-9a-f]{64}$/iu)
    .nullable(),
  base: idaAddressSchema.nullable(),
  architecture: z.string().nullable(),
  bitness: z.number().int().nullable(),
});

const functionEntrySchema = z.object({
  name: z.string().min(1),
  start: idaAddressSchema,
  end: idaAddressSchema,
});
export type IdaFunctionEntry = z.infer<typeof functionEntrySchema>;
export const inventoryResultSchema = z.object({
  functions: z.array(functionEntrySchema),
});

export const stringsResultSchema = z.object({
  strings: z.array(
    z.object({
      address: idaAddressSchema,
      length: z.number().int().nonnegative(),
      text: z.string(),
    }),
  ),
});

const resolvedProcedureSchema = z
  .object({ name: z.string().min(1), start: idaAddressSchema })
  .transform(({ name, start }) => ({ name, address: start }));
export const byNameResultSchema = resolvedProcedureSchema.nullable();
export const containingResultSchema = z.object({
  match: resolvedProcedureSchema.nullable(),
  outside: z.boolean(),
});
export type ResolvedProcedure = { name: string; address: string };

export const pseudocodeResultSchema = z.object({ text: z.string() });
export const assemblyResultSchema = z.object({ lines: z.array(z.string()) });
export const instructionsResultSchema = z.object({
  instructions: z.array(
    z.object({ address: idaAddressSchema, text: z.string() }),
  ),
});
export const callersResultSchema = z.object({
  callers: z.array(
    z.object({
      from: idaAddressSchema,
      caller: resolvedProcedureSchema.nullable(),
    }),
  ),
});
export const calleesResultSchema = z.object({
  callees: z.array(resolvedProcedureSchema),
});
const xrefKind = z.enum(["call", "jump", "read", "write", "flow", "other"]);
export const xrefsResultSchema = z.object({
  to: z.array(z.object({ from: idaAddressSchema, type: xrefKind })),
  from: z.array(z.object({ to: idaAddressSchema, type: xrefKind })),
});

/**
 * Read-only tools REA requires from the official ida-mcp server. REA never
 * calls `save_database` (repo rule: analysis is read-only).
 */
export const HEXRAYS_IDA_TOOLS = [
  "open_database",
  "execute_python",
  "list_databases",
  "close_database",
] as const;

/** Build one execute_python program: a fixture-dispatch marker, its JSON arguments, then the code. */
const program = (
  name: string,
  args: Readonly<Record<string, string>>,
  code: string,
): string => `# rea-op:${name}\n# rea-args:${JSON.stringify(args)}\n${code}`;

/** Python snippets whose trailing expression is the JSON-safe observation. */
export const idaHexraysCode = {
  identity: () =>
    program(
      "identity",
      {},
      `{"path": db.path, "sha256": db.sha256, "base": hex(db.base_address) if db.base_address is not None else None, "architecture": db.architecture, "bitness": db.bitness}`,
    ),
  inventory: () =>
    program(
      "inventory",
      {},
      `{"functions": [{"name": f.name, "start": f"{f.start_ea:x}", "end": f"{f.end_ea:x}"} for f in db.functions.get_all()]}`,
    ),
  strings: () =>
    program(
      "strings",
      {},
      `db.strings.rebuild()\n{"strings": [{"address": f"{s.address:x}", "length": s.length, "text": str(s)} for s in db.strings.get_all()]}`,
    ),
  /** `name` is caller-selected; only its JSON literal form is interpolated. */
  byName: (name: string) =>
    program(
      "by_name",
      { name },
      `f = db.functions.get_by_name(${JSON.stringify(name)})\nif f is None:\n    for ea, n in db.names:\n        if n == ${JSON.stringify(name)}:\n            f = db.functions.get_at(ea)\n            break\n({"name": f.name, "start": f"{f.start_ea:x}"} if f is not None else None)`,
    ),
  /** `address` is an already-validated 0x hexadecimal literal. */
  containing: (address: string) =>
    program(
      "containing",
      { address },
      // An address outside the database's mapped range is outside every
      // segment; the producer raises for it, so both facts come back in one
      // reply instead of a protocol failure.
      `ea = ${address}\nf = None\ntry:\n    f = db.functions.get_at(ea)\nexcept Exception:\n    f = None\n{"match": ({"name": f.name, "start": f"{f.start_ea:x}"} if f is not None else None), "outside": not (db.minimum_ea <= ea < db.maximum_ea)}`,
    ),
  pseudocode: (address: string) =>
    program(
      "pseudocode",
      { address },
      `f = db.functions.get_at(${address})\n{"text": str(db.functions.get_pseudocode(f))}`,
    ),
  assembly: (address: string) =>
    program(
      "assembly",
      { address },
      `f = db.functions.get_at(${address})\n{"lines": db.functions.get_disassembly(f, True)}`,
    ),
  instructions: (address: string) =>
    program(
      "instructions",
      { address },
      `f = db.functions.get_at(${address})\n{"instructions": [{"address": f"{i.ea:x}", "text": db.instructions.get_disassembly(i)} for i in db.functions.get_instructions(f)]}`,
    ),
  callers: (address: string) =>
    program(
      "callers",
      { address },
      `rows = []\nfor x in db.xrefs.to_ea(${address}):\n    if not x.is_call:\n        continue\n    c = db.functions.get_at(x.from_ea)\n    rows.append({"from": f"{x.from_ea:x}", "caller": ({"name": c.name, "start": f"{c.start_ea:x}"} if c is not None else None)})\n{"callers": rows}`,
    ),
  callees: (address: string) =>
    program(
      "callees",
      { address },
      `seen = set()\nrows = []\nfor c in db.functions.get_callees(db.functions.get_at(${address})):\n    if c.start_ea in seen:\n        continue\n    seen.add(c.start_ea)\n    rows.append({"name": c.name, "start": f"{c.start_ea:x}"})\n{"callees": rows}`,
    ),
  xrefs: (address: string) =>
    program(
      "xrefs",
      { address },
      `def _rea_kind(x):\n    if x.is_call:\n        return "call"\n    if x.is_jump:\n        return "jump"\n    if x.is_read:\n        return "read"\n    if x.is_write:\n        return "write"\n    if x.is_flow:\n        return "flow"\n    return "other"\n{"to": [{"from": f"{x.from_ea:x}", "type": _rea_kind(x)} for x in db.xrefs.to_ea(${address})], "from": [{"to": f"{x.to_ea:x}", "type": _rea_kind(x)} for x in db.xrefs.from_ea(${address})]}`,
    ),
} as const;

/**
 * Extract one execute_python trailing expression. A string reply is the
 * producer's Python failure text (traceback), so it stays a protocol error
 * carrying that text; an object the envelope schema cannot match may be a
 * structuredContent reply whose envelope was already unwrapped, so it is
 * admitted and left to the operation schema's own fail-closed parse.
 */
export const parseExecutePythonResult = (raw: JsonValue): JsonValue => {
  const parsed = executePythonResultSchema.safeParse(raw);
  if (parsed.success) return parsed.data.result;
  if (typeof raw === "string")
    throw new AnalysisProtocolError(`IDA execute_python failed: ${raw}`);
  return raw;
};
