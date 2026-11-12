# ILSpy-MCP as REA's managed decompilation source

## Outcome

rea4re drives ILSpy-MCP (https://github.com/cervonwong/ILSpy-MCP) itself. A
single CLI command and MCP operation decompile managed members against REA's
own metadata inventory, hash-lock the decompiler text per method, and return
the same reconstruction Evidence `import_managed_reconstruction` produces
today. The manual "run ilspycmd, hand-edit JSON, pray the hashes match" step
disappears.

This is the decompilation-first pillar of the rea4re paradigm: decompile (or
disassemble when needed) first, understand the workflow behind the code,
collide that comprehension with observed behavior, and rebuild. The README
states this paradigm.

## Background

REA owns managed metadata interpretation: `inspect_managed_artifact` and
`inspect_managed_members` parse assemblies with REA's own readers
(`src/dotnet/`). Decompiler output enters only through
`import_managed_reconstruction`, whose contract already declares
`family: "ilspy"` and locks every method to `token`, `signature_sha256`, and
`normalized_il_sha256` observed by REA (`src/domain/managed/managedReconstruction.ts`).
Today the caller produces that JSON by hand from an out-of-band `ilspycmd` run.

ILSpy-MCP wraps ICSharpCode.Decompiler as an MCP server: 27 tools, stdio or
HTTP transport, self-contained binary (Linux arm64 included), stateless
`assemblyPath` per call, read-only except `export_project`, plain-text
responses with `[pagination:{...}]` footers, beta with frequent breaking
changes.

## Requirements

- Configuration: `REA_ILSPY_MCP_CONFIG` names a JSON file with one stdio
  registration (`command`, `args`, optional `env`); an optional HTTP
  registration (`url`, loopback-only) is accepted and refused outside
  loopback. Same shape and redaction rules as `REA_IDA_MCP_CONFIG`
  (`src/ida/IdaConfiguration.ts`). Sensitive values are redacted by the
  existing diagnostics redactor, never inferred from names.
- Lifecycle: REA spawns the configured stdio server once per
  `decompile_managed_members` operation (the managed lane is stateless, so
  an operation is the session unit), reuses the connection for every tool
  call, and closes it before the operation returns. Close failures keep
  ownership and are reported as incomplete cleanup, following the shared
  `AnalysisClient` close contract.
- Catalog admission: before the first analysis call, REA reads the live
  `tools/list` catalog and requires exactly the tools this workflow drives
  (`decompile_method`, `disassemble_method`, and the inventory tools the
  workflow uses). A missing or renamed tool fails closed with the missing
  names in the error. No version string is treated as a compatibility
  guarantee; the live catalog is the only check. The server's declared
  version is recorded in Evidence as an observation, not a contract.
- Transport scope: an accepted loopback HTTP registration validates but is
  refused at operation time with a typed `unsupported_transport` error in
  phase one; doctor reports the registration healthy and names the refusal.
- Member selection: phase one admits members whose method name is unique
  within the declaring type, because upstream selects only by
  `assemblyPath`/`typeName`/`methodName`. Same-name members (overloads,
  multiple constructors) are excluded with reason `ambiguous_member_name`,
  and the result limitations name the excluded count and the
  `import_managed_reconstruction` fallback for them.
- Text binding: the `decompiled-il` output kind runs `disassemble_method`
  with `showTokens: true` and verifies the member's metadata token appears
  in the response before joining; a token mismatch excludes the member with
  `token_mismatch`. The `decompiled-csharp` kind trusts upstream's
  name-based selection, and the result states this trust model in its
  limitations.
- Text admission: truncated upstream text is never admitted. A member whose
  response carries `truncated: true` is excluded with `truncated_text`; the
  raw text still appears in that member's diagnostic for the caller's own
  import fallback.
- The workflow operation `decompile_managed_members` takes: the assembly
  path, a member selection (one declaring type, optionally narrowed to
  member names), and an output kind (`decompiled-csharp`, default, or
  `decompiled-il`). It runs REA's own member inspection for the selection
  first, then calls ILSpy-MCP per member, then builds and executes the
  existing import request internally and returns its reconstruction
  Evidence. Members whose inspection and decompilation cannot be joined
  (missing normalized IL, text empty after the upstream truncation footer)
  are reported per member and never silently dropped; the import admits the
  joinable subset only when at least one method joins, and the result
  limitations name the excluded members and reasons. Truncated responses
  are never admitted; see the text-admission requirement below.
- A member whose upstream text cannot be parsed into the reconstruction
  record still surfaces the raw text in the per-member diagnostic, so a
  caller can fall back to `import_managed_reconstruction` with their own
  lock values.
- Parsing of ILSpy-MCP text responses lives in one owner module under
  `src/ilspy/` (response footer parser, pagination state, truncation
  flags). No other file interprets upstream text. The parser is
  format-aware, fixture-pinned, and fails closed on shapes it does not
  recognize.
- Doctor: a new optional probe reports the configured ILSpy-MCP server's
  health and declared server info version next to the existing
  `ilspycmd` probe. Absent configuration is reported as not configured, not
  as an error.
- MCP and CLI: the operation registers in the managed tool contracts,
  effects (`launchesProcess` for the spawned server; no filesystem writes —
  `export_project` stays out of scope), the output schema group, the MCP
  catalog, and the CLI (`rea4re decompile-managed-members`), following the
  `import-managed-reconstruction` command shape.
- README: a short paradigm section states the rea4re strategy — decompile or
  disassemble first, understand the workflow, collide static comprehension
  with behavior, rebuild — and names managed .NET analysis as its first
  pillar with this workflow as the worked example.
- Real-provider verification: integration tests run against a pinned
  ILSpy-MCP release binary and a real managed assembly fixture whose
  provenance (source, version, SHA-256) is recorded in the fixture module.
  Parser and lock-join logic additionally carries simulated-producer tests
  with recorded real responses. No test claims real-provider behavior from
  simulated responses alone.

## Approaches considered

- Native analysis provider (like `ida`): rejected. Providers own
  address-space analysis; the managed lane is deliberately provider-less
  and REA must remain the owner of managed metadata interpretation. A
  provider would duplicate that ownership or carve a parallel deep lane
  against the `SessionProviderRouter` disjointness rules.
- One-to-one proxy of all 27 tools: deferred. It doubles catalog maintenance
  against a beta upstream and creates a second surface beside the managed
  tools before the locked workflow proves itself. Revisit after this phase.
- Chosen: managed decompilation source. REA stays the metadata owner,
  ILSpy-MCP is a decompiler producer behind the existing import contract,
  and the workflow is bounded by tools the workflow actually drives.

## Roadmap: the rea4re comprehension paradigm

This spec delivers pillar 1 of the rea4re strategy: decompile (or
disassemble when needed) first, understand the workflow behind the code,
collide that comprehension with observed behavior, and rebuild. The later
pillars are separate future specs, not scope here:

- Pillar 2 (workflow comprehension): a retained, machine-readable
  comprehension record per target — entry points, call and workflow edges,
  data flow, and analyst-grade claims — written from decompilation first,
  shared across the managed and native lanes.
- Pillar 3 (behavior collision): the comprehension record's claims checked
  against capture Evidence (`capture_process_scenario`,
  `correlate_static_and_runtime`), producing confirmed, diverged, and
  unknown verdicts per claim.
- Pillar 4 (creation): the obligation ledger driven by the collided
  comprehension, producing a verified reconstruction and generated source —
  the "collide and create" step, which has no surface today.

Pillar 1 is shaped to feed pillar 2: decompilation Evidence from this
workflow is the comprehension record's first-class input.

## Non-goals

- `export_project` (writes files; caller-choice semantics to design later).
- HTTP transport. Phase one is stdio only, REA-owned lifecycle.
- Managed call-graph / workflow-comprehension tools, behavior correlation
  for managed targets, and any reconstruction-generation ("collide →
  create") surface. These are the next pillars and get their own specs.
- Changes to `inspect_managed_*` ownership, the import contract schema, or
  the native provider surface.
