# ILSpy-MCP Managed Decompilation Source — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `rea4re decompile-managed-members` drives a BYO ILSpy-MCP server, joins decompiled text with REA's own member inventory, and returns the existing `import_managed_reconstruction` Evidence — no hand-built JSON.

**Architecture:** New `src/ilspy/` module family (config, session client, response parser, doctor inspection) mirrors the IDA adapter's shape. One new managed-provider operation `decompile_managed_members` enters through the managed contract array (single source of truth: union, effects, capabilities, MCP registration, CLI admission, catalog all derive). The operation dispatches from `ManagedStaticProvider`, orchestrates inspect → decompile → join → import, and emits reconstruction Evidence through the existing domain executor.

**Tech Stack:** TypeScript, zod, MCP SDK (`StdioClientTransport`), vitest. No new runtime dependencies.

**Spec:** `docs/specs/managed/ilspy-decompilation-source/spec.md`

## Global Constraints

- Node: `.nvmrc` 24.22.1; system Node ≥26.13 also supported (esbuild loader fix already landed).
- Upstream is beta: never trust a version string; the live `tools/list` catalog is the only compatibility check; missing/renamed tools fail closed naming the missing tools.
- Constraint text in every config/registration error is schema-authored only; rejected values never surface; values named in `sensitive.env`/`sensitive.headers` never appear in diagnostics or doctor JSON.
- REA stays the sole owner of managed metadata interpretation; ILSpy-MCP is a decompiler text producer only.
- No filesystem writes by the new operation; effect flags: `launchesProcess`, `mutatesSession`, nothing else.
- Conventional Commits; generated artifact `.cache/mcp-tool-catalog.json` regenerated via `npm run mcp-catalog:generate` when contracts change.
- Tests: `PATH="/usr/local/bin:$PATH" npm run test:local -- <paths>` for source tests; `npm run check:fast` before each push to `origin`.

## Review Focus

1. Secret leakage through the new config/doctor surfaces — a caller's `sensitive.env` value must never appear in any diagnostic, doctor JSON, or error (pinned by Task 1/4 tests asserting `JSON.stringify(inspection)` omits the secret).
2. Orphaned ILSpy-MCP child process on failure mid-operation — close must retain cleanup failures and report them (pinned by Task 3 tests with a fake close failure).
3. Upstream catalog drift — a renamed `decompile_method` tool must refuse before any member call (pinned by Task 3 catalog test).
4. Silent member loss — a member that fails to join must appear in per-member diagnostics, never vanish (pinned by Task 5 tests).
5. Lock mismatch — reconstruction text joined to the wrong token must be impossible; `signature_sha256` comes only from REA's inspection, keyed by member identity, never from upstream (pinned by Task 5).

---

### Task 1: ILSpy-MCP registration config

**Review:** per-task — security

**Files:**

- Create: `src/ilspy/IlspyMcpConfiguration.ts`
- Create: `src/ilspy/IlspyMcpConfiguration.test.ts`
- Modify: `src/config/environment.ts:53-57` (add `REA_ILSPY_MCP_CONFIG` beside `REA_IDA_MCP_CONFIG`)
- Modify: `src/config/parseConfig.ts:156-160` (conditional `ilspyMcpConfigPath`)
- Modify: `src/types.ts:26` (add `readonly ilspyMcpConfigPath?: string;`)
- Modify: `src/application/SetupRegistrationEnvironment.ts:43-47` (env allowlist)

**Interfaces:**

- Produces: `readIlspyMcpConfiguration(path: string): Promise<Result<IlspyMcpRegistration, ConfigurationError>>`; `IlspyMcpRegistration` = strict union `{ type: "stdio", command: string, args: string[], env: Record<string,string> } | { type: "http", url: string (loopback only) }` + shared `sensitive: { headers: string[], env: string[] }` + `timeoutMs` (default 300000). Consumed by Tasks 3, 4, 7.

- [ ] **Step 1: Write failing tests** — valid stdio registration parses; valid loopback http parses; non-loopback http url refuses with constraint naming the setting; relative env path refuses at config parse; 64 KiB file cap; non-JSON file error carries `settings:[{setting:"REA_ILSPY_MCP_CONFIG"}]` and no rejected input values; optional `{mcpServers:{...}}` envelope unwraps.
- [ ] **Step 2: Run** `PATH="/usr/local/bin:$PATH" npm run test:local -- src/ilspy/IlspyMcpConfiguration.test.ts` — expect FAIL (module absent).
- [ ] **Step 3: Implement** modeled on `src/ida/IdaConfiguration.ts:35-231` (omit `mode`/`workspaceRoot`; keep 64 KiB cap, strict union, absolute-path/loopback refinements, constraint-only error projection).
- [ ] **Step 4: Run** — expect PASS. Commit `feat(managed): add REA_ILSPY_MCP_CONFIG registration config`.

### Task 2: Upstream response parser

**Files:**

- Create: `src/ilspy/IlspyMcpResponseParser.ts`
- Create: `src/ilspy/IlspyMcpResponseParser.test.ts`
- Create: `tests/fixtures/ilspyMcpResponses.ts` (recorded real response shapes)

**Interfaces:**

- Produces: `parseIlspyToolText(text: string): Result<IlspyToolText, IlspyResponseParseError>`; `IlspyToolText = { body: string, pagination: { total: number, returned: number, truncated: boolean, offset: number } | null, trailingFooters: string[] }`. Consumed by Task 5 and 7.

- [ ] **Step 1: Failing tests** — fixture with `[pagination:{total:3,returned:3,truncated:false,offset:0}]` parses; text without footer yields `pagination: null`; `truncated:true` is preserved, never normalized away; unrecognized footer syntax fails closed with the offending line quoted in the error constraint.
- [ ] **Step 2: Run** — expect FAIL. **Step 3:** implement one regex-based footer parser; bodies pass through verbatim. **Step 4:** PASS. Commit `feat(ilspy): parse ilspy-mcp text responses`.

### Task 3: Session client with catalog admission

**Review:** per-task — concurrency

**Files:**

- Create: `src/ilspy/IlspyMcpSessionClient.ts`
- Create: `src/ilspy/IlspyMcpConnection.ts`
- Create: `src/ilspy/IlspyMcpSessionClient.test.ts`

**Interfaces:**

- Consumes: Task 1 config; injectable connection `connect/call/serverInfo/close` (pattern: `src/ida/IdaMcpConnection.ts:57-75,364`).
- Produces: `IlspyMcpSessionClient` with `open(): Promise<Result<void, IlspyStartupError>>` (catalog check inside), `callTool(name, args)`, `close(): Promise<void>` throwing `IlspyCleanupError { cleanupResources }` on failed termination; `REQUIRED_ILSPY_TOOLS = ["decompile_method", "disassemble_method"]`.

- [ ] **Step 1: Failing tests** (injectable fake transport): stdio spawn launches configured command once; `open` refuses when live `tools/list` lacks a required tool, error names the missing tools; `close` on already-dead child reports the resource and throws `IlspyCleanupError`; http config refuses non-loopback before connect.
- [ ] **Step 2:** FAIL. **Step 3:** implement modeled on `src/ida/IdaSessionClient.ts` (serial calls, startup identity check, cleanup ownership retained on failure). **Step 4:** PASS. Commit `feat(ilspy): add owned ilspy-mcp session client`.

### Task 4: Doctor probe

**Files:**

- Create: `src/ilspy/IlspyDoctor.ts`
- Create: `src/ilspy/IlspyDoctor.test.ts`
- Modify: `src/application/Doctor.ts:163` (optional `ilspyMcpHealth?` host method), `Doctor.ts` impl block (~`:818`)
- Modify: `src/application/DoctorDiagnostics.ts:43-44,303-321` (probe push + check builder)
- Modify: `src/doctorRuntime.ts:181-186,345-412` (`PROVIDER_SETTINGS`, provider inspection wiring)
- Modify: `src/application/DoctorProviderIds.ts:10-16` (add `ilspy-mcp`)

**Interfaces:**

- Produces: `DoctorProviderInspection { id: "ilspy-mcp", configured, checks: [{ name: "registration" }, { name: "health" } ...] }` flattened as `ilspy-mcp-<check>`; check remediation names `REA_ILSPY_MCP_CONFIG`.

- [ ] **Step 1: Failing tests** — absent env → `configured: false` (not an error); valid config file → `registration` check healthy; unspawnable command → `health` check `runtime_failure` with remediation; redaction invariant: secret env value never appears in `JSON.stringify(inspection)`.
- [ ] **Step 2:** FAIL. **Step 3:** implement modeled on `src/ida/IdaDoctor.ts:15-65` + `optionalIlspyCheck` (`DoctorDiagnostics.ts:303-321`). **Step 4:** PASS. Commit `feat(ilspy): doctor inspection for ilspy-mcp`.

### Task 5: Member join and import builder

**Files:**

- Create: `src/ilspy/IlspyMemberJoin.ts`
- Create: `src/ilspy/IlspyMemberJoin.test.ts`

**Interfaces:**

- Consumes: `ManagedMemberInspection` (from `src/dotnet/` inspection), `IlspyToolText`, output kind.
- Produces: `buildIlspyReconstructionRequest(inspection, selections: { token, text, kind }[]): { request: ManagedReconstructionImportRequest, excluded: [{ token, declaring_type, name, reason }] }` — `signature_sha256`/`normalized_il_sha256` sourced only from inspection rows matched by token; excluded members carry `missing_normalized_il | empty_text | truncated_text | unknown_token | ambiguous_member_name | token_mismatch`; `request.methods` empty → caller refuses before import.

- [ ] **Step 1: Failing tests** — happy join produces per-method lock values from inspection rows; upstream text attached to wrong token in the caller's selection is impossible by construction (selection carries token, join reads lock values from inspection by that token); empty/truncated text excluded with reason; zero joinable members yields empty `methods` and refusal upstream; at least one joinable → request valid per `managedReconstructionImportInputSchema`; two inspection members sharing a method name are both excluded with `ambiguous_member_name` before any upstream call; `decompiled-il` selections whose `showTokens` response lacks the member's token are excluded with `token_mismatch`.
- [ ] **Step 2:** FAIL. **Step 3:** implement pure joiner. **Step 4:** PASS. Commit `feat(ilspy): join ilspy text with managed member evidence`.

### Task 6: Managed contract entry + result schema

**Files:**

- Create: `src/domain/managed/managedDecompilation.ts` (+ `.test.ts`)
- Modify: `src/contracts/toolOutputSchemaGroups.ts:451-467` (`decompile_managed_members` in `managedOutputSchemas`)
- Modify: `src/contracts/toolEffects.ts:685-690` (effect audit entry: `effects({ mutatesSession: true, launchesProcess: true })`)
- Modify: `src/contracts/managed/managedToolContracts.ts:48-131` (contract entry, `kind: "managed-provider"`, input schema: absolute `assembly_path`, `declaring_type`, optional `member_names`, `output_kind` enum)
- Regenerate: `npm run mcp-catalog:generate`

**Interfaces:**

- Produces: `managedDecompilationResultSchema` = strict object: `decompiler {name, version, family: "ilspy"}`, `assembly {path, sha256}`, `methods[] {token, declaring_type, name, status: "reconstructed"|"excluded", reason?, reconstruction?}`, `reconstruction` (import result shape), `limitations[]`, wrapped `evidenceResultOf(...)`.

- [ ] **Step 1: Failing tests** — schema rejects unknown fields; effect-audit completeness test (existing `toolEffects.test.ts`) forces the new entry; contract examples validate against input/output schemas; catalog fixture regenerates with `analysisOperation: "decompile_managed_members"`.
- [ ] **Step 2:** FAIL. **Step 3:** implement. **Step 4:** run `PATH="/usr/local/bin:$PATH" npm run test:local -- src/contracts/toolEffects.test.ts src/domain/managed/managedDecompilation.test.ts` PASS; run `npm run mcp-catalog:generate`. Commit `feat(managed): decompile_managed_members contract`.

### Task 7: Application workflow + provider dispatch

**Files:**

- Create: `src/application/managed/ManagedDecompilationService.ts` (+ `.test.ts`)
- Modify: `src/dotnet/ManagedStaticProvider.ts:218-248` (dispatch branch, result-union widen)

**Interfaces:**

- Consumes: Tasks 1, 2, 3, 5, 6 outputs; `ManagedMemberInspector` via the same application entry `inspect_managed_members` dispatches to.
- Produces: `decompileManagedMembersEvidence(rawInput, lookup?, {signal}): Promise<Result<Evidence, AnalysisError>>` — open session → REA inspection → upstream calls per member → join → `executeManagedReconstructionImport` → Evidence (`MANAGED_WORKFLOW_PROVIDER`, predicate `rea.managed-decompilation`, limitations incl. excluded members) → `close()` in `finally`, cleanup failure appended to result limitations.

- [ ] **Step 1: Failing tests** (fake connection): full happy path yields reconstruction Evidence with `reconstruction_id`; truncated member appears in `methods[]` as `excluded` with reason; startup refusal propagates typed error; close failure appends limitation and keeps Evidence valid; zero joinable members → typed refusal naming members.
- [ ] **Step 2:** FAIL. **Step 3:** implement orchestration; spawn once per execution; serial member calls bounded by existing managed decode budgets. **Step 4:** PASS. Commit `feat(managed): decompile_managed_members workflow`.

### Task 8: CLI command

**Files:**

- Modify: `src/cliCommandNames.ts:142-147` (`decompileManagedMembers: "decompile-managed-members"`)
- Modify: `src/cli/managedCommands.ts` (registrar modeled on `:163-192`)
- Modify: test file covering managed commands (same file as `import-managed-reconstruction` coverage)

**Interfaces:**

- Consumes: Task 7 service. Args: `assembly_path` (absolute), `declaring_type`, optional `member_names`, `output_kind`; `--evidence-bundle` option from shared `evidenceBundleOption`.

- [ ] **Step 1: Failing CLI test** — command resolves workflow via `runEvidenceInputCommand`, projects result like the import command; invalid relative path refused at parse.
- [ ] **Step 2:** FAIL. **Step 3:** implement. **Step 4:** PASS. Commit `feat(cli): decompile-managed-members command`.

### Task 9: MCP surface boundary test

**Files:**

- Modify: `tests/boundary/mcp/managedMcp.test.ts` (style: path admission + catalog listing)

**Interfaces:** Consumes Task 6/7 registration; no production changes expected.

- [ ] **Step 1: Failing test** — `tools/list` exposes `decompile_managed_members` with effect annotations; path admission applies; `runManagedProviderExecution` route reaches Task 7 service (fake client injected).
- [ ] **Step 2:** FAIL. **Step 3:** fix wiring only if drift; expected to pass after Task 7 registration. **Step 4:** PASS. Commit `test(managed): mcp surface for decompile_managed_members`.

### Task 10: Docs + README paradigm

**Files:**

- Create: `docs/providers/ilspy-mcp.md`
- Modify: `docs/guides/managed/managed-code-analysis.md` (link the new workflow)
- Modify: `README.md` (paradigm section)

**Interfaces:** None.

- [ ] **Step 1:** write provider doc (setup, config shape, catalog check semantics, doctor, workflow example, beta-upstream caveat); guide section with one worked command; README paradigm section stating the rea4re strategy and its pillars (decompile-first → workflow comprehension → behavior collision → rebuild), with managed .NET analysis named as pillar 1's worked example and pillars 2–4 declared as upcoming.
- [ ] **Step 2:** `PATH="/usr/local/bin:$PATH" npm run docs:check` — PASS. Commit `docs: ilspy-mcp workflow and rea4re paradigm`.

### Task 11: Real-provider verification lane

**Files:**

- Create: `scripts/verify-real-ilspy-mcp.mjs`
- Create: `tests/fixtures/managedAssemblyProvenance.ts`
- Create: `tests/boundary/providers/ilspy/managedDecompilationReal.test.ts` (env-gated: runs only when `REA_ILSPY_MCP_TEST_BIN` set)

**Interfaces:** Consumes Task 7 with a real config pointing at the pinned release binary.

- [ ] **Step 1:** fixture module records provenance: ILSpy-MCP release tag, archive SHA-256, fixture DLL origin + SHA-256 (fixture DLL shipped inside the release archive, e.g. `ICSharpCode.Decompiler.dll`; refuse to run when digests mismatch). Provisioning follows the repo's BYO convention: both binary and fixture arrive via `REA_ILSPY_MCP_TEST_BIN` / `REA_ILSPY_MCP_TEST_FIXTURE` env paths; nothing downloads in CI, no binaries are committed, tests skip cleanly when unset.
- [ ] **Step 2:** verification script: download pinned archive, verify digest, extract, run the boundary test suite (decompile a known type of the fixture DLL, assert lock join + reconstruction id + excluded-member path via a deliberately mismatched member name).
- [ ] **Step 3:** `PATH="/usr/local/bin:$PATH" npm run test:local -- tests/boundary/providers/ilspy/` with env unset — SKIPPED cleanly (document skip reason).
- [ ] **Step 4:** run script with env set; record output in spec `verification.md`. Commit `test(ilspy): real-provider verification lane`.

## Self-Review Notes

- Spec coverage: config (T1), parser (T2), lifecycle+catalog (T3), doctor (T4), join (T5), contracts (T6), workflow (T7), CLI (T8), MCP (T9), README/docs (T10), real verification (T11). HTTP transport and export_project stay out (spec non-goals).
- Type consistency: `IlspyToolText`, `ManagedReconstructionImportRequest`, `decompile_managed_members` used identically across tasks.
- Review marks: security (T1), concurrency (T3) — plan runs subagent-driven per skill default.
