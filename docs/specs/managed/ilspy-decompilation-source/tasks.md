# Tasks — ILSpy-MCP managed decompilation source

Order matters where noted; Tasks 1–5 are otherwise independent of 6–9's shape but Tasks 6–9 consume their outputs.

- [ ] Task 1: `REA_ILSPY_MCP_CONFIG` registration config (security review)
- [ ] Task 2: Upstream response parser (`src/ilspy/IlspyMcpResponseParser.ts`)
- [ ] Task 3: Owned session client + catalog admission (concurrency review)
- [ ] Task 4: Doctor probe (`ilspy-mcp` provider inspection)
- [ ] Task 5: Member join + import builder (`IlspyMemberJoin.ts`)
- [ ] Task 6: `decompile_managed_members` contract, effects, schema, catalog regen
- [ ] Task 7: Application workflow + `ManagedStaticProvider` dispatch
- [ ] Task 8: CLI `decompile-managed-members`
- [ ] Task 9: MCP surface boundary test
- [ ] Task 10: Provider doc, managed guide section, README paradigm
- [ ] Task 11: Real-provider verification lane (pinned binary + provenance fixture)

Verification gate: after Task 11, run `npm run check:fast`, then the real-provider script, and record results in `verification.md`.
