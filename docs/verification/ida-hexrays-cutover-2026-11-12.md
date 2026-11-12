# IDA cutover to HexRaysSA/ida-mcp — 2026-11-12

Replacing the mrexodia/ida-pro-mcp profiles (legacy attached 1.4 GUI proxy,
headless database supervisor) and the 0xshlomil/ida-free-mcp native bridge
with the official HexRaysSA/ida-mcp server as REA's only IDA upstream.

## Environment

- Linux aarch64 (Arch Linux, kernel 7.3.3).
- Node.js 24.22.1 (repo pin), npm 11.19.1.
- IDA Professional 9.4 with idalib, licensed, at
  `/opt/scttools/disassemblers/idapro/final`; idalib Python bindings
  activated for CPython 3.14.3 (pyenv).
- Official `ida-mcp` PyPI build 20260924.0.3, launched per registration as
  `ida-mcp stdio --agent=rea-verify` (stdio; no uvx on PATH).
- Target: `tests/conformance/ida/inventory.c` built with
  `cc -O0 -g -fno-inline` (aarch64 PIE ELF).

## Real-provider lane

`npm run verify:ida -- --target … --procedure rea_fixture_add
--second-procedure rea_fixture_subtract --second-marker ' - 13'`
(headless mode): **passed**.

Checks recorded by the lane:

- production CLI and complete function Evidence;
- headless containing procedures, the admitted program as the document,
  address context, and the procedure match and references of feature
  tracing;
- second-function pseudocode identity and return to the original function;
- one MCP connection, positive procedure inventory/search, contract-valid
  tool results, invalid input, and close;
- CLI/MCP function identity, pseudocode, assembly, instructions, and
  relationship parity;
- owned instance ids absent from upstream discovery and private workspaces
  removed;
- original binary unchanged and never executed.

Unverified by this run (no independent oracles supplied): string
inventory/search correctness and xref correctness.

## Findings fixed during the run

- `open_database`'s `recovery` field is the upstream string
  (`none`/`repaired`/`restored`), not a boolean; the adapter schema and all
  fake producers were corrected.
- The callers/callees `execute_python` programs must return objects
  (`{"callers": […]}` / `{"callees": […]}`); bare arrays failed the
  operation schemas.
- An address outside the database makes the producer raise; the containing
  program now answers `not found` with an `outside_segments` reason derived
  from `db.minimum_ea`/`db.maximum_ea` instead of surfacing a protocol
  failure.

## Unverified for this upstream

- The attached (GUI) mode on any platform: `open_database` attach to a GUI
  instance, the `gui` backend identity checks, and GUI lease-release
  semantics.
- Windows and macOS hosts; other IDA releases and license editions;
  `uvx`-based launches and the `ida-hcli` installer path (the lane used the
  pip-installed console script directly).
- `list_documents` and health in attached mode; behavior when the GUI
  database is edited externally mid-session.
