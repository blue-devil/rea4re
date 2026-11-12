# IDA provider

REA adapts the [official Hex-Rays IDA MCP server](https://github.com/HexRaysSA/ida-mcp) into its native analysis tools on Windows, macOS, and Linux. Install and configure the upstream server and IDA using their instructions; REA does not install, upgrade, activate, or license IDA or the server, and does not bundle another IDA server. Earlier releases adapted [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp); that upstream and its registration profiles are no longer accepted.

Choose one lifecycle mode in an upstream MCP JSON registration. Set `REA_IDA_MCP_CONFIG` to that file, then select `ida` once through `REA_ANALYSIS_PROVIDER`, the CLI's `--provider ida`, or MCP's `open_binary.provider_id`. No provider startup occurs during discovery.

## Prerequisites

The upstream server requires IDA 9.4 or higher (IDA Home, IDA Pro, or IDA Classroom) with idalib, Python 3.11+, and `git` and [uv](https://github.com/astral-sh/uv) on `PATH`. Install the server and its GUI plugin with upstream's installer:

```bash
uvx ida-hcli mcp install
```

The GUI plugin is optional for headless analysis: without it, the server still opens headless idalib workers. With it, headless workers can run inside `idat` with IDA's own Python, and the server can attach to databases already open in the IDA GUI. REA connects to an already-configured server; it never runs the installer.

## Supported upstream versions

Compatibility is checked against the live `tools/list` catalog after connect, not a version string. REA requires `open_database`, `execute_python`, `list_databases`, and `close_database` and fails closed with the missing tool names when they are absent. `save_database` is never called: REA's upstream contract is read-only analysis, and an attached GUI database is never saved or closed by REA.

## Analyze an already-open GUI target

Open the **original input binary** in the IDA GUI and wait for analysis. The registration names any server you run; the upstream default is:

```json
{
  "command": "uvx",
  "args": ["ida-mcp", "stdio", "--agent=rea"]
}
```

An existing MCP client configuration with an `mcpServers` object containing an `"ida"` entry is also accepted. Use the executable and arguments from your working upstream registration.

```bash
export REA_IDA_MCP_CONFIG=/absolute/path/to/ida-mcp.json
export REA_ANALYSIS_PROVIDER=ida
rea function /absolute/path/to/program main --json
rea decompile /absolute/path/to/program main --json
```

If the registration cannot be read or validated, provider diagnostics retain its selected `registration_path` and the configuration owner's setting/constraint facts in `configuration_details.settings`. `configured` means a path was selected, not that it is valid or that an IDA connection was established; failed registrations remain unavailable.

An HTTP registration's `url` must use `http` or `https` without URL credentials, and its host must be `localhost`, `127.0.0.1`, `[::1]`, or the Docker/Podman host-gateway name `host.docker.internal` or `host.containers.internal`. Use a gateway name when REA runs in a container and the server listens on the container host. REA refuses every other host.

Attached mode attaches through the server's `open_database` to the database the GUI has open for the same path. REA verifies the database's recorded input SHA-256 and image base around every request; a mismatch or target switch fails with recovery guidance. The original input must remain readable by REA; WSL can use its mounted alias while the GUI runs on Windows. Attached mode refuses universal Mach-O inputs at admission: every slice shares the recorded whole-file hash, so REA cannot verify which slice the GUI loaded. Open a thin file extracted with `lipo -thin` in both IDA and REA, or use headless mode, which analyzes the selected slice.

Closing the REA session releases only REA's lease on the attached database (`close_database`); the GUI database stays open and unsaved. External edits remain visible because results are live and are not replayed from snapshots. These checks do not lock the GUI or prove that the database is unpatched.

## Give REA a target for headless analysis

Add `"mode": "headless"` to the registration. REA copies the admitted binary into a private temporary directory, checks its digest, and asks the server to open it in a headless worker (`open_database`; backend `idalib` or `idat`). Headless mode analyzes the selected Mach-O slice after thinning, and supports the same operations as attached mode. REA verifies the worker's reported input path and the private copy's digest around every request.

```json
{
  "command": "uvx",
  "args": ["ida-mcp", "stdio", "--agent=rea"],
  "mode": "headless"
}
```

The same CLI commands work in both modes. For a Windows-native REA process:

```powershell
$env:REA_IDA_MCP_CONFIG = 'D:\analysis\ida-mcp.json'
$env:REA_ANALYSIS_PROVIDER = 'ida'
rea function 'D:\samples\program.exe' main --json
```

Headless REA and the configured server must share the host filesystem and native path syntax. Run REA on Windows when the server runs its workers on Windows. The attached profile can span WSL and a Windows GUI because it binds recorded input hashes instead of asking the GUI to open a WSL path.

On close or failed startup, REA releases its worker with `close_database` and verifies the instance disappears from the server's database inventory; the private input and sidecars are then removed. An unverified release retains the workspace and reports incomplete cleanup.

## How observations are produced

Analysis operations run as read-only `execute_python` programs against the opened database using the upstream ida-domain API. REA composes each query, embeds caller-supplied names and addresses safely, and parses the returned JSON with strict schemas; malformed or unsuitable producer output fails closed with the upstream error text retained in diagnostics. Procedure inventories, string inventories, and both literal and regex search are fetched from the database and matched with REA's own matcher, so REA's Unicode matching rules apply unchanged; there is no upstream regex-dialect divergence.

Direct callers are resolved from call cross-references, and callees from the database's callee relationships, in both modes. `resolve_containing_procedure` resolves an address to the canonical entry of its containing function in both modes. `list_documents` exposes the single target admitted for the session.

Decompilation uses the local Hex-Rays decompiler through the upstream API. IDA Free's cloud decompiler, where applicable, follows its own licensing, consent, and network requirements; failures remain explicit failures.

## Coverage and evidence

REA admits x86, x86_64, arm and arm64 executables through IDA. Every other CPU family, including families that REA recognizes later, is refused until REA admits it explicitly. Raw-binary and GameCube DOL targets are refused; open them with Ghidra. Admission is not verification: see [Verification](#verification) for the covered configurations.

All profiles support procedure/string inventory and literal or regex search, procedure resolution, pseudocode, assembly, raw function instructions, resolved callers and callees, incoming address references, containing-procedure resolution, and a function dossier. `provider.version` identifies the REA adapter; the profile records `version_scope: "rea-ida-adapter"`. The MCP handshake's `serverInfo` is separate and does not establish IDA or Python distribution versions.

Complete body ranges, typed reference edges, CFG, referenced data, source locals, comment kinds, and database revision are unavailable. Empty unsupported dossier facets mean **unknown**, not observed absence. Whole-symbol inventory, mutation, debugging, arbitrary Python forwarding, and requested GUI navigation are outside this adapter's coverage. `execute_python` is never exposed as a passthrough: REA runs only its own composed, read-only queries.

## Connect an agent once

Add the registration path to the **REA** MCP entry's environment, keeping the upstream registration in its separate JSON file:

```json
{
  "mcpServers": {
    "rea": {
      "command": "npx",
      "args": ["-y", "rea-agents@<version-with-ida>", "mcp"],
      "env": {
        "REA_ANALYSIS_PROVIDER": "ida",
        "REA_IDA_MCP_CONFIG": "/absolute/path/to/ida-mcp.json"
      }
    }
  }
}
```

Use a package version that actually includes this adapter; repository main can be ahead of the npm release. After reconnecting:

```json
{"name":"open_binary","arguments":{"path":"/absolute/path/to/program","provider_id":"ida"}}
{"name":"analyze_function","arguments":{"procedure":"main"}}
{"name":"search_strings","arguments":{"pattern":"license"}}
{"name":"close_binary","arguments":{}}
```

Opening an MCP target starts its selected provider session; headless opening waits for auto-analysis. Set the agent's MCP request deadline long enough for the target. The registration JSON named by `REA_IDA_MCP_CONFIG` has an optional `timeoutMs` integer from 1 to 2147483647; omitted means 300000. `rea doctor --provider ida --json` validates the registration without starting IDA.

The public profile's registration digest excludes HTTP authentication header values (`Authorization`, `Proxy-Authorization`, and `Cookie`). Mark any other credential fields explicitly with `"sensitive": { "headers": ["X-Api-Key"], "env": ["PRIVATE_VALUE"] }` in the registration. These values are also redacted from IDA diagnostics.

## Migrate an mrexodia or native registration

1. Install the official server per [Prerequisites](#prerequisites) and stop the old upstream server.
2. Replace the registration file with the upstream registration shown above, keeping your chosen `mode`. An `mcpServers` envelope with an `"ida-pro-mcp"` key is no longer accepted; use the bare registration or an `"ida"` key.
3. The legacy attached 1.4 profile (Python `server.py --ida-rpc` proxy), the database-supervisor headless profile (`idalib-mcp` with `idb_open`/`idb_list`/`idb_close`), and the 0xshlomil/ida-free-mcp native bridge are removed; their registrations fail closed with the missing-tool diagnostics naming what the official catalog provides instead.
4. Reopen the REA binary session to connect with the new registration.

## Verification

Run `npm run verify:ida -- --target /absolute/path/to/program --procedure main` with a configured upstream server. It exercises production CLI and MCP tools, validates their output contracts and Evidence, checks original-input preservation and session cleanup, and keeps local target data out of its console summary. Supply `--package-root` to verify an extracted or installed package. See [testing](../development/testing.md) for the distinction between adapter tests and real-provider evidence.

The adapter's contract tests run against an in-memory producer that serves the official tool catalog. The official server has been verified end to end headless on Linux arm64 with IDA Professional 9.4 (idalib) and server build 20260924.0.3: `npm run verify:ida` passed against `tests/conformance/ida/inventory.c`, covering production CLI and MCP parity, function Evidence, inventory/search, pseudocode, assembly, instructions, containing procedures, address context, feature tracing, second-function switching, invalid input, instance cleanup, and private-workspace removal; string and xref oracles ran without independent expected literals. See [verification](../verification/ida-hexrays-cutover-2026-11-12.md). The GUI attach path on any platform, Windows, and other IDA releases remain unverified.
