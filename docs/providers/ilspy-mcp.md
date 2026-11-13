# ILSpy-MCP managed decompilation source

REA drives a BYO [ILSpy-MCP server](https://github.com/cervonwong/ILSpy-MCP) as its managed decompilation source. REA stays the metadata owner: it inspects assemblies with its own readers, selects members from its own inventory, and locks every decompiled method to the token, signature, and normalized-IL hashes it observed itself. Decompiled text enters REA only through the hash-locked reconstruction import — the same contract `import_managed_reconstruction` already enforces — so decompiler output stays analyst inference and never becomes canonical metadata.

REA does not install, build, or upgrade ILSpy-MCP. Configure a server you provide.

## Prerequisites

Download a pre-built, self-contained ILSpy-MCP server binary from the upstream release page for your host (Linux, macOS, and Windows, x64 and arm64). The binary is self-contained: no .NET SDK or runtime install is required.

Upstream is beta and changes frequently. REA treats no version string as a compatibility guarantee: after connecting, it reads the live `tools/list` catalog and requires exactly the tools this workflow drives. A missing or renamed tool fails closed with the missing tool names in the error. The server's declared version is recorded in Evidence as an observation, not a contract.

## Configuration

Set `REA_ILSPY_MCP_CONFIG` to an absolute path naming a JSON file with one stdio registration (`command`, `args`, optional `env`), following the same shape and redaction rules as `REA_IDA_MCP_CONFIG`:

```json
{
  "command": "/absolute/path/to/ILSpyMCP.Server",
  "args": [],
  "env": {},
  "sensitive": { "headers": [], "env": ["PRIVATE_VALUE"] },
  "timeoutMs": 300000
}
```

`args`, `env`, `sensitive`, and `timeoutMs` are optional; omitted `timeoutMs` means 300000 (1 to 2147483647 milliseconds). Mark credential environment values explicitly under `sensitive.env`; they are redacted from diagnostics and never inferred from names.

A loopback HTTP registration (`url` on `localhost`, `127.0.0.1`, or `[::1]`, no credentials) validates at configuration time but is refused at operation time in phase one with a typed `unsupported_transport` error; doctor reports the registration healthy and names the refusal. Every other host is refused.

## Doctor

```bash
rea4re doctor --provider ilspy-mcp --json
```

With no `REA_ILSPY_MCP_CONFIG`, doctor reports the probe as not configured — a healthy observation, not an error. With a configuration, doctor runs a bounded live probe of the configured server and reports its declared version as an observation, next to the existing optional `ilspycmd` probe.

## Decompile managed members

The workflow command is `rea4re decompile-managed-members`, following the `import-managed-reconstruction` command shape:

```bash
rea4re decompile-managed-members /absolute/path/Assembly.dll \
  Newtonsoft.Json.JsonTextReader \
  --member-names ParseReadNumber --output-kind decompiled-csharp --json
```

Inputs are the assembly path, one declaring type (optionally narrowed to member names), and an output kind: `decompiled-csharp` (default) or `decompiled-il`. The operation inspects the selection with REA's own member reader first, spawns the configured stdio server once for the operation, decompiles each selected member, and internally executes the existing reconstruction import against REA's own locks. The connection is closed before the operation returns.

Each selected member is reported as reconstructed or excluded with one of these reasons:

| Exclusion reason        | Meaning                                                                                |
| ----------------------- | -------------------------------------------------------------------------------------- |
| `ambiguous_member_name` | The method name is not unique in its declaring type (overloads, multiple constructors) |
| `missing_normalized_il` | The member's normalized IL hash was not observed, so no lock could be built            |
| `empty_text`            | Upstream returned empty text (for example after the upstream truncation footer)        |
| `truncated_text`        | Upstream flagged the response `truncated`; truncated text is never admitted            |
| `unknown_token`         | The member's metadata token could not be determined for verification                   |
| `token_mismatch`        | `decompiled-il` output did not contain the member's own metadata token                 |
| `upstream_failure`      | The upstream tool call failed for this member                                          |

Excluded members are never silently dropped: the result limitations name them with their reasons, and each excluded member keeps its raw upstream text in its diagnostic so you can fall back to `import-managed-reconstruction` with your own lock values.

Trust model: `decompiled-csharp` output trusts upstream's name-based member selection, and the result states this in its limitations. `decompiled-il` output is verified — REA runs the upstream disassembler with tokens shown and requires the member's own metadata token to appear in the response before joining it; a mismatch excludes the member with `token_mismatch`. Truncated upstream text is never admitted under either kind.

## Limitations

- Phase one is stdio only; loopback HTTP registrations validate but are refused at use.
- Same-name members within a type are excluded as ambiguous; hand-import them through `import-managed-reconstruction`.
- Upstream is beta: expect breaking changes; compatibility is checked only against the live tool catalog, which fails closed naming missing tools.
- `export_project` and every other upstream tool are out of scope; REA drives only the tools this workflow needs.
