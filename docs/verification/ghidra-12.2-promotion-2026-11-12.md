# Ghidra 12.2 verified-build promotion — 2026-11-12

Moving `SUPPORTED_GHIDRA_VERSION` from 12.1.4 to 12.2 (JDK major 21 → 25)
with the accepted line kept at `12.x (>=12.1)`; 12.1.x installs remain
admitted as compatible, unverified builds.

## Environment

- Linux aarch64 (Arch Linux, kernel 7.3.3), 233 GB free disk.
- Node.js 24.22.1 (repo pin) and npm 11.19.1.
- Ghidra 12.2 PUBLIC, build 20261016, installed at
  `/opt/scttools/disassemblers/ghidra/v12_2`; distribution asset
  `ghidra_12.2_PUBLIC_20261016.zip`, SHA-256
  `2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67`
  (matches the GitHub release digest).
- OpenJDK 27.0.1.0.3 (`java-27-openjdk`), above the 12.2-declared `application.java.min=25`.
- GCC 16.1.1 for host-native fixtures; clang/LLD/llvm-readelf with riscv32
  targets for the RISC-V lane.

## Policy and source observations

- The local 12.2 tree declares `application.version=12.2`,
  `application.release.name=PUBLIC`, `application.java.min=25`,
  `application.java.compiler=25`, Python support 3.9–3.15.
- The public 12.2 distribution ships decompiler natives for `linux_x86_64`
  and `win_x86_64` only (directory listing), consistent with upstream's
  Getting Started: Windows ARM64 runs the x64 natives under emulation and
  macOS natives remain user-built. REA's `NATIVE_PLATFORMS` now maps
  `win32/arm64` to `win_x86_64` accordingly.
- `Ghidra/Processors/RISCV/data/languages` is byte-identical between the
  local 12.1.3 and 12.2 trees (file list, `riscv.table.sinc`,
  `riscv.opinion`); `riscv.ldefs` differs only by added `IDA-PRO` external
  names. The RISC-V lane's measured behavior claims (no big-endian language,
  RV32 default/AndeStar opinion ambiguity, the decoded extension set) carry
  over to 12.2 unchanged.

## Real-provider lanes (all against the local 12.2 install)

| Lane                           | Result                                                                                                                                                                   |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `verify-real-ghidra-riscv.mjs` | passed; ABI/double-float checks completed, `cleanup: "complete"`                                                                                                         |
| `verify-real-ghidra-m68k.mjs`  | passed; `ok: true`, `mocked: false`, provider `ghidra 12.2`, CLI/MCP load-image parity, misaligned/invalid mapping and session-preservation checks green                 |
| `verify-real-ghidra.mjs`       | ran 166 s through bridge compilation, debug/stripped native fixtures, DWARF type layout and inventory/switch assertions; **failed at the entry-aliases fixture** (below) |

Production CLI spot checks also passed against 12.2: `rea analyze`, `rea
search --kind procedures`, `rea function <name>` on a compiled ELF.

## Entry-aliases fixture finding (host-arch, not a 12.2 regression)

`verify-real-ghidra.mjs` fails at `real-ghidra-entry-aliases.mjs:155` with
`No procedure exists at the requested address: 0x10077d`. Reproduced
identically against the local Ghidra **12.1.3** install on this host, so it
is not a 12.2 behavioral change. Cause: on Linux aarch64 with GCC 16.1.1,
the fixture's `rea_interior` label lands one byte into a 4-byte NOP
(`1f 20 03 d5`), and neither Ghidra 12.1.3 nor 12.2 keeps the split-NOP
region inside the analyzed function body. The fixture's x86_64 split-NOP
form is what CI (x86_64 runners) verified. The same binary also defeats
IDA 9.4's auto-analysis of the same function, confirming a fixture/toolchain
interaction rather than an engine regression. A lane that completes on Linux
aarch64 needs either an arch-appropriate interior-label placement in
`tests/conformance/ghidra/entry-aliases.c` (maintainer decision; the
mid-instruction label is deliberate) or an explicit x86_64-only scoping of
that lane segment.

## Unverified for 12.2

- The x86_64 CI lanes (`ghidra-bridge-sources.yml` retargeted to the 12.2
  asset, `real-ghidra-windows.yml` renamed) have not run; the 12.2 zip
  SHA-256 recorded there comes from the GitHub release metadata.
- Windows P0 verification against 12.2 is pending; the historical 12.1.4/JDK
  21 run remains the evidence for that boundary
  (docs/providers/windows-ghidra-p0.md keeps the dated record).
- The PSP Allegrex extension metadata check requires an extension built for
  12.2; the pinned v21.4 (Ghidra 12.1.3) artifact is not rebuilt or verified.
- MIPS, PPC, DOL, checkpoints, seeds, project-coverage, decompile-timeout,
  decompiler-failure and noreturn lanes were not rerun tonight.
- Swift (macOS-only) remains unverified on 12.2.
