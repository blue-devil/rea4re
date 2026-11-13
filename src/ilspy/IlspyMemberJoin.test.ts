import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import type { ManagedMemberInspection } from "../domain/managed/managedArtifact.js";
import { managedReconstructionImportInputSchema } from "../domain/managed/managedReconstruction.js";
import {
  buildIlspyReconstructionRequest,
  uniqueNameMethods,
  type IlspyMemberSelection,
} from "./IlspyMemberJoin.js";

const sha256Text = (value: string): string =>
  createHash("sha256").update(value).digest("hex");

type MethodRow = ManagedMemberInspection["methods"][number];

const methodRow = (
  token: string,
  declaringType: string | null,
  name: string,
  options: {
    status?: "present" | "partial" | "absent" | "malformed";
    normalizedIl?: string | null;
  } = {},
): MethodRow =>
  ({
    token,
    row_offset: 0,
    declaring_type_token: null,
    declaring_type: declaringType,
    name,
    rva: 0,
    impl_flags: 0,
    flags: 0,
    signature: { raw_sha256: sha256Text(`sig:${token}`) },
    body: {
      status: options.status ?? "present",
      header_format: "none",
      rva: 0,
      file_offset: null,
      max_stack: null,
      init_locals: null,
      local_var_sig_token: null,
      local_var_signature: null,
      il_size: 0,
      il_sha256: null,
      normalized_il_sha256:
        options.normalizedIl === undefined
          ? sha256Text(`il:${token}`)
          : options.normalizedIl,
      instruction_count: 0,
      decoded_instruction_count: 0,
      truncated_instructions: 0,
      opcode_counts: {},
      anchors: [],
      exception_regions: [],
      issue: null,
    },
  }) as unknown as MethodRow;

// Two declaring types; an overload pair in Demo.One; Alpha repeats across
// types but stays unique within each; one absent body; one null normalized IL.
const rows: MethodRow[] = [
  methodRow("0x06000001", "Demo.One", "Alpha"),
  methodRow("0x06000002", "Demo.One", "Beta", { normalizedIl: null }),
  methodRow("0x06000003", "Demo.One", "Gamma"),
  methodRow("0x06000004", "Demo.One", "Gamma"),
  methodRow("0x06000005", "Demo.Two", "Alpha"),
  methodRow("0x06000006", "Demo.Two", "Delta", { status: "absent" }),
  methodRow("0x06000007", null, "Solo"),
];

const inspection = { methods: rows } as ManagedMemberInspection;

const csharp = (
  token: string,
  text: string,
  truncated = false,
): IlspyMemberSelection => ({
  token,
  text,
  kind: "decompiled-csharp",
  truncated,
});

const il = (
  token: string,
  text: string,
  truncated = false,
): IlspyMemberSelection => ({ token, text, kind: "decompiled-il", truncated });

describe("uniqueNameMethods", () => {
  it("keeps only members whose name is unique within their declaring type", () => {
    expect(uniqueNameMethods(inspection).map((row) => row.token)).toEqual([
      "0x06000001",
      "0x06000002",
      "0x06000005",
      "0x06000006",
      "0x06000007",
    ]);
  });
});

describe("buildIlspyReconstructionRequest", () => {
  it("joins by token with lock values from inspection rows", () => {
    const { request, excluded } = buildIlspyReconstructionRequest(inspection, [
      csharp("0x06000001", "int Alpha() => 1;"),
    ]);
    expect(excluded).toEqual([]);
    expect(request.methods).toHaveLength(1);
    const method = request.methods[0]!;
    expect(method.token).toBe("0x06000001");
    expect(method.signature_sha256).toBe(sha256Text("sig:0x06000001"));
    expect(method.normalized_il_sha256).toBe(sha256Text("il:0x06000001"));
    expect(method.reconstruction).toEqual({
      kind: "decompiled-csharp",
      language: "csharp",
      text: "int Alpha() => 1;",
      text_sha256: sha256Text("int Alpha() => 1;"),
    });
  });

  it("excludes a selection whose token matches no inspection row", () => {
    const { excluded } = buildIlspyReconstructionRequest(inspection, [
      csharp("0x06000099", "orphan"),
    ]);
    expect(excluded).toEqual([
      {
        token: "0x06000099",
        declaring_type: null,
        name: "",
        reason: "unknown_token",
      },
    ]);
  });

  it("excludes both overloads sharing a name, matching the pre-filter", () => {
    const unique = new Set(
      uniqueNameMethods(inspection).map((row) => row.token),
    );
    const selections = [csharp("0x06000003", "a"), csharp("0x06000004", "b")];
    const { request, excluded } = buildIlspyReconstructionRequest(
      inspection,
      selections,
    );
    expect(excluded).toEqual([
      {
        token: "0x06000003",
        declaring_type: "Demo.One",
        name: "Gamma",
        reason: "ambiguous_member_name",
      },
      {
        token: "0x06000004",
        declaring_type: "Demo.One",
        name: "Gamma",
        reason: "ambiguous_member_name",
      },
    ]);
    expect(request.methods).toEqual([]);
    // Pre-filter equivalence: a caller that only selects unique-name members
    // reaches the same join outcome for the remaining members.
    const filtered = selections.filter((sel) => unique.has(sel.token));
    expect(filtered).toEqual([]);
  });

  it("excludes absent bodies and null normalized IL as missing_normalized_il", () => {
    const { excluded } = buildIlspyReconstructionRequest(inspection, [
      csharp("0x06000006", "text"),
      csharp("0x06000002", "text"),
    ]);
    expect(excluded.map((item) => [item.token, item.reason])).toEqual([
      ["0x06000006", "missing_normalized_il"],
      ["0x06000002", "missing_normalized_il"],
    ]);
  });

  it("never admits truncated text even when non-empty", () => {
    const { excluded } = buildIlspyReconstructionRequest(inspection, [
      csharp("0x06000001", "partial body…", true),
    ]);
    expect(excluded).toEqual([
      {
        token: "0x06000001",
        declaring_type: "Demo.One",
        name: "Alpha",
        reason: "truncated_text",
      },
    ]);
  });
});

describe("buildIlspyReconstructionRequest exclusions and batches", () => {
  it("excludes empty or whitespace-only text", () => {
    const { excluded } = buildIlspyReconstructionRequest(inspection, [
      csharp("0x06000001", ""),
      csharp("0x06000005", "  \n\t "),
    ]);
    expect(excluded.map((item) => item.reason)).toEqual([
      "empty_text",
      "empty_text",
    ]);
  });

  it("requires the member token comment in decompiled IL, case-insensitively", () => {
    const good = il("0x06000001", ".method /* 06000001 */ int Alpha() {}");
    const lower = il("0x06000005", ".method /* 06000005 */ int Alpha() {}");
    const missing = il("0x06000007", ".method void Solo() {}");
    const { request, excluded } = buildIlspyReconstructionRequest(inspection, [
      good,
      lower,
      missing,
    ]);
    expect(request.methods.map((method) => method.token)).toEqual([
      "0x06000001",
      "0x06000005",
    ]);
    expect(request.methods[0]!.reconstruction.language).toBe("il");
    expect(excluded).toEqual([
      {
        token: "0x06000007",
        declaring_type: null,
        name: "Solo",
        reason: "token_mismatch",
      },
    ]);
  });

  it("reports only the highest-precedence reason per selection", () => {
    const { excluded } = buildIlspyReconstructionRequest(inspection, [
      csharp("0x06000003", "x", true), // ambiguous beats truncated
      csharp("0x06000099", "  ", true), // unknown beats empty+truncated
      csharp("0x06000002", "", true), // missing IL beats truncated+empty
      il("0x06000006", "no token", true), // missing IL beats token_mismatch
    ]);
    expect(excluded.map((item) => [item.token, item.reason])).toEqual([
      ["0x06000003", "ambiguous_member_name"],
      ["0x06000099", "unknown_token"],
      ["0x06000002", "missing_normalized_il"],
      ["0x06000006", "missing_normalized_il"],
    ]);
  });

  it("splits a mixed batch and tolerates zero selections without throwing", () => {
    const { request, excluded } = buildIlspyReconstructionRequest(inspection, [
      csharp("0x06000001", "one"),
      csharp("0x06000005", "two"),
      csharp("0x06000004", "overload"),
      csharp("0x06000099", "orphan"),
    ]);
    expect(request.methods.map((method) => method.token)).toEqual([
      "0x06000001",
      "0x06000005",
    ]);
    expect(excluded.map((item) => item.token)).toEqual([
      "0x06000004",
      "0x06000099",
    ]);
    const empty = buildIlspyReconstructionRequest(inspection, []);
    expect(empty.request.methods).toEqual([]);
    expect(empty.excluded).toEqual([]);
  });

  it("produces methods that validate against the import request shape", () => {
    const { request } = buildIlspyReconstructionRequest(inspection, [
      csharp("0x06000001", "int Alpha() => 1;"),
      il("0x06000005", "/* 06000005 */ ldarg.0"),
    ]);
    expect(() =>
      managedReconstructionImportInputSchema.shape.methods.parse(
        request.methods,
      ),
    ).not.toThrow();
  });
});
