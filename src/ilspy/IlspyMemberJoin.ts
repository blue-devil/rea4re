import { createHash } from "node:crypto";

import type { Result } from "../domain/result.js";
import { parseIlspyToolText } from "./IlspyMcpResponseParser.js";

import type { ManagedMemberInspection } from "../domain/managed/managedArtifact.js";
import type { ManagedReconstructionImportRequest } from "../domain/managed/managedReconstruction.js";

type Member = ManagedMemberInspection["methods"][number];

/** One upstream decompiled member text, already bound to a REA inspection token. */
export type IlspyMemberSelection = {
  token: string;
  text: string;
  kind: "decompiled-csharp" | "decompiled-il";
  truncated: boolean;
  /** Raw upstream reply retained when parsing failed, for hand-import. */
  readonly raw?: string;
  /** No admitted upstream text; excluded as upstream_failure. */
  readonly upstream_failure?: boolean;
};

/** Why one selection did not join; every selection joins or appears here exactly once. */
export type IlspyJoinExclusion = {
  token: string;
  declaring_type: string | null;
  name: string;
  reason:
    | "ambiguous_member_name"
    | "missing_normalized_il"
    | "empty_text"
    | "truncated_text"
    | "unknown_token"
    | "token_mismatch"
    | "upstream_failure";
};

type JoinResult = {
  request: ManagedReconstructionImportRequest;
  excluded: IlspyJoinExclusion[];
};

/** Members whose method name is unique within their declaring type; safe for name-keyed upstream calls. */
export function uniqueNameMethods(
  inspection: ManagedMemberInspection,
): ManagedMemberInspection["methods"] {
  const counts = new Map<string, number>();
  for (const method of inspection.methods) {
    const key = `${method.declaring_type ?? "\u0000"}::${method.name}`;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return inspection.methods.filter(
    (method) =>
      counts.get(`${method.declaring_type ?? "\u0000"}::${method.name}`) === 1,
  );
}

const exclusion = (
  selection: IlspyMemberSelection,
  row: Member | undefined,
  reason: IlspyJoinExclusion["reason"],
): IlspyJoinExclusion => ({
  token: selection.token,
  declaring_type: row?.declaring_type ?? null,
  name: row?.name ?? "",
  reason,
});

/**
 * Join upstream ILSpy decompilation text with REA's own member inspection
 * into an import-managed-reconstruction request, or per-member exclusions.
 * Pure: no I/O, no MCP calls; the caller attaches the static_members Evidence.
 */
export function buildIlspyReconstructionRequest(
  inspection: ManagedMemberInspection,
  selections: readonly IlspyMemberSelection[],
): JoinResult {
  const ambiguousTokens = new Set(
    uniqueNameMethods(inspection).map((method) => method.token),
  );
  const methods: NonNullable<JoinResult["request"]["methods"]> = [];
  const excluded: IlspyJoinExclusion[] = [];

  for (const selection of selections) {
    const row = inspection.methods.find(
      (method) => method.token === selection.token,
    );
    // Precedence: unknown_token, ambiguous_member_name, upstream_failure,
    // missing_normalized_il, truncated_text, empty_text, token_mismatch —
    // first match only.
    if (row === undefined) {
      excluded.push(exclusion(selection, row, "unknown_token"));
      continue;
    }
    if (!ambiguousTokens.has(selection.token)) {
      excluded.push(exclusion(selection, row, "ambiguous_member_name"));
      continue;
    }
    if (selection.upstream_failure === true) {
      excluded.push(exclusion(selection, row, "upstream_failure"));
      continue;
    }
    if (
      row.body.status !== "present" ||
      row.body.normalized_il_sha256 === null
    ) {
      excluded.push(exclusion(selection, row, "missing_normalized_il"));
      continue;
    }
    if (selection.truncated) {
      // Truncated upstream text is never admitted.
      excluded.push(exclusion(selection, row, "truncated_text"));
      continue;
    }
    if (selection.text.trim().length === 0) {
      excluded.push(exclusion(selection, row, "empty_text"));
      continue;
    }
    if (
      selection.kind === "decompiled-il" &&
      !new RegExp(
        `/\\*\\s*(?:0x)?${selection.token.slice(2)}\\s*\\*/`,
        "i",
      ).test(selection.text)
    ) {
      excluded.push(exclusion(selection, row, "token_mismatch"));
      continue;
    }
    methods.push({
      token: row.token,
      signature_sha256: row.signature.raw_sha256,
      normalized_il_sha256: row.body.normalized_il_sha256,
      reconstruction: {
        kind: selection.kind,
        language: selection.kind === "decompiled-csharp" ? "csharp" : "il",
        text: selection.text,
        text_sha256: createHash("sha256").update(selection.text).digest("hex"),
      },
    });
  }

  // The caller owns the decompiler identity and attaches static_members; the
  // joiner only supplies the token-locked methods payload.
  return {
    request: {
      decompiler: {
        name: "ilspy",
        version: null,
        family: "ilspy",
        executable_sha256: null,
        options: [],
      },
      methods,
      notes: [],
      static_members: undefined,
    } as unknown as JoinResult["request"],
    excluded,
  };
}

/** Decode one upstream reply into a selection; failures stay excluded. */
export const ilspySelectionFromToolReply = (
  call: Result<unknown, unknown>,
  token: string,
  kind: IlspyMemberSelection["kind"],
): IlspyMemberSelection => {
  if (!call.ok || typeof call.value !== "string")
    return { token, text: "", kind, truncated: false, upstream_failure: true };
  const parsed = parseIlspyToolText(call.value);
  if (!parsed.ok)
    return {
      token,
      text: "",
      kind,
      truncated: false,
      upstream_failure: true,
      raw: call.value,
    };
  return {
    token,
    text: parsed.value.body,
    kind,
    truncated: parsed.value.pagination?.truncated ?? false,
  };
};

/** One limitation line per excluded or ambiguous member, with its raw text. */
export const ilspyExclusionLines = (
  requested: readonly { readonly token: string; readonly name: string }[],
  candidateTokens: ReadonlySet<string>,
  excluded: readonly { readonly token: string; readonly reason: string }[],
  truncatedTexts: ReadonlyMap<string, string>,
): readonly string[] => {
  const reasons = new Map(excluded.map((item) => [item.token, item.reason]));
  return requested
    .filter(
      (method) =>
        !candidateTokens.has(method.token) || reasons.has(method.token),
    )
    .map((method) => {
      const reason =
        reasons.get(method.token) ??
        (candidateTokens.has(method.token)
          ? undefined
          : "ambiguous_member_name");
      if (reason === undefined) return null;
      const raw = truncatedTexts.get(method.token);
      return `Excluded ${method.name} (${method.token}): ${reason}${raw === undefined ? "" : `; raw text: ${raw}`}`;
    })
    .filter((line): line is string => line !== null);
};
