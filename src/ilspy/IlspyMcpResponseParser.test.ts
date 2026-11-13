import { describe, expect, it } from "vitest";
import {
  DECOMPILE_METHOD_RESPONSE,
  MALFORMED_FOOTER_RESPONSE,
  REAL_V121_JSON_FOOTER_RESPONSE,
  REAL_V121_JSON_FOOTER_TRUNCATED_RESPONSE,
  SEARCH_STRINGS_RESPONSE,
  TWO_FOOTER_RESPONSE,
} from "../../tests/fixtures/ilspyMcpResponses.js";
import { parseIlspyToolText } from "./IlspyMcpResponseParser.js";

describe("parseIlspyToolText", () => {
  it("parses a trailing pagination footer and removes it from the body", () => {
    const parsed = parseIlspyToolText(SEARCH_STRINGS_RESPONSE);
    if (!parsed.ok) throw parsed.error;
    expect(parsed.value.pagination).toEqual({
      total: 3,
      returned: 3,
      truncated: false,
      offset: 0,
    });
    expect(parsed.value.body).toBe(
      SEARCH_STRINGS_RESPONSE.slice(
        0,
        SEARCH_STRINGS_RESPONSE.lastIndexOf("[pagination:"),
      ).replace(/\r?\n$/, ""),
    );
    expect(parsed.value.trailingFooters).toEqual([]);
  });

  it("returns null pagination and a verbatim body without a footer", () => {
    const parsed = parseIlspyToolText(DECOMPILE_METHOD_RESPONSE);
    if (!parsed.ok) throw parsed.error;
    expect(parsed.value.pagination).toBeNull();
    expect(parsed.value.body).toBe(DECOMPILE_METHOD_RESPONSE);
    expect(parsed.value.trailingFooters).toEqual([]);
  });

  it("preserves truncated:true exactly", () => {
    const parsed = parseIlspyToolText(
      "Match: s\r\n[pagination:{total:10,returned:1,truncated:true,offset:1}]",
    );
    if (!parsed.ok) throw parsed.error;
    expect(parsed.value.pagination).toEqual({
      total: 10,
      returned: 1,
      truncated: true,
      offset: 1,
    });
    expect(parsed.value.body).toBe("Match: s");
  });

  it("fails closed on a malformed pagination footer, quoting the line", () => {
    const parsed = parseIlspyToolText(MALFORMED_FOOTER_RESPONSE);
    expect(parsed.ok).toBe(false);
    if (parsed.ok) throw new Error("expected failure");
    expect(parsed.error._tag).toBe("IlspyResponseParseError");
    expect(parsed.error.constraint).toContain("[pagination:{total:3]");
  });

  it("fails closed on an unknown trailing bracket footer", () => {
    const parsed = parseIlspyToolText("[foo:{a:1}]");
    expect(parsed.ok).toBe(false);
    if (parsed.ok) throw new Error("expected failure");
    expect(parsed.error.constraint).toContain("[foo:{a:1}]");
  });

  it("keeps the first of two trailing footers in trailingFooters", () => {
    const parsed = parseIlspyToolText(TWO_FOOTER_RESPONSE);
    if (!parsed.ok) throw parsed.error;
    expect(parsed.value.trailingFooters).toEqual([
      "[pagination:{total:1,returned:1,truncated:false,offset:0}]",
    ]);
    expect(parsed.value.pagination).toEqual({
      total: 3,
      returned: 3,
      truncated: false,
      offset: 0,
    });
  });

  it("splits CRLF footers and preserves original line endings in the body", () => {
    const text =
      "alpha\r\nbeta\r\n[pagination:{total:2,returned:2,truncated:false,offset:0}]";
    const parsed = parseIlspyToolText(text);
    if (!parsed.ok) throw parsed.error;
    expect(parsed.value.body).toBe("alpha\r\nbeta");
    expect(parsed.value.pagination).toEqual({
      total: 2,
      returned: 2,
      truncated: false,
      offset: 0,
    });
  });

  it("parses the recorded ILSpy.Mcp v1.2.1 quoted-JSON footer", () => {
    const parsed = parseIlspyToolText(REAL_V121_JSON_FOOTER_RESPONSE);
    if (!parsed.ok) throw parsed.error;
    expect(parsed.value.pagination).toEqual({
      total: 842,
      returned: 842,
      truncated: false,
      offset: 0,
    });
    expect(parsed.value.body).toBe(
      REAL_V121_JSON_FOOTER_RESPONSE.slice(
        0,
        REAL_V121_JSON_FOOTER_RESPONSE.lastIndexOf("[pagination:"),
      ).replace(/\r?\n$/, ""),
    );
    expect(parsed.value.trailingFooters).toEqual([]);
  });

  it("preserves truncated:true from the v1.2.1 quoted-JSON footer", () => {
    const parsed = parseIlspyToolText(REAL_V121_JSON_FOOTER_TRUNCATED_RESPONSE);
    if (!parsed.ok) throw parsed.error;
    expect(parsed.value.pagination).toEqual({
      total: 900,
      returned: 100,
      truncated: true,
      offset: 0,
    });
    expect(parsed.value.body).toBe('Match 1: "alpha" in A.Method');
  });

  it("fails closed on a quoted-JSON footer with a wrong value type", () => {
    const parsed = parseIlspyToolText(
      'body\n[pagination:{"total":"842","returned":1,"offset":0,"truncated":false}]',
    );
    expect(parsed.ok).toBe(false);
    if (parsed.ok) throw new Error("expected failure");
    expect(parsed.error.constraint).toContain('"total":"842"');
  });

  it("fails closed on a quoted-JSON footer with invalid JSON", () => {
    const parsed = parseIlspyToolText("body\n[pagination:{total:842,}]");
    expect(parsed.ok).toBe(false);
    if (parsed.ok) throw new Error("expected failure");
    expect(parsed.error.constraint).toContain("[pagination:{total:842,}]");
  });
});
