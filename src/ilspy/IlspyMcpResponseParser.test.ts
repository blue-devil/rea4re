import { describe, expect, it } from "vitest";
import {
  DECOMPILE_METHOD_RESPONSE,
  MALFORMED_FOOTER_RESPONSE,
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
});
