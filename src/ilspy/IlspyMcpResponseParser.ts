import { err, ok, type Result } from "../domain/result.js";

/** One parsed upstream pagination footer. */
export type IlspyPagination = {
  total: number;
  returned: number;
  truncated: boolean;
  offset: number;
};

/** Interpretation of one ILSpy-MCP plain-text tool response. */
export type IlspyToolText = {
  body: string;
  pagination: IlspyPagination | null;
  trailingFooters: string[];
};

/** The upstream response's trailing footer is not a valid pagination footer. */
export class IlspyResponseParseError extends Error {
  readonly _tag = "IlspyResponseParseError";
  constructor(readonly constraint: string) {
    super(`Unrecognized ILSpy-MCP response footer: ${constraint}`);
  }
}

const FOOTER_PATTERN =
  /^\[pagination:\{total:(\d+),returned:(\d+),truncated:(true|false),offset:(\d+)\}\]$/;

/** Split off the final line, keeping its preceding text and line endings intact. */
function splitLastLine(text: string): { rest: string; line: string } | null {
  const match = /(?:\r?\n)([^\r\n]*)\r?\n?$/.exec(text);
  if (match === null) {
    // The whole text is one unterminated line.
    return text.startsWith("[") ? { rest: "", line: text } : null;
  }
  return { rest: text.slice(0, match.index), line: match[1] };
}

/** Parse one ILSpy-MCP plain-text tool response, owning all upstream text interpretation. */
export function parseIlspyToolText(
  text: string,
): Result<IlspyToolText, IlspyResponseParseError> {
  const footers: string[] = [];
  let rest = text;
  for (;;) {
    const split = splitLastLine(rest);
    if (split === null) break;
    if (!split.line.startsWith("[")) break;
    const footer = FOOTER_PATTERN.exec(split.line);
    if (footer === null) {
      return err(new IlspyResponseParseError(split.line));
    }
    footers.unshift(split.line);
    rest = split.rest;
  }
  if (footers.length === 0) {
    return ok({ body: text, pagination: null, trailingFooters: [] });
  }
  const last = FOOTER_PATTERN.exec(footers[footers.length - 1]);
  if (last === null) {
    return err(new IlspyResponseParseError(footers[footers.length - 1]));
  }
  return ok({
    body: rest,
    pagination: {
      total: Number(last[1]),
      returned: Number(last[2]),
      truncated: last[3] === "true",
      offset: Number(last[4]),
    },
    trailingFooters: footers.slice(0, -1),
  });
}
