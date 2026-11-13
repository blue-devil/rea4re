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

/**
 * One admitted footer line. The legacy README form is unquoted; ILSpy.Mcp
 * v1.2.1 emits a quoted-JSON object whose extra keys (e.g. nextOffset) are
 * observations REA does not interpret.
 */
type Footer = {
  total: number;
  returned: number;
  truncated: boolean;
  offset: number;
};

/** Decode one `[pagination:...]` line; null when the line is not a footer. */
function parseFooterLine(line: string): Footer | null {
  const legacy = FOOTER_PATTERN.exec(line);
  if (legacy !== null) {
    return {
      total: Number(legacy[1]),
      returned: Number(legacy[2]),
      truncated: legacy[3] === "true",
      offset: Number(legacy[4]),
    };
  }
  if (!line.startsWith("[pagination:{")) return null;
  const decoded: Record<string, unknown> | null = (() => {
    try {
      // Strip the "[pagination:" prefix and the trailing "]".
      const parsed: unknown = JSON.parse(line.slice("[pagination:".length, -1));
      return typeof parsed === "object" && parsed !== null
        ? (parsed as Record<string, unknown>)
        : null;
    } catch {
      // Invalid JSON fails closed below, quoting the offending line.
      return null;
    }
  })();
  const total = decoded?.total;
  const returned = decoded?.returned;
  const truncated = decoded?.truncated;
  const offset = decoded?.offset;
  if (
    typeof total === "number" &&
    typeof returned === "number" &&
    typeof truncated === "boolean" &&
    typeof offset === "number"
  )
    return { total, returned, truncated, offset };
  throw new IlspyResponseParseError(line);
}

/** Split off the final line, keeping its preceding text and line endings intact. */
function splitLastLine(text: string): { rest: string; line: string } | null {
  const match = /(?:\r?\n)([^\r\n]*)\r?\n?$/.exec(text);
  if (match === null) {
    // The whole text is one unterminated line.
    return text.startsWith("[") ? { rest: "", line: text } : null;
  }
  return { rest: text.slice(0, match.index), line: match[1] ?? "" };
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
    let footer: Footer | null;
    try {
      footer = parseFooterLine(split.line);
    } catch (cause) {
      return err(cause as IlspyResponseParseError);
    }
    if (footer === null) {
      return err(new IlspyResponseParseError(split.line));
    }
    footers.unshift(split.line);
    rest = split.rest;
  }
  if (footers.length === 0) {
    return ok({ body: text, pagination: null, trailingFooters: [] });
  }
  const lastFooter = footers[footers.length - 1];
  if (lastFooter === undefined) {
    return ok({ body: text, pagination: null, trailingFooters: [] });
  }
  let last: Footer | null;
  try {
    last = parseFooterLine(lastFooter);
  } catch (cause) {
    return err(cause as IlspyResponseParseError);
  }
  if (last === null) {
    return err(new IlspyResponseParseError(lastFooter));
  }
  return ok({
    body: rest,
    pagination: {
      total: last.total,
      returned: last.returned,
      truncated: last.truncated,
      offset: last.offset,
    },
    trailingFooters: footers.slice(0, -1),
  });
}
