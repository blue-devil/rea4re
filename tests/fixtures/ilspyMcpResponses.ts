/**
 * Recorded-shape ILSpy-MCP response fixtures, modeled on the upstream
 * ILSpy-MCP README examples and its docs/PAGINATION.md footer contract.
 */

/** A search_strings response ending in the pagination footer. */
export const SEARCH_STRINGS_RESPONSE = `Match 1: "Hello, world!" in Program.Core.DoWork (iloffset 0x002a)
Match 2: "Hello, world!" in Program..ctor (iloffset 0x0007)
Match 3: "Hello, world!" in ProgramTests.Works (iloffset 0x0011)
[pagination:{total:3,returned:3,truncated:false,offset:0}]
`;

/** A decompile_method response: plain C# body, no pagination footer. */
export const DECOMPILE_METHOD_RESPONSE = `using System;

namespace Demo;

public class Greeter
{
    public string Greet(string name) => $"Hello, {name}!";
}
`;

/** A response whose trailing pagination footer is malformed. */
export const MALFORMED_FOOTER_RESPONSE = `Match 1: "flag" in Program.Main
[pagination:{total:3]
`;

/** An exotic response carrying two trailing footers; only the last is live. */
export const TWO_FOOTER_RESPONSE = `Match 1: "alpha" in A.Method
[pagination:{total:1,returned:1,truncated:false,offset:0}]
[pagination:{total:3,returned:3,truncated:false,offset:0}]
`;
