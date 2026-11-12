import type { RegexMatchingDeadline } from "../config/regexMatchingDeadline.js";
import type { RegexWorkerHeapRequest } from "../config/regexWorkerHeapRequest.js";
import { z } from "zod";
import {
  analysisSearchPredicate,
  analysisSearchQuerySchema,
  type AnalysisSearchQuery,
} from "../domain/analysisSearch.js";
import {
  matchRegexValues,
  launchRegexMatchingLimitation,
} from "../process/RegexMatcher.js";
import {
  AnalysisInputError,
  AnalysisCancelledError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import {
  functionDossierSchema,
  functionInstructionWindowSchema,
} from "../domain/native/functionDossier.js";
import type { JsonValue } from "../domain/jsonValue.js";
import type { RelationshipCoverage } from "../domain/relationshipCoverage.js";
import { combineFunctionRelationshipCoverage } from "../domain/functionCallCoverage.js";
import type { IdaMcpConnection } from "./IdaMcpConnection.js";
import type { IdaOperation } from "./IdaProviderCapabilities.js";
import { IDA_LIMITATIONS } from "./IdaProviderCapabilities.js";
import type { EvidenceLocation } from "../domain/evidence.js";
import { idaAddressSchema } from "./IdaProtocolValues.js";
import {
  parseExecutePythonResult,
  idaHexraysCode,
  inventoryResultSchema,
  stringsResultSchema,
  byNameResultSchema,
  containingResultSchema,
  pseudocodeResultSchema,
  instructionsResultSchema,
  callersResultSchema,
  calleesResultSchema,
  xrefsResultSchema,
  type ResolvedProcedure,
} from "./IdaHexraysProtocol.js";

/** One operation's raw source observations, retained alongside normalized results. */
export interface IdaRawObservation {
  readonly tool: string;
  readonly arguments: Readonly<Record<string, JsonValue>>;
  readonly result: JsonValue;
}

const unknownBody = {
  available: false,
  reason: "IDA MCP does not report complete function body ranges.",
} as const;
const identity = (fn: { address: string; name: string }) => ({
  address: fn.address,
  name: fn.name,
  symbol: null,
  classification: null,
  body: unknownBody,
});
interface IdaRelationships {
  readonly items: ReturnType<typeof identity>[];
  readonly coverage: RelationshipCoverage;
}

const UNKNOWN_COVERAGE: RelationshipCoverage = {
  status: "unknown",
  reason: "The upstream relationship response does not report coverage.",
};

/** Translate explicit analyst questions into closed read-only execute_python programs. */
export class IdaOperationRunner {
  readonly raw: IdaRawObservation[] = [];
  readonly locations: EvidenceLocation[] = [];
  readonly limitations: string[] = [];
  relationshipCoverage: RelationshipCoverage | undefined;
  constructor(
    private readonly connection: IdaMcpConnection,
    private readonly instanceId?: string,
    private readonly options: {
      readonly signal?: AbortSignal | undefined;
      readonly regexMatchingDeadline?: RegexMatchingDeadline | undefined;
      readonly regexWorkerHeapRequest?: RegexWorkerHeapRequest | undefined;
      readonly selectorOrigin?: "provider" | undefined;
      /** The program identity REA admitted, reported by `list_documents`. */
      readonly admittedDocument?: string;
      /** Whole-request budget for one execute_python call, in seconds. */
      readonly timeoutSeconds?: number | undefined;
    } = {},
  ) {}

  /** Run one builder program and parse its trailing expression fail-closed. */
  private async python<T>(
    code: string,
    schema: z.ZodType<T>,
    operation = "execute_python",
  ): Promise<T> {
    if (this.options.signal?.aborted)
      throw new AnalysisCancelledError(operation, {
        cause: this.options.signal.reason,
      });
    const args = {
      code,
      ...(this.instanceId === undefined
        ? {}
        : { instance_id: this.instanceId }),
      timeout: this.options.timeoutSeconds ?? 360,
    };
    const result = await this.connection.call("execute_python", args, {
      signal: this.options.signal,
    });
    this.raw.push({ tool: "execute_python", arguments: args, result });
    if (this.options.signal?.aborted)
      throw new AnalysisCancelledError(operation, {
        cause: this.options.signal.reason,
      });
    return schema.parse(parseExecutePythonResult(result));
  }

  async functions(): Promise<{ address: string; name: string }[]> {
    const { functions } = await this.python(
      idaHexraysCode.inventory(),
      inventoryResultSchema,
    );
    return functions.map(({ name, start }) => ({ address: start, name }));
  }

  /**
   * Resolves a procedure by exact name, or by entry/interior address when the
   * caller selects an explicit 0x address. When `requestedBy` names the
   * caller's operation, an unresolved selector is invalid input; every other
   * failed lookup stays a producer fault.
   */
  async resolve(
    query: string,
    requestedBy?: string,
  ): Promise<{ address: string; name: string }> {
    if (query.startsWith("file-offset:"))
      throw new AnalysisInputError(
        requestedBy ?? "procedure_address",
        undefined,
        [
          {
            path: ["procedure"],
            reason: "invalid_value",
            message:
              "IDA does not support file-offset: procedure selectors. Select Ghidra for source-file coordinates or supply an IDA analysis address or exact procedure name.",
          },
        ],
      );
    const address = idaAddressSchema.safeParse(
      /^0x/iu.test(query) ? query : undefined,
    );
    const resolved = address.success
      ? (
          await this.python(
            idaHexraysCode.containing(address.data),
            containingResultSchema,
          )
        ).match
      : await this.python(idaHexraysCode.byName(query), byNameResultSchema);
    if (resolved !== null) return resolved;
    const missing = address.success ? "not a function" : "not found";
    if (requestedBy === undefined)
      throw new AnalysisProtocolError(
        `IDA function lookup failed for ${query}: ${missing}`,
      );
    throw new AnalysisInputError(
      requestedBy,
      {
        cause: new AnalysisProtocolError(
          `IDA function lookup failed for ${query}: ${missing}`,
        ),
      },
      [
        {
          path: [],
          reason: "invalid_value",
          message: `IDA could not resolve procedure ${JSON.stringify(query)}: ${missing}.`,
        },
      ],
    );
  }

  /** The containing function of an address, or why none contains it. */
  private async containingProcedure(address: string): Promise<JsonValue> {
    const outcome = await this.python(
      idaHexraysCode.containing(address),
      containingResultSchema,
    );
    return {
      query_address: address,
      found: outcome.match !== null,
      procedure: outcome.match === null ? null : identity(outcome.match),
      ...(outcome.match === null
        ? {
            reason: outcome.outside
              ? ("outside_segments" as const)
              : ("not_in_procedure" as const),
          }
        : {}),
    };
  }

  async strings(): Promise<{ address: string; value: string }[]> {
    const { strings } = await this.python(
      idaHexraysCode.strings(),
      stringsResultSchema,
    );
    return strings.map(({ address, text }) => ({ address, value: text }));
  }

  /** Addressed instruction lines of one procedure, rendered "address: text". */
  async assembly(fn: { address: string }): Promise<string[]> {
    const { instructions } = await this.python(
      idaHexraysCode.instructions(fn.address),
      instructionsResultSchema,
    );
    return instructions.map(({ address, text }) => `${address}: ${text}`);
  }

  async pseudocode(fn: { address: string }): Promise<string> {
    const { text } = await this.python(
      idaHexraysCode.pseudocode(fn.address),
      pseudocodeResultSchema,
    );
    return text;
  }

  /** All references to an address, classified by the upstream xref predicates. */
  async xrefs(address: string): Promise<{ address: string; type: string }[]> {
    const { to } = await this.python(
      idaHexraysCode.xrefs(address),
      xrefsResultSchema,
    );
    return to.map(({ from, type }) => ({ address: from, type }));
  }

  async relationships(
    fn: { address: string },
    direction: "callers" | "callees",
  ): Promise<IdaRelationships> {
    if (direction === "callers") {
      const { callers } = await this.python(
        idaHexraysCode.callers(fn.address),
        callersResultSchema,
      );
      const items = callers.map(({ from, caller }) =>
        identity(caller ?? { address: from, name: `sub_${from.slice(2)}` }),
      );
      return { items, coverage: UNKNOWN_COVERAGE };
    }
    const { callees } = await this.python(
      idaHexraysCode.callees(fn.address),
      calleesResultSchema,
    );
    return {
      items: callees.map((callee: ResolvedProcedure) => identity(callee)),
      coverage: UNKNOWN_COVERAGE,
    };
  }

  private async searchItems<T extends { readonly value: string }>(
    operation: IdaOperation,
    items: T[],
    query: AnalysisSearchQuery | undefined,
  ): Promise<T[]> {
    if (query === undefined) return items;
    if (query.mode === "literal") {
      const matches = analysisSearchPredicate(query);
      return items.filter(({ value }) => matches(value));
    }
    this.limitations.push(
      launchRegexMatchingLimitation(
        this.options.regexMatchingDeadline,
        this.options.regexWorkerHeapRequest,
      ),
    );
    const matched = await matchRegexValues({
      operation,
      pattern: query.pattern,
      caseSensitive: query.case_sensitive,
      values: items.map(({ value }) => value),
      deadline: this.options.regexMatchingDeadline,
      heapRequest: this.options.regexWorkerHeapRequest,
      signal: this.options.signal,
    });
    if (!matched.ok) throw matched.error;
    const indices = new Set(matched.value);
    return items.filter((_, index) => indices.has(index));
  }

  async run(
    operation: IdaOperation,
    parameters: Readonly<Record<string, JsonValue>>,
  ): Promise<JsonValue> {
    const query =
      operation === "search_procedures" || operation === "search_strings"
        ? analysisSearchQuerySchema.parse(parameters)
        : undefined;
    if (operation === "list_procedures" || operation === "search_procedures") {
      const items = (await this.functions()).map((fn) => ({
        address: fn.address,
        value: fn.name,
      }));
      return this.searchItems(operation, items, query);
    }
    if (operation === "list_strings" || operation === "search_strings") {
      const selectedAddress =
        query === undefined && parameters.address !== undefined
          ? idaAddressSchema.parse(parameters.address)
          : undefined;
      const items = await this.strings();
      return query !== undefined
        ? this.searchItems(operation, items, query)
        : selectedAddress === undefined
          ? items
          : items.filter(({ address }) => address === selectedAddress);
    }
    if (operation === "list_documents") {
      if (this.options.admittedDocument === undefined)
        throw new AnalysisProtocolError("The admitted IDA program is unknown.");
      return [this.options.admittedDocument];
    }
    if (operation === "resolve_containing_procedure") {
      const queried = idaAddressSchema.parse(parameters.address);
      this.locations.push({ kind: "address", address: queried });
      return this.containingProcedure(queried);
    }
    if (operation === "xrefs") {
      const inspectedAddress = idaAddressSchema.parse(parameters.address);
      this.locations.push({ kind: "address", address: inspectedAddress });
      return (await this.xrefs(inspectedAddress)).map(({ address }) => address);
    }
    const fn = await this.resolve(
      z.string().min(1).parse(parameters.procedure),
      this.options.selectorOrigin === "provider" ? undefined : operation,
    );
    this.locations.push({ kind: "address", address: fn.address });
    switch (operation) {
      case "procedure_address":
        return fn.address;
      case "procedure_pseudo_code":
        return this.pseudocode(fn);
      case "procedure_assembly":
        return (await this.assembly(fn)).join("\n");
      case "procedure_callers":
      case "procedure_callees": {
        const relationships = await this.relationships(
          fn,
          operation === "procedure_callers" ? "callers" : "callees",
        );
        this.relationshipCoverage = relationships.coverage;
        return relationships.items.map(({ address }) => address);
      }
      case "read_function_instructions":
        return functionInstructionWindowSchema.parse({
          procedure: identity(fn),
          instructions: await this.assembly(fn),
          limitations: IDA_LIMITATIONS,
        });
      case "analyze_function":
        return this.dossier(fn);
    }
  }

  private async dossier(fn: {
    address: string;
    name: string;
  }): Promise<JsonValue> {
    const assembly = await this.assembly(fn);
    const pseudocode = await this.pseudocode(fn);
    const callers = await this.relationships(fn, "callers");
    const callees = await this.relationships(fn, "callees");
    this.relationshipCoverage = combineFunctionRelationshipCoverage(
      callers.coverage,
      callees.coverage,
    );
    return functionDossierSchema.parse({
      procedure: { ...identity(fn), signature: null, locals: [] },
      pseudocode,
      assembly,
      comments: [],
      callers: callers.items,
      callees: callees.items,
      incoming_references: [],
      outgoing_references: [],
      referenced_strings: [],
      referenced_names: [],
      basic_blocks: [],
      native_api: null,
      native_value_flow: null,
      facet_availability: {
        pseudocode: { available: true },
        assembly: { available: true },
        comments: {
          available: false,
          reason: "IDA adapter does not expose typed comments.",
        },
        callers: { available: true },
        callees: { available: true },
        references: {
          available: false,
          reason: "IDA adapter does not expose typed reference edges.",
        },
        strings_names: {
          available: false,
          reason:
            "IDA adapter does not expose function-referenced strings and names.",
        },
        cfg: {
          available: false,
          reason: "IDA adapter does not expose basic blocks.",
        },
      },
      limitations: [
        ...IDA_LIMITATIONS,
        ...this.limitations,
        "Stack frame records are not evidence of source locals. Rendered comments do not identify regular versus inline origin.",
      ],
    });
  }
}
