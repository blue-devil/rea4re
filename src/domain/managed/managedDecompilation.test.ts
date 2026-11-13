import { describe, expect, it } from "vitest";

import {
  managedDecompilationInputSchema,
  managedDecompilationResultSchema,
} from "./managedDecompilation.js";

const reconstruction = {
  kind: "decompiled-csharp" as const,
  language: "csharp" as const,
  text: "public static void Main() { }",
};

const resultExample = {
  decompiler: { name: "ilspy", version: "9.0.0.0", family: "ilspy" as const },
  assembly: { path: "/tmp/Example.dll", sha256: null },
  methods: [
    {
      token: "0x06000001",
      declaring_type: "Example.Program",
      name: "Main",
      status: "reconstructed" as const,
      reason: null,
      reconstruction,
    },
    {
      token: "0x06000002",
      declaring_type: null,
      name: "Skipped",
      status: "excluded" as const,
      reason: "ambiguous member name",
      reconstruction: null,
    },
  ],
  reconstruction: null,
  limitations: ["Decompiler output is analyst inference."],
};

describe("managedDecompilationInputSchema", () => {
  it("accepts a minimal valid request", () => {
    const parsed = managedDecompilationInputSchema.parse({
      assembly_path: "/tmp/Example.dll",
      declaring_type: "Example.Program",
    });
    expect(parsed.output_kind).toBe("decompiled-csharp");
    expect("member_names" in parsed).toBe(false);
  });

  it("accepts explicit member names and output kind", () => {
    expect(
      managedDecompilationInputSchema.parse({
        assembly_path: "/tmp/Example.dll",
        declaring_type: "Example.Program",
        member_names: ["Main"],
        output_kind: "decompiled-il",
      }),
    ).toEqual({
      assembly_path: "/tmp/Example.dll",
      declaring_type: "Example.Program",
      member_names: ["Main"],
      output_kind: "decompiled-il",
    });
  });

  it("rejects a relative assembly path", () => {
    expect(
      managedDecompilationInputSchema.safeParse({
        assembly_path: "Example.dll",
        declaring_type: "Example.Program",
      }).success,
    ).toBe(false);
  });

  it("rejects unknown fields", () => {
    expect(
      managedDecompilationInputSchema.safeParse({
        assembly_path: "/tmp/Example.dll",
        declaring_type: "Example.Program",
        extra: true,
      }).success,
    ).toBe(false);
  });

  it("rejects an empty declaring_type", () => {
    expect(
      managedDecompilationInputSchema.safeParse({
        assembly_path: "/tmp/Example.dll",
        declaring_type: "",
      }).success,
    ).toBe(false);
  });
});

describe("managedDecompilationResultSchema", () => {
  it("accepts a full result example", () => {
    expect(managedDecompilationResultSchema.parse(resultExample)).toEqual(
      resultExample,
    );
  });

  it("rejects unknown fields", () => {
    expect(
      managedDecompilationResultSchema.safeParse({
        ...resultExample,
        extra: 1,
      }).success,
    ).toBe(false);
  });

  it("rejects a non-ilspy decompiler family", () => {
    expect(
      managedDecompilationResultSchema.safeParse({
        ...resultExample,
        decompiler: { ...resultExample.decompiler, family: "dnspy" },
      }).success,
    ).toBe(false);
  });
});
