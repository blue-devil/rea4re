import { z } from "zod";

import { absoluteLocalPathStringSchema } from "../localPath.js";
import { managedMetadataTokenSchema } from "./managedArtifact.js";
import {
  managedReconstructionImportResultSchema,
  managedReconstructionObjectSchema,
} from "./managedReconstruction.js";

/** Caller boundary for decompiling selected managed members via BYO ILSpy-MCP. */
export const managedDecompilationInputSchema = z.strictObject({
  assembly_path: absoluteLocalPathStringSchema.describe(
    "Explicit absolute managed PE/CLI path holding the declaring type",
  ),
  declaring_type: z
    .string()
    .min(1)
    .describe(
      "Exact declaring-type full_name whose members are decompiled; nested types report their bare name",
    ),
  member_names: z
    .array(z.string().min(1))
    .meta({ uniqueItems: true })
    .describe(
      "Decompile only these member names; omit to decompile every member of the declaring type. Same-name members are refused as ambiguous.",
    )
    .optional(),
  output_kind: z
    .enum(["decompiled-csharp", "decompiled-il"])
    .default("decompiled-csharp"),
});

/** Evidence result of one managed decompilation operation. */
export const managedDecompilationResultSchema = z.strictObject({
  decompiler: z.strictObject({
    name: z.string().min(1),
    version: z.string().nullable(),
    family: z.literal("ilspy"),
  }),
  assembly: z.strictObject({
    path: z.string().min(1),
    sha256: z
      .string()
      .regex(/^[0-9a-f]{64}$/u)
      .nullable(),
  }),
  methods: z.array(
    z.strictObject({
      token: managedMetadataTokenSchema,
      declaring_type: z.string().nullable(),
      name: z.string().min(1),
      status: z.enum(["reconstructed", "excluded"]),
      reason: z.string().nullish(),
      reconstruction: managedReconstructionObjectSchema.nullish(),
    }),
  ),
  /** Present when at least one method joined and reconstruction Evidence was recorded. */
  reconstruction: managedReconstructionImportResultSchema.nullish(),
  limitations: z.array(z.string()),
});
