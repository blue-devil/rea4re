import { z } from "zod";

/** Normalize an IDA hexadecimal coordinate without passing through a JavaScript number. */
export const idaAddressSchema = z
  .string()
  .regex(/^(?:0x)?[0-9a-f]+$/iu)
  .transform(
    (value) =>
      `0x${BigInt(value.startsWith("0x") || value.startsWith("0X") ? value : `0x${value}`).toString(16)}`,
  );
