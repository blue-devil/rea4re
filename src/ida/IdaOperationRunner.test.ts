import { rm } from "node:fs/promises";
import { expect, it } from "vitest";
import {
  createIdaTarget,
  RecordingIdaMcp,
  reaOpOf,
} from "../../tests/fixtures/idaMcp.js";
import { IdaOperationRunner } from "./IdaOperationRunner.js";
import type { JsonValue } from "../domain/jsonValue.js";

const runnerOver = (
  producer: RecordingIdaMcp,
  op: string,
  reply: () => JsonValue,
) => {
  producer.overrideCall = (name, args) =>
    name === "execute_python" && reaOpOf(args.code) === op
      ? { result: reply(), stdout: "", stderr: "" }
      : undefined;
};

it("validates string address selectors independently of inventory contents", async () => {
  const { root, target } = await createIdaTarget();
  const producer = new RecordingIdaMcp(target);
  const runner = new IdaOperationRunner(producer);
  try {
    runnerOver(producer, "strings", () => ({
      strings: [
        { address: "0x10", length: 8, text: "selected" },
        { address: "0x20", length: 5, text: "other" },
      ],
    }));
    const callsBeforeInvalidSelector = producer.calls.length;
    await expect(
      runner.run("list_strings", { address: "invalid" }),
    ).rejects.toThrow();
    expect(producer.calls).toHaveLength(callsBeforeInvalidSelector);
    expect(await runner.run("list_strings", { address: "0X0010" })).toEqual([
      { address: "0x10", value: "selected" },
    ]);
  } finally {
    await producer.close();
    await rm(root, { recursive: true, force: true });
  }
});

it("procedure resolution rejects file coordinates before any symbol lookup", async () => {
  const { root, target } = await createIdaTarget();
  const producer = new RecordingIdaMcp(target);
  const runner = new IdaOperationRunner(producer);
  try {
    await expect(
      runner.resolve("file-offset:0x10", "procedure_pseudo_code"),
    ).rejects.toMatchObject({
      _tag: "AnalysisInputError",
      operation: "procedure_pseudo_code",
      issues: [
        {
          path: ["procedure"],
          message: expect.stringContaining("source-file coordinates"),
        },
      ],
    });
    expect(producer.calls).toEqual([]);
    expect((await runner.resolve("main")).name).toBe("main");
  } finally {
    await producer.close();
    await rm(root, { recursive: true, force: true });
  }
});

it("preserves function identities from the inventory in raw observations", async () => {
  const { root, target } = await createIdaTarget();
  const producer = new RecordingIdaMcp(target);
  const runner = new IdaOperationRunner(producer);
  try {
    expect(await runner.run("list_procedures", {})).toEqual([
      { address: "0x1000", value: "main" },
    ]);
    expect(await runner.resolve("main")).toEqual({
      address: "0x1000",
      name: "main",
    });
    expect(await runner.xrefs("0x1000")).toEqual([
      { address: "0x1004", type: "call" },
    ]);
    const instructions = await runner.run("read_function_instructions", {
      procedure: "main",
    });
    expect(instructions).toMatchObject({
      procedure: {
        address: "0x1000",
        name: "main",
        body: {
          available: false,
          reason: expect.stringContaining("complete function body ranges"),
        },
      },
    });
    expect(runner.raw).toContainEqual(
      expect.objectContaining({
        tool: "execute_python",
        result: expect.objectContaining({ stdout: "" }),
      }),
    );
  } finally {
    await producer.close();
    await rm(root, { recursive: true, force: true });
  }
});

it("fails closed when the producer omits required inventory fields", async () => {
  const { root, target } = await createIdaTarget();
  const producer = new RecordingIdaMcp(target);
  const runner = new IdaOperationRunner(producer);
  try {
    runnerOver(producer, "inventory", () => ({
      functions: [{ name: "main" }],
    }));
    await expect(runner.functions()).rejects.toThrow();
    runnerOver(producer, "by_name", () => ({ name: "main" }));
    await expect(runner.resolve("main")).rejects.toThrow();
  } finally {
    await producer.close();
    await rm(root, { recursive: true, force: true });
  }
});
