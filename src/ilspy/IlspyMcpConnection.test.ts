import { PassThrough } from "node:stream";

import { describe, expect, it } from "vitest";

import { drainIlspyStderr } from "./IlspyMcpConnection.js";

describe("drainIlspyStderr", () => {
  it("attaches a data drain on a piped stderr stream", () => {
    const stderr = new PassThrough();
    expect(stderr.listenerCount("data")).toBe(0);
    drainIlspyStderr(stderr);
    expect(stderr.listenerCount("data")).toBe(1);
  });

  it("tolerates an absent stderr stream", () => {
    expect(() => {
      drainIlspyStderr(undefined);
      drainIlspyStderr(null);
    }).not.toThrow();
  });

  it("keeps large server stderr flowing without error", async () => {
    const stderr = new PassThrough();
    drainIlspyStderr(stderr);
    const errors: Error[] = [];
    stderr.on("error", (error: Error) => errors.push(error));
    for (let index = 0; index < 200; index++)
      stderr.write(`server diagnostic ${index} ${"x".repeat(512)}\n`);
    stderr.end();
    // A drained stream never accumulates its whole backlog in the buffer.
    expect(stderr.readableLength).toBeLessThan(200 * 512);
    const ended = new Promise<void>((resolve) => stderr.once("end", resolve));
    await ended;
    expect(errors).toEqual([]);
  });
});
