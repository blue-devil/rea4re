import { describe, expect, it } from "vitest";
import type { JsonValue } from "../domain/jsonValue.js";
import type { IlspyMcpRegistration } from "./IlspyMcpConfiguration.js";
import { ConfigurationError } from "../domain/configurationErrors.js";
import { createIlspyMcpConnection } from "./IlspyMcpConnection.js";
import {
  IlspyCleanupError,
  IlspyMcpSessionClient,
  REQUIRED_ILSPY_TOOLS,
} from "./IlspyMcpSessionClient.js";
/** Programmable fake seam: records calls, owns a child-alive flag for close. */
class FakeIlspyConnection {
  tools: readonly string[] = [...REQUIRED_ILSPY_TOOLS];
  connectCalls = 0;
  calls: readonly (readonly [string, unknown])[] = [];
  connectError: Error | undefined;
  closeError: Error | undefined;
  childAlive = false;
  serverInfoValue: JsonValue = { version: "1.2.3-test" };
  async connect(): Promise<readonly string[]> {
    this.connectCalls++;
    if (this.connectError !== undefined) throw this.connectError;
    this.childAlive = true;
    return this.tools;
  }
  async call(name: string, args: unknown): Promise<JsonValue> {
    this.calls.push([name, args]);
    return { name };
  }
  serverInfo(): JsonValue {
    return this.serverInfoValue;
  }
  detach(): void {}
  async close(): Promise<void> {
    if (!this.childAlive) return;
    if (this.closeError !== undefined) throw this.closeError;
    this.childAlive = false;
  }
}

const summary = "ilspy stdio registration (redacted)";

const session = (
  connection: FakeIlspyConnection = new FakeIlspyConnection(),
) => ({ connection, client: new IlspyMcpSessionClient(connection, summary) });

describe("IlspyMcpSessionClient", () => {
  it("open connects once, records admitted tools and returns serverVersion", async () => {
    const { connection, client } = session();
    const result = await client.open();
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected open success");
    expect(result.value.tools).toEqual([...REQUIRED_ILSPY_TOOLS]);
    expect(result.value.serverVersion).toBe("1.2.3-test");
    expect(connection.connectCalls).toBe(1);
  });

  it("refuses startup when the live catalog lacks a required tool, then refuses member calls", async () => {
    const fake = new FakeIlspyConnection();
    fake.tools = ["decompile_method"];
    const { client } = session(fake);
    const result = await client.open();
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected startup failure");
    const diagnostic = JSON.stringify(result.error.diagnostics);
    expect(diagnostic).toContain("disassemble_method");
    expect(diagnostic).not.toContain("decompile_method");
    const call = await client.callTool("decompile_method", {});
    expect(call.ok).toBe(false);
  });

  it("maps a tools/list transport failure to a typed startup failure without retry", async () => {
    const fake = new FakeIlspyConnection();
    fake.connectError = new Error("connection refused");
    const { connection, client } = session(fake);
    const result = await client.open();
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected startup failure");
    expect(result.error.message).toContain("ILSpy MCP startup failed");
    expect(connection.connectCalls).toBe(1);
  });

  it("fails closed when callTool names a tool outside the admitted catalog", async () => {
    const fake = new FakeIlspyConnection();
    fake.tools = ["decompile_method", "disassemble_method", "extra_tool"];
    const { connection, client } = session(fake);
    await client.open();
    const result = await client.callTool("not_admitted", {});
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected refusal");
    expect(result.error.message).toContain("not_admitted");
    expect(connection.calls).toHaveLength(0);
  });

  it("serializes concurrent callTool invocations", async () => {
    const fake = new FakeIlspyConnection();
    fake.tools = [...REQUIRED_ILSPY_TOOLS, "first", "second"];
    const order: string[] = [];
    const originalCall = fake.call.bind(fake);
    fake.call = async (name: string, args: unknown) => {
      order.push(`start:${name}`);
      const { promise, resolve } = Promise.withResolvers<void>();
      queueMicrotask(resolve);
      await promise;
      order.push(`end:${name}`);
      return originalCall(name, args);
    };
    const { client } = session(fake);
    await client.open();
    await Promise.all([
      client.callTool("second", {}),
      client.callTool("first", {}),
    ]);
    expect(order).toEqual([
      "start:second",
      "end:second",
      "start:first",
      "end:first",
    ]);
  });

  it("close terminates a live child and a second close is a no-op", async () => {
    const fake = new FakeIlspyConnection();
    const { client } = session(fake);
    await client.open();
    expect(fake.childAlive).toBe(true);
    await client.close();
    expect(fake.childAlive).toBe(false);
    await expect(client.close()).resolves.toBeUndefined();
  });

  it("throws IlspyCleanupError with cleanupResources when the child survives close", async () => {
    const fake = new FakeIlspyConnection();
    fake.closeError = new Error("child refused termination");
    const { client } = session(fake);
    await client.open();
    let caught: unknown;
    try {
      await client.close();
    } catch (cause: unknown) {
      caught = cause;
    }
    expect(caught).toBeInstanceOf(IlspyCleanupError);
    const failure = caught as IlspyCleanupError;
    expect(failure.cleanupResources?.[0]).toContain("ILSpy MCP");
  });

  it("refuses to construct a connection for an http registration in phase one", () => {
    const registration: IlspyMcpRegistration = {
      type: "http",
      url: "http://127.0.0.1:3000/mcp",
      sensitive: { headers: [], env: [] },
      timeoutMs: 300000,
    };
    expect(() =>
      createIlspyMcpConnection(registration, registration.timeoutMs),
    ).toThrow(ConfigurationError);
    expect(() =>
      createIlspyMcpConnection(registration, registration.timeoutMs),
    ).toThrow(/stdio/);
  });

  it("never includes a sensitive.env value in diagnostics built from the summary", async () => {
    const fake = new FakeIlspyConnection();
    fake.connectError = new Error("secret-value-hunter2 leaked");
    const secretClient = new IlspyMcpSessionClient(
      fake,
      "ilspy registration (values redacted)",
    );
    const result = await secretClient.open();
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected startup failure");
    const diagnostic = JSON.stringify(result.error.diagnostics);
    expect(diagnostic).not.toContain("hunter2");
    expect(diagnostic).toContain("ilspy registration (values redacted)");
  });
});
