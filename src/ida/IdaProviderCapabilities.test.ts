import { describe, expect, it } from "vitest";
import { IDA_COMPATIBILITY_PROFILES } from "./IdaConfiguration.js";
import { idaCapabilities } from "./IdaProviderCapabilities.js";
import { IDA_OPERATIONS } from "./IdaProviderMetadata.js";

describe("IDA profile operation admission", () => {
  for (const [name, profile] of Object.entries(IDA_COMPATIBILITY_PROFILES)) {
    it(`advertises every operation as available in the ${name} profile without UI effects`, () => {
      const capabilities = idaCapabilities(profile, false);
      expect(capabilities.map(({ operation }) => operation).sort()).toEqual(
        [...IDA_OPERATIONS].sort(),
      );
      for (const capability of capabilities) {
        expect(capability.available).toBe(true);
        expect(capability.reason).toBeNull();
        expect(capability.effects.mayShowUi).toBe(false);
        expect(capability.cachePolicy).toBe("live");
      }
    });
    it(`declares headless process and filesystem effects only when stdio or headless in ${name}`, () => {
      const stdio = idaCapabilities(profile, true);
      const http = idaCapabilities(profile, false);
      expect(stdio.every(({ effects }) => effects.launchesProcess)).toBe(true);
      expect(
        http.every(
          ({ effects }) => effects.launchesProcess === (name === "headless"),
        ),
      ).toBe(true);
    });
  }
});
