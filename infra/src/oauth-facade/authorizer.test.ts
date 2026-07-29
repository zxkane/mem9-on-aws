import { describe, expect, it } from "vitest";

import { handler } from "./authorizer.js";

describe("OAuth facade compliance authorizer", () => {
  it("TC-FACADEAUTH-003: authorizes every request", async () => {
    await expect(handler()).resolves.toEqual({ isAuthorized: true });
  });
});
