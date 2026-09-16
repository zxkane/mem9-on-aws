import { describe, expect, it } from "vitest";
import { assertSupportedMaintenanceConfiguration, UNSUPPORTED_MAINTENANCE_FLAGS } from "./maintenance-config";
describe("unsupported maintenance deployment configuration", () => {
  it.each(UNSUPPORTED_MAINTENANCE_FLAGS)("refuses enabled or malformed %s before resource construction", flag => {
    for (const value of ["1", "true", "invalid"]) expect(() => assertSupportedMaintenanceConfiguration({[flag]:value})).toThrow("not supported");
    for (const value of ["", "0", "false", undefined]) expect(() => assertSupportedMaintenanceConfiguration({[flag]:value})).not.toThrow();
  });
});
