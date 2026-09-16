import { describe, expect, it, vi } from "vitest";
import { validateServiceBinding, manageMemoryService } from "./manage-memory-services.mjs";
const namespace_id = "60000000-0000-4000-8000-000000000001";
describe("service administration input", () => {
  it.each([{}, {namespace_id,service:"sampler"}, {namespace_id,service:"cleanup",password:"invalid"}, {namespace_id:"all",service:"cleanup"}])("rejects invalid or internal-only service before database work", async binding => {
    const db={query:vi.fn()};
    expect(()=>validateServiceBinding(binding)).toThrow();
    await expect(manageMemoryService({db,command:"enable",binding})).rejects.toThrow();
    expect(db.query).not.toHaveBeenCalled();
  });
  it("accepts only the exact explicit binding shape",()=>{
    expect(validateServiceBinding({namespace_id,service:"cleanup"})).toEqual({namespace_id,service:"cleanup"});
  });
});
