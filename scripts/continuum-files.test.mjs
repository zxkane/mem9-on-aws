import { chmod, mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { canonicalPaths, readPrivate, writePrivate } from "./deploy-continuum.mjs";

const directories = [];
async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), "continuum-state-"));
  directories.push(directory);
  return join(directory, "state.local.json");
}
afterEach(async () => { for (const dir of directories.splice(0)) await rm(dir, { recursive: true, force: true }); });

it("writes private state atomically and reads absent state explicitly", async () => {
  const path = await fixture();
  expect(await readPrivate(path, true)).toBeNull();
  await writePrivate(path, { phase: "creating" });
  expect((await stat(path)).mode & 0o777).toBe(0o600);
  await writePrivate(path, { phase: "bound", environmentId: "example" });
  expect(await readPrivate(path)).toEqual({ phase: "bound", environmentId: "example" });
});
it("rejects readable-by-others and symlink state without overwriting it", async () => {
  const path = await fixture();
  await writeFile(path, "{}", { mode: 0o600 });
  await chmod(path, 0o644);
  await expect(readPrivate(path)).rejects.toThrow(/private/);
  await expect(writePrivate(path, { changed: true })).rejects.toThrow(/private/);
  expect(await readFile(path, "utf8")).toBe("{}");
  const link = `${path}.link`;
  await symlink(path, link);
  await expect(readPrivate(link)).rejects.toThrow();
  await expect(writePrivate(link, {})).rejects.toThrow();
});

it("rejects parent-directory aliases that make plan overwrite state", async () => {
  const path = await fixture();
  await writePrivate(path, { phase: "bound" });
  const parent = dirname(path);
  const alias = `${parent}/alias`;
  await symlink(parent, alias);
  const config = join(parent, "config.json");
  await writeFile(config, "{}");
  await expect(canonicalPaths({ config, binding: join(parent, "binding.local.json"), state: path, plan: join(alias, "state.local.json") })).rejects.toThrow(/distinct/);
  expect(await readPrivate(path)).toEqual({ phase: "bound" });
  const result = await canonicalPaths({ config, binding: join(alias, "binding.local.json"), state: path, plan: join(alias, "plan.local.json") });
  expect(result.plan).toBe(join(parent, "plan.local.json"));
});
