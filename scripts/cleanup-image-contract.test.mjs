// The llm-proxy image is the runtime for BOTH the weekly consolidation task and
// the Slack-triggered cleanup apply task (#123). Those entrypoints are COPYd in
// from scripts/, so their import graph is a contract with
// docker/llm-proxy/package.json that nothing else checks: a `node_modules` that
// satisfies the sidecar can still be missing a client the entrypoint reaches, and
// the failure is a MODULE_NOT_FOUND at task start — after the operator's click has
// already been claimed and spent.
//
// Kin to TC-CONSOL-045 (scripts/run-consolidation-task.test.mjs), which pins the
// entrypoint PATHS across the same three files. This pins the DEPENDENCIES.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const root = new URL("..", import.meta.url);
const read = (rel) => readFileSync(new URL(rel, root), "utf8");

const imagePackage = JSON.parse(read("docker/llm-proxy/package.json"));
const imageLock = JSON.parse(read("docker/llm-proxy/package-lock.json"));
const dockerfile = read("docker/llm-proxy/Dockerfile");

/**
 * Every bare module specifier a source file can import, static or dynamic.
 *
 * Dynamic `import()` is the shape that matters most here: every AWS client in
 * these entrypoints is imported lazily so the operator CLI pays for only the ones
 * its flags reach, which also means a missing one is invisible until the exact
 * code path runs. A static-import-only check would have passed while the apply
 * task died on `await import("@aws-sdk/client-ssm")`.
 *
 * Bare = not relative, not absolute, not `node:` — i.e. resolved from
 * node_modules, which is the only thing `npm ci` in the image controls.
 */
function bareSpecifiers(source) {
  const specifiers = new Set();
  for (const match of source.matchAll(
    /(?:\bfrom\s*|\bimport\s*\(\s*)["']([^"']+)["']/gu,
  )) {
    const specifier = match[1];
    if (/^[./]/u.test(specifier) || specifier.startsWith("node:")) continue;
    // The pattern matches inside comments too, which is deliberate — over-inclusion
    // only ever asks the image to ship one more package — but prose reaches it that
    // way as well (`// from "a concurrent write protected me"`). Keep only strings
    // shaped like a module specifier; anything a package name cannot contain is not
    // one, and no valid specifier is excluded by this.
    if (!/^(?:@[\w.-]+\/)?[\w.-]+(?:\/[\w.-]+)*$/u.test(specifier)) continue;
    // A subpath import (`pkg/sub`) is satisfied by the PACKAGE, so compare on the
    // package name. Scoped names carry one slash before the package name.
    const parts = specifier.split("/");
    specifiers.add(
      specifier.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0],
    );
  }
  return specifiers;
}

/**
 * The files the image runs: the sidecar plus everything copied under
 * /app/scripts/. Derived from the Dockerfile rather than hardcoded, so a new
 * entrypoint is covered the moment it is copied in.
 */
function copiedEntrypoints() {
  return [
    ...dockerfile.matchAll(
      /^COPY\s+(scripts\/[^/\s]+\.mjs)\s+\/app\/scripts\/[^/\s]+$/gmu,
    ),
  ].map((match) => match[1]);
}

function relativeSpecifiers(source) {
  return [
    ...source.matchAll(
      /(?:\bfrom\s*|\bimport\s*\(\s*)["'](\.\.?\/[^"']+)["']/gu,
    ),
  ].map((match) => match[1]);
}

describe("the llm-proxy image can run the entrypoints copied into it (TC-SLACKAPP-099)", () => {
  it("ships every module the copied entrypoints import", () => {
    const entrypoints = copiedEntrypoints();
    // A vacuous pass is the failure mode of a Dockerfile-derived list: if the COPY
    // regex ever stops matching, an empty list satisfies every assertion below.
    expect(entrypoints).toContain("scripts/memory-cleanup.mjs");
    expect(entrypoints).toContain("scripts/memory-consolidation.mjs");

    const shipped = new Set(Object.keys(imagePackage.dependencies));
    const missing = [];
    for (const relative of [...entrypoints, "docker/llm-proxy/server.mjs"]) {
      for (const specifier of bareSpecifiers(read(relative))) {
        if (!shipped.has(specifier)) missing.push(`${relative} -> ${specifier}`);
      }
    }
    // Asserted over EVERY specifier rather than only the ones the task's own argv
    // reaches. Reachability is the wrong question because the two errors are not
    // symmetric: shipping a client no code path takes costs image bytes, while
    // omitting one a path does take kills the run after the approval is spent. The
    // cheap rule is "if the file can name it, the image has it".
    expect(missing).toEqual([]);
  });

  it("ships every relative module in the copied entrypoints' static graph", () => {
    for (const relative of copiedEntrypoints()) {
      for (const specifier of relativeSpecifiers(read(relative))) {
        const resolved = new URL(specifier, new URL(relative, root));
        const sourcePath = resolved.pathname.slice(root.pathname.length);
        expect(
          dockerfile,
          `${relative} imports an image file that is not copied: ${sourcePath}`,
        ).toContain(`COPY ${sourcePath} /app/${sourcePath}`);
      }
    }
  });

  it("keeps the lockfile in agreement so `npm ci` cannot fail the image build", () => {
    // `npm ci` REFUSES to install when package.json and the lockfile disagree, so
    // adding a dependency without regenerating the lock does not produce a thinner
    // image — it produces no image at all, discovered in CI rather than here.
    expect(imageLock.packages[""].dependencies).toEqual(
      imagePackage.dependencies,
    );
  });

  it("fails the image build, not the run, when an entrypoint's static graph breaks", () => {
    // The existing guard covers consolidation only. It catches the class of bug
    // that produced it (a flattened COPY breaking `../docker/llm-proxy/server.mjs`),
    // and that import is shared by both entrypoints — but the guard is per-file, so
    // an entrypoint without one is unverified at build time.
    //
    // Static graph only: a `RUN node -e "await import(...)"` never executes the
    // lazy `import()` calls, which is exactly why the dependency assertion above
    // exists alongside it.
    for (const relative of copiedEntrypoints()) {
      const containerPath = `/app/${relative}`;
      expect(
        dockerfile.includes(`await import('${containerPath}')`),
        `${relative} has no build-time import guard`,
      ).toBe(true);
    }
  });
});
