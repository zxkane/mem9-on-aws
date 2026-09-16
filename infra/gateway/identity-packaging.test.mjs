import { execFileSync } from "node:child_process";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";

const gateway = dirname(fileURLToPath(import.meta.url));
const infra = dirname(gateway);
const dependencies = Object.keys(
  JSON.parse(readFileSync(join(infra, "package.json"))).dependencies,
);

// Deploy jobs install only infra dependencies. An isolated module graph prevents
// root node_modules from hiding a missing Lambda runtime dependency in CI.
function importDeployment({ omitVerifier = false } = {}) {
  const directory = mkdtempSync(join(tmpdir(), "mem9-identity-package-"));
  try {
    cpSync(gateway, join(directory, "gateway"), {
      recursive: true,
      filter: (source) => !source.endsWith(".test.mjs"),
    });
    for (const name of dependencies) {
      if (omitVerifier && name === "aws-jwt-verify") continue;
      const destination = join(directory, "node_modules", name);
      mkdirSync(dirname(destination), { recursive: true });
      symlinkSync(join(infra, "node_modules", name), destination, "dir");
    }
    const entry = pathToFileURL(
      join(directory, "gateway", "identity-interceptor.mjs"),
    ).href;
    return execFileSync(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `const {handler} = await import(${JSON.stringify(entry)}); if (typeof handler !== 'function') process.exit(1);`,
      ],
      { cwd: directory, encoding: "utf8", timeout: 5000, stdio: "pipe" },
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

describe("identity interceptor deployment dependencies", () => {
  it("loads using only the infra runtime dependency graph", () => {
    expect(() => importDeployment()).not.toThrow();
  });
  it("detects a missing verifier even when the root package has it installed", () => {
    expect(() => importDeployment({ omitVerifier: true })).toThrow(
      /aws-jwt-verify/,
    );
  });
});
