import {
  chmod,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import {
  acceptanceHttpEvents,
  humanTargetFingerprint,
  writePrivateRecord,
} from "./lib/human-namespace-records.mjs";

describe("human acceptance recovery and denial proof", () => {
  it("never replaces existing acceptance evidence, including cleanup-only", async () => {
    const dir = await mkdtemp(join(tmpdir(), "human-evidence-")),
      file = join(dir, "evidence.json");
    try {
      await writeFile(file, '{"success":false}', { mode: 0o600 });
      for (const extra of [[], ["--cleanup-only"]]) {
        const run = spawnSync(
          process.execPath,
          [
            resolve("scripts/run-human-namespace-e2e.mjs"),
            "--deployment-file",
            join(dir, "deployment.local.json"),
            "--fixtures-file",
            join(dir, "fixtures.local.json"),
            "--evidence-file",
            file,
            ...extra,
          ],
          { encoding: "utf8", timeout: 5000 },
        );
        expect(run.status).toBe(1);
        expect(run.stderr).toContain("evidence_file_already_exists");
        expect(await readFile(file, "utf8")).toBe('{"success":false}');
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
  it("binds recovery to immutable target identities without commit/readiness", () => {
    const m = {
      accountId: "123456789012",
      region: "ap-northeast-1",
      userPoolId: "fixture",
      database: { resourceId: "cluster-fixture", name: "mem9" },
      commit: "a".repeat(40),
    };
    const fp = humanTargetFingerprint(m, ["alpha", "beta"]);
    expect(
      humanTargetFingerprint({ ...m, commit: "b".repeat(40) }, [
        "alpha",
        "beta",
      ]),
    ).toBe(fp);
    for (const changed of [
      { ...m, userPoolId: "other" },
      { ...m, region: "us-west-2" },
      { ...m, database: { ...m.database, resourceId: "cluster-other" } },
    ])
      expect(humanTargetFingerprint(changed, ["alpha", "beta"])).not.toBe(fp);
    expect(humanTargetFingerprint(m, ["beta", "alpha"])).not.toBe(fp);
    expect(() => humanTargetFingerprint(m, ["alpha", "alpha"])).toThrow();
  });
  it("preserves the original record across a failed update and tightens replacement permissions", async () => {
    const dir = await mkdtemp(join(tmpdir(), "human-private-record-")),
      path = join(dir, "fixture.local.json");
    try {
      await writeFile(path, JSON.stringify({ value: "old" }), { mode: 0o600 });
      await expect(
        writePrivateRecord(
          path,
          { value: "new" },
          {
            beforeRename: () => {
              throw new Error("injected");
            },
          },
        ),
      ).rejects.toThrow("injected");
      expect(JSON.parse(await readFile(path, "utf8"))).toEqual({
        value: "old",
      });
      expect(await readdir(dir)).toEqual(["fixture.local.json"]);
      await chmod(path, 0o644);
      await writePrivateRecord(path, { value: "new" });
      expect((await stat(path)).mode & 0o077).toBe(0);
      expect(JSON.parse(await readFile(path, "utf8"))).toEqual({
        value: "new",
      });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
  it("correlates real target status records and does not treat arbitrary errors as denial", () => {
    const record = {
      event: "namespace_acceptance_http_error",
      request_hash: "a".repeat(64),
      status: 403,
    };
    expect(
      acceptanceHttpEvents(
        [{ message: "prefix INFO " + JSON.stringify(record) + "\n" }],
        record.request_hash,
      ),
    ).toEqual([403]);
    expect(
      acceptanceHttpEvents(
        [
          {
            message: JSON.stringify({
              message: JSON.stringify({ ...record, status: 500 }),
            }),
          },
        ],
        record.request_hash,
      ),
    ).toEqual([500]);
    expect(
      acceptanceHttpEvents(
        [
          { message: "An internal error occurred" },
          { message: JSON.stringify({ ...record, request_hash: "other" }) },
        ],
        record.request_hash,
      ),
    ).toEqual([]);
  });
});
