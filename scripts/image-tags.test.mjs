import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";

import { selectImageTags } from "./image-tags.mjs";

const SHA = "abcdef0123456789abcdef0123456789abcdef01";
const tempDirs = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("selectImageTags", () => {
  it.each([
    ["push", { releaseTag: "mem9-abcdef0", tags: ["mem9-abcdef0", "latest"] }],
    [
      "workflow_dispatch",
      { releaseTag: "mem9-abcdef0", tags: ["mem9-abcdef0", "latest"] },
    ],
    ["pull_request", { releaseTag: "pr-abcdef0", tags: ["pr-abcdef0"] }],
  ])("maps %s to the expected release tags", (eventName, expected) => {
    expect(selectImageTags(eventName, SHA)).toEqual(expected);
  });

  it("rejects unsupported events and malformed SHAs", () => {
    expect(() => selectImageTags("schedule", SHA)).toThrow(/unsupported/i);
    expect(() => selectImageTags("push", "not-a-sha")).toThrow(/sha/i);
  });
});

describe("image-tags workflow command", () => {
  it("writes the release tag and newline-delimited tag list to GITHUB_OUTPUT", () => {
    const dir = mkdtempSync(join(tmpdir(), "mem9-image-tags-"));
    tempDirs.push(dir);
    const output = join(dir, "github-output");
    const result = spawnSync(
      process.execPath,
      [new URL("./image-tags.mjs", import.meta.url).pathname],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          EVENT_NAME: "workflow_dispatch",
          GITHUB_SHA: SHA,
          GITHUB_OUTPUT: output,
        },
      },
    );

    expect(result.status, result.stderr).toBe(0);
    expect(readFileSync(output, "utf8")).toBe(
      [
        "image_tag=mem9-abcdef0",
        "image_tags<<EOF",
        "mem9-abcdef0",
        "latest",
        "EOF",
        "",
      ].join("\n"),
    );
  });
});
