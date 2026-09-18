#!/usr/bin/env node

import { appendFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

const RELEASE_EVENTS = new Set(["push", "workflow_dispatch"]);

export function selectImageTags(eventName, sha) {
  if (!/^[0-9a-f]{7,64}$/i.test(sha ?? "")) {
    throw new Error("GITHUB_SHA must be a hexadecimal Git SHA");
  }

  const shortSha = sha.slice(0, 7).toLowerCase();
  if (RELEASE_EVENTS.has(eventName)) {
    const releaseTag = `mem9-${shortSha}`;
    return { releaseTag, tags: [releaseTag, "latest"] };
  }
  if (eventName === "pull_request") {
    const releaseTag = `pr-${shortSha}`;
    return { releaseTag, tags: [releaseTag] };
  }
  throw new Error(`unsupported GitHub event: ${eventName || "<empty>"}`);
}

export function selectHumanImageTags(eventName, sha) {
  if (eventName !== "pull_request") {
    throw new Error("human acceptance images are built only for pull requests");
  }
  const selection = selectImageTags(eventName, sha);
  const releaseTag = `pr-human-${selection.releaseTag.slice(3)}`;
  return { releaseTag, tags: [releaseTag, "human-latest"] };
}

function writeGithubOutputs(path, selection) {
  appendFileSync(
    path,
    [
      `image_tag=${selection.releaseTag}`,
      "image_tags<<EOF",
      ...selection.tags,
      "EOF",
      "",
    ].join("\n"),
  );
}

function main() {
  const output = process.env.GITHUB_OUTPUT;
  if (!output) throw new Error("GITHUB_OUTPUT is required");
  const selection = selectImageTags(
    process.env.EVENT_NAME,
    process.env.GITHUB_SHA,
  );
  writeGithubOutputs(output, selection);
  if (process.env.EVENT_NAME === "pull_request") {
    const human = selectHumanImageTags(
      process.env.EVENT_NAME,
      process.env.GITHUB_SHA,
    );
    appendFileSync(
      output,
      [
        `human_image_tag=${human.releaseTag}`,
        "human_image_tags<<EOF",
        ...human.tags,
        "EOF",
        "",
      ].join("\n"),
    );
  }
}

const isMain =
  process.argv[1] &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (isMain) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`image tag selection failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
