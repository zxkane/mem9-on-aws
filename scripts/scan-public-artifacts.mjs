#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const TEST_ACCOUNT_ID = ["123456", "789012"].join("");
const MAX_GIT_OUTPUT_BYTES = 32 * 1024 * 1024;
const GENERIC_BUCKET_PLACEHOLDERS = Object.freeze(new Set(["bucket"]));
const S3_BUCKET_NAME_PATTERN = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/u;

/**
 * Whether an accountless S3 ARN discloses a real bucket name.
 *
 * S3 bucket names are one GLOBAL namespace, so a name is a targeting hint even
 * with no account id in the ARN — that is the whole reason this detector exists.
 * But three shapes disclose nothing, and IAM policy code cannot be written
 * without them: a wildcard or interpolated segment is a PATTERN rather than a
 * name, a name suffixed with the documentation account id is the same
 * placeholder the account detector above already blesses, and `bucket` is the
 * generic noun that prose about ARN matching has to say out loud. Anything that
 * parses as a well-formed bucket name and is none of those is treated as real.
 *
 * Only the bucket segment decides this; the object key is ignored. Keying off
 * the whole ARN would let a trailing `/*` — the ordinary object-glob form that
 * every real S3 policy already ends in — vouch for the name in front of it.
 */
function disclosesBucketName(arn) {
  const bucket = arn.replace(/^arn:[a-z0-9-]+:s3:::/iu, "").split("/")[0];
  return (
    S3_BUCKET_NAME_PATTERN.test(bucket) &&
    !bucket.includes(TEST_ACCOUNT_ID) &&
    !GENERIC_BUCKET_PLACEHOLDERS.has(bucket)
  );
}
const PRIVATE_REPOSITORY_PATTERN = new RegExp(
  `\\b(?:${["quant", "scorer"].join("[-]")}|${["vid", "syllabus"].join(
    "",
  )})\\b`,
  "iu",
);

const LINE_DETECTORS = Object.freeze([
  {
    category: "private repository reference",
    pattern: PRIVATE_REPOSITORY_PATTERN,
  },
  {
    category: "private comment permalink",
    pattern: /issuecomment-[0-9]+/iu,
  },
  {
    category: "cross-repository issue reference",
    pattern: /<owner>\/<repo>#[0-9]+/iu,
  },
  {
    category: "RDS endpoint",
    pattern:
      /[A-Za-z0-9-]+\.cluster-[A-Za-z0-9-]+\.[a-z0-9-]+\.rds\.amazonaws\.com/iu,
  },
  {
    category: "API Gateway endpoint",
    pattern:
      /(?:https?:\/\/)?[a-z0-9]{10}\.execute-api\.[a-z0-9-]+\.amazonaws\.com(?:\/[^\s"'<>]*)?/iu,
  },
  {
    category: "Cognito hosted-domain endpoint",
    pattern:
      /(?:https?:\/\/)?[a-z0-9][a-z0-9-]{0,62}\.auth(?:-fips)?\.[a-z0-9-]+\.amazoncognito\.com(?:\/[^\s"'<>]*)?/iu,
  },
  {
    category: "AgentCore Gateway endpoint",
    pattern:
      /(?:https?:\/\/)?[a-z0-9][a-z0-9-]{2,63}\.gateway\.bedrock-agentcore\.[a-z0-9-]+\.amazonaws\.com(?:\/[^\s"'<>]*)?/iu,
  },
  {
    category: "Cognito user-pool identifier",
    pattern: /\b[a-z]{2}(?:-[a-z0-9]+)+-[0-9]_[A-Za-z0-9]+\b/iu,
    validate: (value) => value.length <= 55,
  },
  {
    category: "Cognito client identifier",
    pattern:
      /(?:client[_-]?id|clientId|ClientId)\s*["']?\s*[:=]\s*(?:["'][a-z0-9]{26}["']|[a-z0-9]{26})(?![a-z0-9])/iu,
  },
  {
    category: "AWS access-key identifier",
    pattern: /(?:AKIA|ASIA)[0-9A-Z]{16}/u,
  },
  {
    category: "AWS secret access key",
    pattern:
      /AWS_SECRET_ACCESS_KEY\s*[:=]\s*(?:["'][A-Za-z0-9/+=]{40,}["']|[A-Za-z0-9/+=]{40,})(?![A-Za-z0-9/+=])/iu,
  },
  {
    category: "AWS session token",
    pattern:
      /AWS_SESSION_TOKEN\s*[:=]\s*(?:["'][A-Za-z0-9/+=._-]{40,}["']|[A-Za-z0-9/+=._-]{40,})(?![A-Za-z0-9/+=._-])/iu,
  },
  {
    category: "GitHub personal access token",
    pattern:
      /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/u,
  },
  {
    category: "private key",
    pattern: /BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY/u,
  },
  {
    category: "bearer credential",
    pattern: /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}/u,
  },
  {
    category: "Bedrock bearer credential",
    pattern: /\bbedrock-api-key-[A-Za-z0-9._~+/=-]{12,}/u,
  },
  {
    category: "client secret",
    pattern:
      /(?:client[_-]?secret|clientSecret|ClientSecret)\s*["']?\s*[:=]\s*(?:["'][A-Za-z0-9+/=_-]{32,}["']|[A-Za-z0-9+/=_-]{32,})(?![A-Za-z0-9+/=_-])/iu,
  },
  {
    category: "API key",
    pattern:
      /(?:api[_-]?key|apiKey|ApiKey|x-api-key)\s*["']?\s*[:=]\s*(?:["'][A-Za-z0-9._~+/=-]{16,}["']|[A-Za-z0-9._~+/=-]{16,})(?![A-Za-z0-9._~+/=-])/iu,
  },
  {
    category: "credential in URL",
    pattern: /https?:\/\/[^/\s:@]+:[^/\s@]{8,}@/iu,
  },
  {
    category: "accountless S3 resource ARN",
    // The bucket segment admits `*` and `${...}` so a pattern is captured WHOLE
    // and can be recognized as one. Matching only the legal-name characters
    // would truncate `arn:aws:s3:::mem9-on-aws-*-decisions` to its prefix, and
    // that prefix parses as a perfectly good bucket name — the wildcard form
    // would be reported as a real disclosure on the strength of the text the
    // regex declined to look at.
    pattern:
      /\barn:[a-z0-9-]+:s3:::[a-z0-9*${](?:[a-z0-9.*${}-]{1,61}[a-z0-9*}])?(?:\/[^\s"'`<>]+)?/iu,
    validate: disclosesBucketName,
  },
  {
    category: "accountless Route 53 resource ARN",
    pattern: /\barn:[a-z0-9-]+:route53:::hostedzone\/[A-Z0-9]{8,32}\b/u,
  },
]);

function runGit(args, { cwd = process.cwd(), encoding = "utf8" } = {}) {
  const result = spawnSync("git", args, {
    cwd,
    encoding,
    maxBuffer: MAX_GIT_OUTPUT_BYTES,
  });
  if (result.status !== 0 || result.error) {
    throw new Error("public-artifact Git inspection failed");
  }
  return result.stdout;
}

function canonicalCommit(reference, cwd) {
  const commit = runGit(["rev-parse", "--verify", `${reference}^{commit}`], {
    cwd,
  }).trim();
  if (!/^[0-9a-f]{40,64}$/u.test(commit)) {
    throw new Error("public-artifact Git reference is malformed");
  }
  return commit;
}

function changedEntries(parent, commit, cwd) {
  const output = runGit(
    [
      "diff",
      "--name-status",
      "-z",
      "--diff-filter=ACDMRTUXB",
      "-M",
      "-C",
      parent,
      commit,
      "--",
    ],
    { cwd },
  );
  const fields = output.split("\0");
  if (fields.at(-1) === "") fields.pop();

  const entries = [];
  for (let index = 0; index < fields.length;) {
    const status = fields[index++];
    if (!/^[ACDMRTUXB][0-9]*$/u.test(status ?? "")) {
      throw new Error("public-artifact Git diff is malformed");
    }
    if (status.startsWith("R") || status.startsWith("C")) {
      const oldPath = fields[index++];
      const path = fields[index++];
      if (oldPath === undefined || path === undefined) {
        throw new Error("public-artifact Git diff is malformed");
      }
      entries.push({ oldPath, path, status: status[0] });
      continue;
    }
    const path = fields[index++];
    if (path === undefined) {
      throw new Error("public-artifact Git diff is malformed");
    }
    entries.push({ path, status: status[0] });
  }
  return entries;
}

function readBlobAtCommit(commit, path, cwd) {
  const treeEntry = runGit(
    ["ls-tree", "-z", commit, "--", `:(literal)${path}`],
    { cwd },
  );
  const records = treeEntry.split("\0").filter(Boolean);
  if (records.length !== 1) {
    throw new Error("public-artifact Git tree lookup failed");
  }
  const separator = records[0].indexOf("\t");
  const metadata = records[0].slice(0, separator).split(" ");
  if (
    separator < 0 ||
    records[0].slice(separator + 1) !== path ||
    metadata.length !== 3
  ) {
    throw new Error("public-artifact Git tree entry is malformed");
  }
  const [, type, objectId] = metadata;
  if (type !== "blob") return undefined;
  if (!/^[0-9a-f]{40,64}$/u.test(objectId)) {
    throw new Error("public-artifact Git object identifier is malformed");
  }
  return runGit(["cat-file", "blob", objectId], {
    cwd,
    encoding: null,
  }).toString("utf8");
}

function pathHasSensitiveValue(path) {
  return scanPublicArtifactText(path).length > 0;
}

export function scanPublicArtifactText(source) {
  const findings = [];
  const lines = String(source).split(/\r?\n/u);

  for (const [index, line] of lines.entries()) {
    const accountIds = line.match(/\b[0-9]{12}\b/gu) ?? [];
    if (accountIds.some((accountId) => accountId !== TEST_ACCOUNT_ID)) {
      findings.push({
        category: "AWS account identifier",
        line: index + 1,
      });
    }

    for (const { category, pattern, validate } of LINE_DETECTORS) {
      const match = line.match(pattern);
      if (match && (!validate || validate(match[0]))) {
        findings.push({ category, line: index + 1 });
      }
    }
  }

  return findings;
}

export async function scanPublicArtifactFiles(paths) {
  const findings = [];
  for (const path of paths) {
    for (const finding of scanPublicArtifactText(path)) {
      findings.push({ ...finding, path, scope: "path" });
    }
    const source = await readFile(path, "utf8");
    for (const finding of scanPublicArtifactText(source)) {
      findings.push({ ...finding, path, scope: "content" });
    }
  }
  return findings;
}

export function scanPublicArtifactGitRange({
  base,
  cwd = process.cwd(),
  head,
}) {
  const canonicalBase = canonicalCommit(base, cwd);
  const canonicalHead = canonicalCommit(head, cwd);
  const mergeBase = runGit(["merge-base", canonicalBase, canonicalHead], {
    cwd,
  }).trim();
  if (!/^[0-9a-f]{40,64}$/u.test(mergeBase)) {
    throw new Error("public-artifact Git merge base is malformed");
  }
  const commits = runGit(
    ["rev-list", "--reverse", `${mergeBase}..${canonicalHead}`],
    { cwd },
  )
    .trim()
    .split("\n")
    .filter(Boolean);
  const findings = [];

  for (const commit of commits) {
    const commitMessage = runGit(
      ["show", "--no-patch", "--format=%B", commit],
      { cwd },
    );
    for (const finding of scanPublicArtifactText(commitMessage)) {
      findings.push({
        ...finding,
        commit,
        path: "<commit-message>",
        scope: "commit-message",
      });
    }

    const revision = runGit(["rev-list", "--parents", "-n", "1", commit], {
      cwd,
    })
      .trim()
      .split(" ");
    if (revision[0] !== commit || revision.length < 2) {
      throw new Error("public-artifact Git commit ancestry is malformed");
    }
    const parent = revision[1];
    for (const entry of changedEntries(parent, commit, cwd)) {
      const paths = [entry.oldPath, entry.path].filter(
        (path) => path !== undefined,
      );
      for (const path of new Set(paths)) {
        for (const finding of scanPublicArtifactText(path)) {
          findings.push({
            ...finding,
            commit,
            path,
            scope: "path",
          });
        }
      }
      if (entry.status === "D") continue;
      const source = readBlobAtCommit(commit, entry.path, cwd);
      if (source === undefined) continue;
      for (const finding of scanPublicArtifactText(source)) {
        findings.push({
          ...finding,
          commit,
          path: entry.path,
          scope: "content",
        });
      }
    }
  }
  return findings;
}

function writeFinding({ category, commit, line, path, scope }) {
  const location = pathHasSensitiveValue(path)
    ? "<redacted-path>"
    : JSON.stringify(path);
  const commitLabel = commit ? `commit ${commit.slice(0, 12)} ` : "";
  const lineLabel =
    scope === "path"
      ? "path"
      : scope === "commit-message"
        ? `commit-message line ${line}`
        : `line ${line}`;
  process.stderr.write(
    `${commitLabel}${location}:${lineLabel}: prohibited ${category}\n`,
  );
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 0) return;

  let findings;
  if (args[0] === "--git-range") {
    if (args.length !== 3) {
      throw new Error("expected --git-range <base> <head>");
    }
    findings = scanPublicArtifactGitRange({ base: args[1], head: args[2] });
  } else {
    findings = await scanPublicArtifactFiles(args);
  }
  for (const finding of findings) writeFinding(finding);
  if (findings.length > 0) process.exitCode = 1;
}

if (
  process.argv[1] &&
  pathToFileURL(process.argv[1]).href === import.meta.url
) {
  await main();
}
