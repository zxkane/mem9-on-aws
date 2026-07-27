import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  scanPublicArtifactFiles,
  scanPublicArtifactGitRange,
  scanPublicArtifactText,
} from "./scan-public-artifacts.mjs";

const scannerPath = resolve(import.meta.dirname, "scan-public-artifacts.mjs");

function runGit(cwd, ...args) {
  const result = spawnSync("git", args, { cwd, encoding: "utf8" });
  expect(result.status, result.stderr).toBe(0);
  return result.stdout.trim();
}

describe("public artifact scanner", () => {
  it.each([
    ["AWS account identifier", `account=${["210987", "654321"].join("")}`],
    [
      "API Gateway endpoint",
      `https://${["a1b2c", "3d4e5"].join("")}.execute-api.ap-northeast-1.amazonaws.com/prod`,
    ],
    [
      "Cognito hosted-domain endpoint",
      `https://${["operator", "login"].join("-")}.auth.ap-northeast-1.amazoncognito.com/oauth2/token`,
    ],
    [
      "AgentCore Gateway endpoint",
      `https://${["gateway", "a1b2c3d4"].join("-")}.gateway.bedrock-agentcore.ap-northeast-1.amazonaws.com/mcp`,
    ],
    ["Cognito user-pool identifier", ["ap-northeast-1", "_A1b2C3d4E"].join("")],
    ["Cognito client identifier", `client_id="${"a1".repeat(13)}"`],
    [
      "accountless S3 resource ARN",
      ["arn:", "aws:s3:::operator-memory-backup"].join(""),
    ],
    [
      "accountless Route 53 resource ARN",
      ["arn:", "aws:route53:::hostedzone/Z123456789ABC"].join(""),
    ],
    ["bearer credential", `Authorization: Bearer ${"a".repeat(32)}`],
    [
      "Bedrock bearer credential",
      `token=${["bedrock", "api", "key"].join("-")}-${"a".repeat(24)}`,
    ],
    ["client secret", `client_secret="${"a".repeat(64)}"`],
    ["API key", `X-API-Key="${"a".repeat(32)}"`],
    ["client secret", `CLIENT_SECRET=${"b".repeat(48)}`],
    ["API key", `API_KEY=${"c".repeat(32)}`],
    [
      "AWS secret access key",
      `AWS_${["SECRET", "ACCESS", "KEY"].join("_")}=${"d".repeat(40)}`,
    ],
    [
      "AWS secret access key",
      `aws_${["secret", "access", "key"].join("_")} = ${"h".repeat(40)}`,
    ],
    [
      "AWS session token",
      `AWS_${["SESSION", "TOKEN"].join("_")}=${"e".repeat(80)}`,
    ],
    [
      "AWS session token",
      `aws_${["session", "token"].join("_")} = ${"j".repeat(80)}`,
    ],
    ["GitHub personal access token", `${["ghp", "f".repeat(36)].join("_")}`],
    [
      "GitHub personal access token",
      `${["github", "pat", "g".repeat(70)].join("_")}`,
    ],
    [
      "cross-repository issue reference",
      [["<owner>", "<repo>#42"].join("/")].join(""),
    ],
    ["Cognito user-pool identifier", ["us-east-1", "_A"].join("")],
    [
      "Cognito user-pool identifier",
      ["us-gov-west-1", "_", "A".repeat(40)].join(""),
    ],
    [
      "API Gateway endpoint",
      `https://${["a1b2c", "3d4e5"].join("")}.execute-api.ap-northeast-1.amazonaws.com/\${stage}`,
    ],
  ])("detects a %s without returning its value", (category, source) => {
    expect(scanPublicArtifactText(source)).toEqual([{ category, line: 1 }]);
  });

  it("allows placeholders, test identifiers, and source patterns", async () => {
    expect(
      scanPublicArtifactText(
        [
          "account=123456789012",
          "arn:aws:iam::<aws-account-id>:role/example-role",
          "https://{api-id}.execute-api.{region}.amazonaws.com",
          "https://{domain-prefix}.auth.{region}.amazoncognito.com",
          "https://{gateway-id}.gateway.bedrock-agentcore.{region}.amazonaws.com",
          "client_secret=<client-secret>",
          "API_KEY=${API_KEY}",
          "AWS_SECRET_ACCESS_KEY=<aws-secret-access-key>",
          ["us-east-1", "_", "A".repeat(46)].join(""),
        ].join("\n"),
      ),
    ).toEqual([]);
    await expect(scanPublicArtifactFiles([scannerPath])).resolves.toEqual([]);
  });

  it("fails the CLI without echoing a detected credential", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mem9-public-scan-"));
    const leaked = `Bearer ${"sensitive".repeat(5)}`;
    const unsafePath = join(directory, "unsafe.txt");
    const safePath = join(directory, "safe.txt");
    try {
      await writeFile(unsafePath, leaked);
      await writeFile(safePath, "account=<aws-account-id>\n");

      const unsafe = spawnSync(process.execPath, [scannerPath, unsafePath], {
        encoding: "utf8",
      });
      expect(unsafe.status).toBe(1);
      expect(unsafe.stderr).toContain("prohibited bearer credential");
      expect(unsafe.stderr).not.toContain(leaked);

      const safe = spawnSync(process.execPath, [scannerPath, safePath], {
        encoding: "utf8",
      });
      expect(safe.status, safe.stderr).toBe(0);
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });

  it("redacts a sensitive filename from CLI diagnostics", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mem9-public-path-scan-"));
    const token = ["ghp", "h".repeat(36)].join("_");
    const unsafePath = join(directory, `${token}.txt`);
    try {
      await writeFile(unsafePath, "safe content\n");
      const result = spawnSync(process.execPath, [scannerPath, unsafePath], {
        encoding: "utf8",
      });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("<redacted-path>:path");
      expect(result.stderr).not.toContain(token);
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });

  it("scans changed paths and every intermediate commit blob", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mem9-public-git-scan-"));
    const leaked = `Bearer ${"transient-secret".repeat(3)}`;
    const pathToken = ["ghp", "i".repeat(36)].join("_");
    const commitMessageLeak = ["quant", "scorer"].join("-");
    try {
      runGit(directory, "init", "--quiet");
      runGit(directory, "config", "user.name", "Scanner Test");
      runGit(directory, "config", "user.email", "scanner@example.com");
      await writeFile(join(directory, "README.md"), "safe\n");
      runGit(directory, "add", "README.md");
      runGit(directory, "commit", "--quiet", "-m", "initial");
      const base = runGit(directory, "rev-parse", "HEAD");

      await writeFile(join(directory, "transient.txt"), `${leaked}\n`);
      await writeFile(join(directory, `${pathToken}.txt`), "safe\n");
      runGit(directory, "add", ".");
      runGit(
        directory,
        "commit",
        "--quiet",
        "-m",
        `introduce then remove ${commitMessageLeak}`,
      );
      const unsafeCommit = runGit(directory, "rev-parse", "HEAD");

      await rm(join(directory, "transient.txt"));
      await rm(join(directory, `${pathToken}.txt`));
      await writeFile(join(directory, "renamed-safe.txt"), "safe\n");
      runGit(directory, "add", "--all");
      runGit(directory, "commit", "--quiet", "-m", "remove unsafe artifacts");
      const head = runGit(directory, "rev-parse", "HEAD");

      const findings = scanPublicArtifactGitRange({
        base,
        cwd: directory,
        head,
      });
      expect(findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            category: "bearer credential",
            commit: unsafeCommit,
            path: "transient.txt",
            scope: "content",
          }),
          expect.objectContaining({
            category: "GitHub personal access token",
            commit: unsafeCommit,
            path: `${pathToken}.txt`,
            scope: "path",
          }),
          expect.objectContaining({
            category: "private repository reference",
            commit: unsafeCommit,
            path: "<commit-message>",
            scope: "commit-message",
          }),
        ]),
      );

      const result = spawnSync(
        process.execPath,
        [scannerPath, "--git-range", base, head],
        { cwd: directory, encoding: "utf8" },
      );
      expect(result.status).toBe(1);
      expect(result.stderr).toContain(unsafeCommit.slice(0, 12));
      expect(result.stderr).toContain("<redacted-path>:path");
      expect(result.stderr).toContain(
        '"<commit-message>":commit-message line 1',
      );
      expect(result.stderr).not.toContain(leaked);
      expect(result.stderr).not.toContain(pathToken);
      expect(result.stderr).not.toContain(commitMessageLeak);
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });
});
