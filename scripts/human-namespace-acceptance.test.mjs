import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { Readable } from "node:stream";
import { readUsername } from "./lib/memory-namespace.mjs";
import {
  HUMAN_CASES,
  HumanNamespaceFixture,
  createFixturePlan,
  readDeploymentManifest,
  validateDeploymentManifest,
  validateFixturePlan,
  validateHumanAccessToken,
  verifyHumanOperatorOutput,
} from "./lib/human-namespace-acceptance.mjs";

export const manifestFixture = () => ({
  version: 1,
  stage: "pr-42",
  commit: "a".repeat(40),
  accountId: "123456789012",
  region: "ap-northeast-1",
  userPoolId: ["ap-northeast-1", "fixture"].join("_"),
  facadeUrl: "https://facade.example.com",
  gatewayUrl: "https://gateway.example.com/mcp",
  proxyFunctionArn:
    "arn:aws:lambda:ap-northeast-1:123456789012:function:mem9-on-aws-pr-42-Mem9ProxyFn-fixture",
  proxyLogGroup: "/aws/lambda/mem9-on-aws-pr-42-Mem9ProxyFn-fixture",
  database: {
    host: "database.example.com",
    port: 5432,
    name: "mem9",
    resourceId: "cluster-fixture",
    clusterId: "mem9-on-aws-pr-42-db",
    secretArn:
      "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:mem9-on-aws-pr-42-Mem9DbSecret-fixture",
    caFile: "/tmp/fixture-rds-ca.pem",
  },
  namespaces: [
    {
      slug: "preview-alpha",
      display_name: "PR isolation fixture preview-alpha",
      cognito_group: "memory-preview-alpha",
      default_role: "member",
      jit_enabled: true,
      status: "active",
    },
    {
      slug: "preview-beta",
      display_name: "PR isolation fixture preview-beta",
      cognito_group: "memory-preview-beta",
      default_role: "member",
      jit_enabled: true,
      status: "active",
    },
  ],
});

describe("operator human namespace acceptance guards", () => {
  it("reads managed identities from private files or stdin and rejects unsafe input", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mem9-managed-identity-"));
    const file = join(directory, "username.local.txt");
    try {
      await writeFile(file, " fixture-user\n", { mode: 0o600 });
      expect(await readUsername({ file })).toBe("fixture-user");
      expect(await readUsername({ stdin: Readable.from([Buffer.from(" fixture-user\n")]) })).toBe("fixture-user");
      await chmod(file, 0o644);
      await expect(readUsername({ file })).rejects.toThrow("owner-only");
      for (const input of ["", "first\nsecond", "x".repeat(129), "bad\0value"])
        await expect(readUsername({ stdin: Readable.from([Buffer.from(input)]) })).rejects.toThrow("username input is invalid");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
  it("accepts only the complete fixed case vocabulary in captured normal output", () => {
    const clean =
      HUMAN_CASES.map((label) => `PASS ${label}`).join("\n") +
      "\nhuman namespace acceptance: complete\n";
    expect(verifyHumanOperatorOutput(clean)).toEqual({
      output_redacted: true,
      case_count: HUMAN_CASES.length,
    });
    for (const leak of [
      "namespace-e2e-private-user",
      "Bearer private-token",
      "a".repeat(64),
      "private-client-value",
    ])
      expect(() => verifyHumanOperatorOutput(clean + leak)).toThrow(
        "unexpected_or_sensitive_operator_output",
      );
    expect(() =>
      verifyHumanOperatorOutput(
        "PASS owned_fixture_cleanup_complete\nhuman namespace acceptance: complete\n",
      ),
    ).toThrow("operator_output_cases_incomplete");
    expect(() =>
      verifyHumanOperatorOutput(
        clean.replace("human namespace acceptance: complete\n", ""),
      ),
    ).toThrow("operator_output_not_complete");
  });
  it("rejects a fixture cleanup record from another approved target before mutation", () => {
    expect(
      () =>
        new HumanNamespaceFixture({
          manifest: manifestFixture(),
          plan: createFixturePlan("a".repeat(64)),
          targetFingerprint: "b".repeat(64),
          cognito: {
            send: () => {
              throw new Error("must not call provider");
            },
          },
          connect: () => {
            throw new Error("must not connect");
          },
        }),
    ).toThrow("fixture_deployment_mismatch");
  });
  it("requires an exact preview deployment and rejects production targets", () => {
    expect(validateDeploymentManifest(manifestFixture()).stage).toBe("pr-42");
    for (const change of [
      { stage: "prod" },
      { stage: "dev" },
      { stage: "pr-0" },
      { commit: "main" },
      {
        namespaces: manifestFixture().namespaces.map((n) => ({
          ...n,
          status: "disabled",
        })),
      },
      {
        namespaces: manifestFixture().namespaces.map((n) => ({
          ...n,
          jit_enabled: false,
        })),
      },
      { accountId: "*" },
      { userPoolId: ["us-west-2", "fixture"].join("_") },
      { facadeUrl: "http://facade.example.com" },
      { gatewayUrl: "https://secret@gateway.example.com/mcp" },
      { password: "do-not-accept-inline-secrets" },
      {
        database: {
          ...manifestFixture().database,
          secretArn:
            "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:mem9-on-aws-prod-Mem9DbSecret-fixture",
        },
      },
      { database: { ...manifestFixture().database, resourceId: "" } },
      {
        namespaces: [
          manifestFixture().namespaces[0],
          manifestFixture().namespaces[0],
        ],
      },
    ])
      expect(() =>
        validateDeploymentManifest({ ...manifestFixture(), ...change }),
      ).toThrow();
  });

  it("reads deployment metadata only from an owner-only regular file", async () => {
    const directory = await mkdtemp(
      join(tmpdir(), "human-namespace-manifest-"),
    );
    try {
      const file = join(directory, "deployment.local.json");
      await writeFile(file, JSON.stringify(manifestFixture()), { mode: 0o600 });
      expect((await readDeploymentManifest(file)).stage).toBe("pr-42");
      await chmod(file, 0o644);
      await expect(readDeploymentManifest(file)).rejects.toThrow(/owner-only/);
      await chmod(file, 0o600);
      await writeFile(file, "{private-invalid");
      await expect(readDeploymentManifest(file)).rejects.toThrow(
        /^Invalid deployment manifest JSON$/,
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("creates bounded owned fixture identities without fixed credentials", () => {
    const a = createFixturePlan("f".repeat(64)),
      b = createFixturePlan("f".repeat(64));
    expect(a.runId).not.toBe(b.runId);
    expect(validateFixturePlan(a)).toEqual(a);
    expect(Object.keys(a.users)).toEqual([
      "writer",
      "peer",
      "other",
      "none",
      "multi",
      "mover",
      "revoked",
      "never_used",
      "emergency",
      "concurrent",
      "viewer",
    ]);
    expect(new Set(Object.values(a.users).map((x) => x.username)).size).toBe(
      11,
    );
    for (const user of Object.values(a.users)) {
      expect(user.username).toContain(a.runId);
      expect(user.password).toMatch(/^[A-Za-z0-9_-]+Aa0!$/);
      expect(user.password.length).toBeGreaterThanOrEqual(32);
    }
    expect(() =>
      validateFixturePlan({
        ...a,
        users: {
          ...a.users,
          writer: { ...a.users.writer, username: "existing-user" },
        },
      }),
    ).toThrow();
    expect(() => validateFixturePlan({ ...a, unexpected: true })).toThrow();
  });

  it("allows only a nominal 15-minute lifetime or the observed one-second shorter lifetime", () => {
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      token_use: "access",
      sub: "subject",
      client_id: "client",
      scope: "mem9-mcp/read mem9-mcp/write",
      iat: now,
      exp: now + 900,
    };
    const token = (body) =>
      `header.${Buffer.from(JSON.stringify(body)).toString("base64url")}.signature`;
    expect(validateHumanAccessToken(token(claims), now).sub).toBe("subject");
    expect(validateHumanAccessToken(token({ ...claims, exp: now + 899 }), now).sub).toBe("subject");
    for (const change of [
      { token_use: "id" },
      { scope: "openid" },
      { exp: now + 3600 },
      { exp: now + 898 },
      { exp: now + 901 },
      { exp: now - 1 },
      { sub: "" },
    ])
      expect(() =>
        validateHumanAccessToken(token({ ...claims, ...change }), now),
      ).toThrow();
  });
  it("records only timing deltas from the same clock used by a failed guard", () => {
    const now = 1_700_000_000;
    for (const [iat, exp, expected] of [
      [now, now + 898, [true, 898, 898, 0]],
      [now - 900, now, [true, 900, 0, -900]],
      [now + 6, now + 906, [true, 900, 906, 6]],
      ["private-invalid-time", now + 900, [false, null, null, null]],
    ]) {
      const claims = { token_use: "access", sub: "private-subject-marker", client_id: "private-client-marker", scope: "mem9-mcp/read mem9-mcp/write", iat, exp };
      const token = `header.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.signature`;
      let failure;
      try { validateHumanAccessToken(token, now); } catch (error) { failure = error; }
      expect(failure?.message).toBe("human token must have a live 15-minute lifetime");
      expect(failure.tokenTiming).toEqual(Object.fromEntries(
        ["integer_times", "lifetime_seconds", "remaining_seconds", "issued_offset_seconds"].map((name, i) => [name, expected[i]]),
      ));
      expect(JSON.stringify(failure)).not.toMatch(/private-subject|private-client|private-invalid|header\./);
    }
  });
});
