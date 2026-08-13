import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";

const script = resolve("scripts/run-oauth-facade-smoke.sh");
const temporaryPaths = [];
const validReaderClientConfig = {
  RefreshTokenRotation: {
    Feature: "ENABLED",
    RetryGracePeriodSeconds: 10,
  },
  ExplicitAuthFlows: ["ALLOW_USER_SRP_AUTH"],
};

afterEach(() => {
  for (const path of temporaryPaths.splice(0)) {
    rmSync(path, { force: true, recursive: true });
  }
});

function runFixture({
  readerClientConfig = validReaderClientConfig,
} = {}) {
  const directory = mkdtempSync(join(tmpdir(), "mem9-oauth-smoke-"));
  temporaryPaths.push(directory);
  const bin = join(directory, "bin");
  const calls = join(directory, "calls.jsonl");
  mkdirSync(bin);

  const aws = join(bin, "aws");
  writeFileSync(
    aws,
    `#!${process.execPath}
import { appendFileSync } from "node:fs";
const args = process.argv.slice(2);
appendFileSync(process.env.MOCK_CALLS, JSON.stringify(["aws", ...args]) + "\\n");
const option = (name) => {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
};
const command = args.slice(0, 2).join(" ");
if (command === "ssm get-parameter") {
  const name = option("--name") ?? "";
  if (name.endsWith("/facade/url")) console.log(process.env.MOCK_FACADE);
  else if (name.endsWith("/cognito/issuer")) console.log(process.env.MOCK_ISSUER);
  else if (name.endsWith("/cognito/reader/client-id")) console.log(process.env.MOCK_CLIENT_ID);
  else {
    console.error("unexpected parameter:", name);
    process.exit(2);
  }
} else if (command === "cognito-idp describe-user-pool-client") {
  console.log(process.env.MOCK_READER_CLIENT_CONFIG);
} else {
  console.error("unexpected aws command:", command);
  process.exit(2);
}
`,
    { mode: 0o755 },
  );
  chmodSync(aws, 0o755);

  const curl = join(bin, "curl");
  writeFileSync(
    curl,
    `#!${process.execPath}
import { appendFileSync, writeFileSync } from "node:fs";
const args = process.argv.slice(2);
appendFileSync(process.env.MOCK_CALLS, JSON.stringify(["curl", ...args]) + "\\n");
const option = (name) => {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
};
const url = args.at(-1) ?? "";
const base = process.env.MOCK_FACADE;
if (url.endsWith("/.well-known/oauth-authorization-server")) {
  console.log(JSON.stringify({
    issuer: base,
    authorization_endpoint: base + "/oauth/authorize",
    token_endpoint: base + "/oauth/token",
    registration_endpoint: base + "/register",
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
  }));
} else if (url.endsWith("/.well-known/oauth-protected-resource")) {
  console.log(JSON.stringify({
    resource: base + "/mcp",
    authorization_servers: [base],
  }));
} else if (url.endsWith("/.well-known/openid-configuration")) {
  console.log(JSON.stringify({ issuer: base }));
} else if (url.endsWith("/register")) {
  console.log(JSON.stringify({
    client_id: "fixture-public-client",
    redirect_uris: ["http://localhost:8080/cb"],
    token_endpoint_auth_method: "none",
  }));
} else if (url.endsWith("/oauth/authorize")) {
  writeFileSync(
    option("-D"),
    "HTTP/1.1 302 Found\\r\\n" +
      "Set-Cookie: __Secure-mem9-oauth=fixture; Path=/oauth/callback; Secure; HttpOnly; SameSite=Lax\\r\\n" +
      "Location: https://auth.example.com/oauth2/authorize?state=short-state\\r\\n\\r\\n",
  );
  writeFileSync(option("-o"), "");
  process.stdout.write("302");
} else {
  console.error("unexpected curl URL:", url);
  process.exit(2);
}
`,
    { mode: 0o755 },
  );
  chmodSync(curl, 0o755);

  const result = spawnSync("bash", [script], {
    encoding: "utf8",
    env: {
      ...process.env,
      AWS_REGION: "ap-northeast-1",
      MOCK_CALLS: calls,
      MOCK_CLIENT_ID: "fixture-reader-client-id",
      MOCK_FACADE: "https://facade.example.com",
      MOCK_ISSUER:
        "https://cognito-idp.ap-northeast-1.amazonaws.com/pool-fixture",
      MOCK_READER_CLIENT_CONFIG: JSON.stringify(readerClientConfig),
      PATH: `${bin}${delimiter}${process.env.PATH}`,
      STAGE: "pr-162",
    },
  });
  const callRecords = (existsSync(calls) ? readFileSync(calls, "utf8") : "")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  return {
    callRecords,
    result,
    output: `${result.stdout}${result.stderr}`,
  };
}

describe("OAuth facade smoke harness (TC-OAUTH-REFRESH-008)", () => {
  it("passes only after inspecting enabled rotation and keeps credentials out of output", () => {
    const { callRecords, result, output } = runFixture();

    expect(result.status, output).toBe(0);
    expect(output).toContain("reader refresh-token rotation OK");
    expect(output).not.toContain("fixture-reader-client-id");
    expect(output).not.toMatch(/access-token|id-token|refresh-token-value/iu);
    expect(
      callRecords.filter(
        ([tool, service, operation]) =>
          tool === "aws" &&
          service === "cognito-idp" &&
          operation === "describe-user-pool-client",
      ),
    ).toHaveLength(1);
    expect(JSON.stringify(callRecords)).not.toContain("client-secret");
  });

  it.each([
    [
      "rotation is disabled",
      {
        readerClientConfig: {
          ...validReaderClientConfig,
          RefreshTokenRotation: {
            ...validReaderClientConfig.RefreshTokenRotation,
            Feature: "DISABLED",
          },
        },
      },
      /refresh-token rotation is not enabled/iu,
    ],
    [
      "the retry grace period drifts",
      {
        readerClientConfig: {
          ...validReaderClientConfig,
          RefreshTokenRotation: {
            ...validReaderClientConfig.RefreshTokenRotation,
            RetryGracePeriodSeconds: 0,
          },
        },
      },
      /retry grace period is not 10 seconds/iu,
    ],
    [
      "the incompatible refresh auth flow is configured",
      {
        readerClientConfig: {
          ...validReaderClientConfig,
          ExplicitAuthFlows: ["ALLOW_REFRESH_TOKEN_AUTH"],
        },
      },
      /ALLOW_REFRESH_TOKEN_AUTH/iu,
    ],
    [
      "explicit auth flows are absent and Cognito defaults apply",
      {
        readerClientConfig: {
          RefreshTokenRotation: validReaderClientConfig.RefreshTokenRotation,
        },
      },
      /explicit auth flows/iu,
    ],
    [
      "refresh-token rotation is absent",
      {
        readerClientConfig: {
          ExplicitAuthFlows: validReaderClientConfig.ExplicitAuthFlows,
        },
      },
      /refresh-token rotation is not enabled/iu,
    ],
  ])("fails when %s", (_case, options, expectedError) => {
    const { result, output } = runFixture(options);

    expect(result.status).not.toBe(0);
    expect(output).toMatch(expectedError);
  });
});
