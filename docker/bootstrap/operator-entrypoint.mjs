#!/usr/bin/env node

import { spawn } from "node:child_process";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { GetParametersCommand, SSMClient } from "@aws-sdk/client-ssm";

const OPERATION = requireEnv("MEM9_BOOTSTRAP_OPERATION");
const REGION = requireEnv("AWS_REGION");
const SCRIPT_ROOT = "/bootstrap/operator/scripts";
const SIGNAL_EXIT_CODES = Object.freeze({ SIGINT: 130, SIGTERM: 143 });
const CHILD_STOP_TIMEOUT_MS = 25_000;
let activeChild;
let receivedSignal;
let childStopTimer;

function interruptionError() {
  const error = new Error(`operator interrupted by ${receivedSignal}`);
  error.exitCode = SIGNAL_EXIT_CODES[receivedSignal] ?? 1;
  return error;
}

function forwardSignal(signal) {
  receivedSignal ??= signal;
  if (!activeChild) return;
  activeChild.kill(signal);
  if (!childStopTimer) {
    childStopTimer = setTimeout(() => {
      activeChild?.kill("SIGKILL");
    }, CHILD_STOP_TIMEOUT_MS);
    childStopTimer.unref();
  }
}

for (const signal of Object.keys(SIGNAL_EXIT_CODES)) {
  process.on(signal, () => forwardSignal(signal));
}

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`missing required env ${name}`);
  return value;
}

function databaseDsn() {
  const secret = JSON.parse(requireEnv("MEM9_DB_SECRET"));
  if (
    typeof secret.username !== "string" ||
    typeof secret.password !== "string"
  ) {
    throw new Error("MEM9_DB_SECRET must contain username and password");
  }
  const url = new URL("postgres://placeholder");
  url.username = secret.username;
  url.password = secret.password;
  url.hostname = requireEnv("MEM9_DB_HOST");
  url.port = requireEnv("MEM9_DB_PORT");
  url.pathname = `/${encodeURIComponent(requireEnv("MEM9_DB_NAME"))}`;
  url.searchParams.set("sslmode", "require");
  return url.toString();
}

async function readParameters(names) {
  const unique = [...new Set(names.filter(Boolean))];
  if (unique.length === 0) return new Map();
  const client = new SSMClient({ region: REGION });
  try {
    const response = await client.send(
      new GetParametersCommand({
        Names: unique,
        WithDecryption: true,
      }),
    );
    if ((response.InvalidParameters ?? []).length > 0) {
      throw new Error("one or more operator input parameters are unavailable");
    }
    const values = new Map(
      (response.Parameters ?? []).map((item) => [item.Name, item.Value]),
    );
    if (values.size !== unique.length) {
      throw new Error("one or more operator input parameters are empty");
    }
    return values;
  } finally {
    client.destroy();
  }
}

function run(script, args, env) {
  return new Promise((resolve, reject) => {
    if (receivedSignal) {
      reject(interruptionError());
      return;
    }
    const child = spawn(process.execPath, [script, ...args], {
      env,
      stdio: "inherit",
    });
    activeChild = child;
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      activeChild = undefined;
      clearTimeout(childStopTimer);
      childStopTimer = undefined;
      if (receivedSignal) reject(interruptionError());
      else if (code === 0) resolve();
      else {
        const error = new Error(`operator command exited ${code ?? signal}`);
        if (Number.isInteger(code)) error.exitCode = code;
        reject(error);
      }
    });
  });
}

async function main() {
  const configParameter = process.env.MEM9_NAMESPACE_CONFIG_PARAMETER;
  const usernameParameter = process.env.MEM9_NAMESPACE_USERNAME_PARAMETER;
  const values = await readParameters([configParameter, usernameParameter]);
  const directory = await mkdtemp(join(tmpdir(), "mem9-namespace-operator-"));
  try {
    const env = {
      ...process.env,
      MNEMO_DSN: databaseDsn(),
      MEM9_STAGE: requireEnv("MEM9_STAGE"),
      MEM9_COGNITO_ISSUER: requireEnv("MEM9_COGNITO_ISSUER"),
      MEM9_COGNITO_USER_POOL_ID: requireEnv("MEM9_COGNITO_USER_POOL_ID"),
    };
    let configPath;
    if (configParameter) {
      configPath = join(directory, "namespace-config.json");
      await writeFile(configPath, values.get(configParameter), { mode: 0o600 });
      await chmod(configPath, 0o600);
      env.MEM9_NAMESPACE_CONFIG = configPath;
    }
    let usernamePath;
    if (usernameParameter) {
      usernamePath = join(directory, "username");
      await writeFile(usernamePath, values.get(usernameParameter), {
        mode: 0o600,
      });
      await chmod(usernamePath, 0o600);
    }

    if (OPERATION === "namespace-reconcile") {
      if (!configPath)
        throw new Error("namespace config parameter is required");
      await run(
        `${SCRIPT_ROOT}/reconcile-memory-namespaces.mjs`,
        ["reconcile", "--config", configPath],
        env,
      );
      return;
    }
    if (
      ["assign-user", "move-user", "revoke-user", "show-user"].includes(
        OPERATION,
      )
    ) {
      if (!configPath || !usernamePath) {
        throw new Error(
          "namespace config and username parameters are required",
        );
      }
      const args = [
        OPERATION,
        "--config",
        configPath,
        "--username-file",
        usernamePath,
      ];
      if (process.env.MEM9_NAMESPACE_SLUG) {
        args.push("--namespace", process.env.MEM9_NAMESPACE_SLUG);
      }
      if (process.env.MEM9_NAMESPACE_EMERGENCY === "1") {
        args.push("--emergency");
      }
      await run(`${SCRIPT_ROOT}/manage-memory-access.mjs`, args, env);
      return;
    }
    if (OPERATION === "assert-phase") {
      await run(
        `${SCRIPT_ROOT}/migrate-memory-namespaces.mjs`,
        [
          OPERATION,
          "--expected-phase",
          requireEnv("MEM9_EXPECTED_NAMESPACE_PHASE"),
        ],
        env,
      );
      return;
    }
    if (["preflight", "freeze", "enforce"].includes(OPERATION)) {
      await run(
        `${SCRIPT_ROOT}/migrate-memory-namespaces.mjs`,
        [OPERATION],
        env,
      );
      return;
    }
    if (OPERATION === "backfill") {
      await run(
        `${SCRIPT_ROOT}/migrate-memory-namespaces.mjs`,
        [
          "backfill",
          "--stage",
          env.MEM9_STAGE,
          "--namespace",
          requireEnv("MEM9_LEGACY_NAMESPACE_SLUG"),
          "--display-name",
          requireEnv("MEM9_LEGACY_NAMESPACE_DISPLAY_NAME"),
          "--acknowledge-shared-history",
          requireEnv("MEM9_SHARED_HISTORY_ACKNOWLEDGEMENT"),
        ],
        env,
      );
      return;
    }
    throw new Error("unsupported namespace operator operation");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

main().catch((error) => {
  process.stderr.write(`namespace operator failed: ${error.message}\n`);
  process.exitCode = Number.isInteger(error.exitCode) ? error.exitCode : 1;
});
