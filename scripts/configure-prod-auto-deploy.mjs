#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const requiredCheck = "Runbook & Public-Content Scan";
const branchPolicy = { protected_branches: false, custom_branch_policies: true };

export const mainProtection = {
  required_status_checks: { strict: true, contexts: [requiredCheck] },
  enforce_admins: true,
  required_pull_request_reviews: { required_approving_review_count: 0 },
  restrictions: null,
  allow_force_pushes: false,
  allow_deletions: false,
};

export const prodEnvironment = {
  wait_timer: 0,
  prevent_self_review: false,
  reviewers: [],
  deployment_branch_policy: branchPolicy,
};

export function assertMainOnlyEnvironment(environment, policies) {
  const configured = environment?.deployment_branch_policy;
  if (
    configured?.protected_branches !== false ||
    configured?.custom_branch_policies !== true ||
    policies?.total_count !== 1 ||
    policies.branch_policies?.length !== 1 ||
    policies.branch_policies[0]?.type !== "branch" ||
    policies.branch_policies[0]?.name !== "main"
  ) {
    throw new Error("prod must already allow exactly the main branch");
  }
  const types = (environment.protection_rules || []).map((rule) => rule.type);
  if (
    !types.includes("branch_policy") ||
    types.some((type) => !["branch_policy", "required_reviewers", "wait_timer"].includes(type))
  ) {
    throw new Error("prod has an unknown protection rule; refusing to replace it");
  }
  return types.some((type) => type !== "branch_policy");
}

export function isProtectedMain(protection) {
  const statusChecks = protection?.required_status_checks;
  const checks = [
    ...(statusChecks?.contexts || []),
    ...(statusChecks?.checks || []).map((check) => check.context),
  ];
  return Boolean(
    statusChecks?.strict === true &&
    checks.includes(requiredCheck) &&
    protection.required_pull_request_reviews &&
    protection.enforce_admins?.enabled === true &&
    protection.allow_force_pushes?.enabled !== true &&
    protection.allow_deletions?.enabled !== true,
  );
}

export function reconcileProdAutoDeploy(api, repo, apply = false) {
  const root = "repos/" + repo;
  const environmentPath = root + "/environments/prod";
  const protectionPath = root + "/branches/main/protection";
  const metadata = api("GET", root);
  if (metadata?.default_branch !== "main" || metadata?.permissions?.admin !== true) {
    throw new Error("repository admin access and main as the default branch are required");
  }
  if (api("GET", root + "/branches/main")?.name !== "main") {
    throw new Error("main branch could not be verified");
  }

  const environment = api("GET", environmentPath);
  const policies = api("GET", environmentPath + "/deployment-branch-policies");
  const reviewGate = assertMainOnlyEnvironment(environment, policies);
  const protection = api("GET", protectionPath);
  let protectedMain = isProtectedMain(protection);

  if (apply && !protectedMain) {
    if (protection !== null) {
      throw new Error("main has different protection; refusing to overwrite it");
    }
    api("PUT", protectionPath, mainProtection);
    protectedMain = isProtectedMain(api("GET", protectionPath));
    if (!protectedMain) {
      throw new Error("main protection was not verified; prod reviewers remain in place");
    }
  }

  if (apply && reviewGate) {
    api("PUT", environmentPath, prodEnvironment);
    const updatedEnvironment = api("GET", environmentPath);
    const updatedPolicies = api("GET", environmentPath + "/deployment-branch-policies");
    if (assertMainOnlyEnvironment(updatedEnvironment, updatedPolicies)) {
      throw new Error("prod still requires review or a wait timer");
    }
  }

  return { protectedMain, approvalFree: apply ? true : !reviewGate };
}

function gh(args, input) {
  const result = spawnSync("gh", args, {
    cwd: repoRoot,
    encoding: "utf8",
    input: input === undefined ? undefined : JSON.stringify(input),
    maxBuffer: 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    if (
      args[0] === "api" &&
      args.includes("GET") &&
      args.some((arg) => arg.endsWith("/branches/main/protection")) &&
      result.stderr?.includes("Branch not protected (HTTP 404)")
    ) {
      return null;
    }
    throw new Error("gh failed while inspecting or updating GitHub configuration");
  }
  try {
    return JSON.parse(result.stdout);
  } catch {
    throw new Error("gh returned invalid JSON");
  }
}

function api(method, path, input) {
  const args = ["api", "--method", method, path];
  if (input !== undefined) args.push("--input", "-");
  return gh(args, input);
}

function main() {
  const mode = process.argv[2] || "--check";
  if (!["--check", "--apply"].includes(mode) || process.argv.length > 3) {
    throw new Error("usage: node scripts/configure-prod-auto-deploy.mjs [--check|--apply]");
  }
  const repo = spawnSync(
    "gh",
    ["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"],
    { cwd: repoRoot, encoding: "utf8" },
  );
  const name = repo.stdout?.trim();
  if (repo.status !== 0 || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(name)) {
    throw new Error("the checkout's GitHub repository could not be verified");
  }
  const state = reconcileProdAutoDeploy(api, name, mode === "--apply");
  console.log("main PR/check protection: " + (state.protectedMain ? "ready" : "missing"));
  console.log("prod deployment approval: " + (state.approvalFree ? "disabled" : "required"));
  if (!state.protectedMain || !state.approvalFree) process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
