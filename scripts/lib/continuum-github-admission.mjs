import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile } from "node:fs/promises";
import { continuumApp, verifyApp } from "./continuum-auto-merge.mjs";
const exec = promisify(execFile);
export const cloudEnvironments = ["preview-ci", "preview-maintenance", "prod"];
const requireThat = (ok, message) => { if (!ok) throw new Error(message); };

export function verifyAwsPrTrust(roles, binding, repository, info) {
  const prefix = `repo:${repository}:`;
  const roleName = `github-actions-${repository.split("/")[1]}`;
  const expectedNames = [roleName, `${roleName}-preview`, `${roleName}-prod`];
  requireThat(Number.isSafeInteger(info?.id) && Number.isSafeInteger(info?.owner?.id), "GitHub immutable identity unavailable");
  requireThat(Array.isArray(roles) && roles.some(role => role.RoleName === `${roleName}-preview`) && roles.some(role => role.RoleName === `${roleName}-prod`), "Cannot verify current CI roles");
  for (const role of roles) {
    requireThat(expectedNames.includes(role?.RoleName) && role.Arn === `arn:aws:iam::${binding.accountId}:role/${role.RoleName}`, "CI role identity mismatch");
    const document = typeof role.AssumeRolePolicyDocument === "string" ? JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument)) : role.AssumeRolePolicyDocument;
    requireThat(Array.isArray(document?.Statement), "Invalid CI trust policy");
    const federated = `arn:aws:iam::${binding.accountId}:oidc-provider/token.actions.githubusercontent.com`;
    const denied = document.Statement.some(s => s.Effect === "Deny" && s.Action === "sts:AssumeRoleWithWebIdentity" && !s.Condition && s.Principal?.Federated === federated);
    // The retired legacy role has an explicit deny, not a fictitious environment.
    if (role.RoleName === roleName && denied) {
      requireThat(document.Statement.every(s => s.Effect === "Deny" || (s.Action === "sts:AssumeRoleWithWebIdentity" && s.Principal?.Federated === federated && Object.keys(s.Principal).length === 1)), "Retired CI role has an unreviewed alternate trust");
      continue;
    }
    for (const statement of document.Statement) {
      if (statement.Effect === "Deny") continue;
      const equals = statement.Condition?.StringEquals;
      const like = statement.Condition?.StringLike;
      const subjects = equals?.["token.actions.githubusercontent.com:sub"] ?? like?.["token.actions.githubusercontent.com:sub"];
      requireThat(statement.Effect === "Allow" && statement.Action === "sts:AssumeRoleWithWebIdentity" && statement.Principal?.Federated === federated && Object.keys(statement.Principal).length === 1 && Object.keys(statement.Condition ?? {}).every(key => ["StringEquals", "StringLike"].includes(key)) && Object.keys(like ?? {}).every(key => key === "token.actions.githubusercontent.com:sub") && equals?.["token.actions.githubusercontent.com:aud"] === "sts.amazonaws.com", "Unsupported CI trust requires review before robot PR activation");
      requireThat(equals["token.actions.githubusercontent.com:repository_id"] === String(info.id) && equals["token.actions.githubusercontent.com:repository_owner_id"] === String(info.owner.id), "CI trust must bind immutable repository identities");
      const owner = equals["token.actions.githubusercontent.com:actor_id"] === String(info.owner.id);
      const main = equals["token.actions.githubusercontent.com:ref"] === "refs/heads/main";
      requireThat(owner || main, "CI trust permits unreviewed robot PR credentials");
      for (const subject of Array.isArray(subjects) ? subjects : [subjects]) {
        requireThat(typeof subject === "string" && ["environment:preview-ci", "environment:preview-maintenance", "environment:prod", "ref:refs/heads/main"].some(value => subject === prefix + value), "CI role trusts unreviewed subject or another repository");
        if (subject === prefix + "environment:preview-ci") requireThat(owner, "Preview credentials require the owner actor");
      }
    }
  }
  return ["preview-maintenance", "prod"];
}

export function verifyMainProtection(protection) {
  const checks = protection?.required_status_checks;
  requireThat(protection?.enforce_admins?.enabled === true && protection.allow_force_pushes?.enabled === false && protection.allow_deletions?.enabled === false && checks?.strict === true && ["Runbook & Public-Content Scan", "Continuum PR admission", "Typecheck & Unit Tests"].every(name => checks.checks?.some(check => check.context === name && check.app_id === 15368)), "Main needs enforced strict GitHub Actions checks with force pushes and deletion disabled");
}

export function verifyGithubAdmission({ repository, mainProtection, tokenPolicy, runnerLabels, environments, app, requiredEnvironments = ["preview-maintenance", "prod"] }) {
  requireThat(repository.owner?.type === "User" && Number.isSafeInteger(repository.owner.id), "This admission check requires an individually owned repository");
  verifyMainProtection(mainProtection);
  verifyApp(app);
  requireThat(tokenPolicy.default_workflow_permissions === "read" && tokenPolicy.can_approve_pull_request_reviews === false, "Robot PRs require read-default workflow tokens without review approval permission");
  const hosted = ["ubuntu-latest", "ubuntu-24.04", "ubuntu-24.04-arm", "ubuntu-22.04", "ubuntu-22.04-arm"];
  requireThat(Array.isArray(runnerLabels) && runnerLabels.length === 1 && hosted.includes(runnerLabels[0]), "Robot PR runner isolation requires review; runner selection was not changed");
  for (const name of requiredEnvironments) {
    const environment = environments[name];
    const branchPolicy = environment?.deployment_branch_policy;
    const branches = environment?.branches;
    requireThat(branchPolicy?.custom_branch_policies === true && branchPolicy.protected_branches === false && Array.isArray(branches) && branches.length === 1 && branches[0].type === "branch" && branches[0].name === "main", `Unsafe robot PR AWS admission: ${name} needs exact main-only branches`);
  }
}

export async function checkGithubAdmission(repository, binding, api) {
  requireThat((await api.identity()).Account === binding.accountId, "AWS caller account does not match binding");
  const get = async (endpoint) => {
    const { stdout } = await exec("gh", ["api", "--hostname", "github.com", endpoint], { timeout: 30000, maxBuffer: 1024 * 1024 });
    return JSON.parse(stdout);
  };
  const root = `repos/${repository}`;
  const info = await get(root);
  requireThat(info.full_name === repository && info.html_url === `https://github.com/${repository}` && info.default_branch === "main", "GitHub.com repository identity mismatch");
  const requiredEnvironments = verifyAwsPrTrust(await api.ciRoles(repository), binding, repository, info);
  const mainProtection = await get(`${root}/branches/main/protection`);
  const tokenPolicy = await get(`${root}/actions/permissions/workflow`);
  const variables = await get(`${root}/actions/variables?per_page=100`);
  requireThat(Array.isArray(variables.variables) && variables.total_count <= 100, "Unable to verify complete runner configuration");
  const label = variables.variables.find(item => item.name === "RUNNER_LABEL")?.value;
  requireThat(variables.variables.find(item => item.name === "CONTINUUM_AUTO_MERGE_ENABLED")?.value === "true", "Continuum auto-merge controller must be enabled before patch creation");
  // The reviewed local controller and workflows must already be on main.
  // This also prevents activating a half-landed local working-tree change.
  for (const path of [".github/workflows/infra-ci.yml", ".github/workflows/docs-security.yml", ".github/workflows/runtime-recovery.yml", ".github/workflows/continuum-admission.yml", "scripts/check-continuum-pr.mjs", ".github/workflows/continuum-auto-merge.yml", "scripts/merge-continuum-prs.mjs", "scripts/lib/continuum-auto-merge.mjs"]) {
    const remote = await get(`${root}/contents/${path}?ref=main`);
    requireThat(remote.type === "file" && remote.encoding === "base64" && Buffer.from(remote.content, "base64").equals(await readFile(new URL(`../../${path}`, import.meta.url))), "Reviewed robot PR controls must match deployed main");
  }
  const environments = {};
  for (const name of requiredEnvironments) {
    const environment = await get(`${root}/environments/${name}`);
    if (environment.deployment_branch_policy?.custom_branch_policies) {
      const policies = await get(`${root}/environments/${name}/deployment-branch-policies?per_page=100`);
      requireThat(Array.isArray(policies.branch_policies) && policies.total_count <= 100, "Unable to verify complete deployment branch policy");
      environment.branches = policies.branch_policies;
    }
    environments[name] = environment;
  }
  verifyGithubAdmission({ repository: info, mainProtection, tokenPolicy, runnerLabels: label ? JSON.parse(label) : ["ubuntu-latest"], environments, requiredEnvironments, app: await get(`apps/${continuumApp.slug}`) });
}
