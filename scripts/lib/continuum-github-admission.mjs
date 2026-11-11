import { execFile } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execFile);

// These are the exact GitHub environment subjects trusted by the project's
// current OIDC ownership stack. Tests keep this set aligned with the template.
export const cloudEnvironments = ["preview-ci", "preview-maintenance", "prod"];

export function verifyAwsPrTrust(roles, binding, repository) {
  const required = new Set(cloudEnvironments);
  const prefix = `repo:${repository}:`;
  const roleName = `github-actions-${repository.split("/")[1]}`;
  const expectedNames = [roleName, `${roleName}-preview`, `${roleName}-prod`];
  if (!Array.isArray(roles) || !roles.some((role) => role?.RoleName === `${roleName}-preview`) || !roles.some((role) => role?.RoleName === `${roleName}-prod`)) throw new Error("Cannot verify current CI roles");
  for (const role of roles) {
    if (!expectedNames.includes(role?.RoleName) || role.Arn !== `arn:aws:iam::${binding.accountId}:role/${role.RoleName}`) throw new Error("CI role identity mismatch");
    const document = typeof role.AssumeRolePolicyDocument === "string" ? JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument)) : role.AssumeRolePolicyDocument;
    if (!Array.isArray(document?.Statement)) throw new Error("Invalid CI trust policy");
    for (const statement of document.Statement) {
      if (statement.Effect === "Deny") continue;
      const equals = statement.Condition?.StringEquals;
      const like = statement.Condition?.StringLike;
      const subjects = equals?.["token.actions.githubusercontent.com:sub"] ?? like?.["token.actions.githubusercontent.com:sub"];
      if (statement.Effect !== "Allow" || statement.Action !== "sts:AssumeRoleWithWebIdentity" || statement.Principal?.Federated !== `arn:aws:iam::${binding.accountId}:oidc-provider/token.actions.githubusercontent.com` || Object.keys(statement.Principal).length !== 1 || Object.keys(statement.Condition ?? {}).some((key) => !["StringEquals", "StringLike"].includes(key)) || Object.keys(like ?? {}).some((key) => key !== "token.actions.githubusercontent.com:sub") || equals?.["token.actions.githubusercontent.com:aud"] !== "sts.amazonaws.com") throw new Error("Unsupported CI trust requires review before enabling robot PRs");
      for (const subject of Array.isArray(subjects) ? subjects : [subjects]) {
        if (subject === `${prefix}ref:refs/heads/main`) continue;
        if (typeof subject !== "string" || !subject.startsWith(`${prefix}environment:`)) throw new Error("CI role trusts unreviewed pull requests or another repository");
        const environment = subject.slice(`${prefix}environment:`.length);
        if (!/^[a-z][a-z0-9-]{0,63}$/u.test(environment)) throw new Error("Unsafe CI environment subject");
        required.add(environment);
      }
    }
  }
  return [...required];
}

export function verifyMainProtection(protection) {
  const review = protection?.required_pull_request_reviews;
  const bypass = review?.bypass_pull_request_allowances ?? {};
  const checks = protection?.required_status_checks;
  if (!(review?.required_approving_review_count >= 1) || review.dismiss_stale_reviews !== true || review.require_last_push_approval !== true || Object.values(bypass).some((entries) => !Array.isArray(entries) || entries.length > 0) || protection.enforce_admins?.enabled !== true || protection.allow_force_pushes?.enabled !== false || protection.allow_deletions?.enabled !== false || checks?.strict !== true || !checks.contexts?.includes("Runbook & Public-Content Scan")) throw new Error("Main needs enforced human PR approval, stale-review dismissal, latest-push approval, required checks and no review bypasses before robot PR activation");
}

export function verifyGithubAdmission({ repository, mainProtection, tokenPolicy, runnerLabels, environments, requiredEnvironments = cloudEnvironments }) {
  if (repository.owner?.type !== "User" || !Number.isSafeInteger(repository.owner.id)) throw new Error("This admission check requires an individually owned repository");
  verifyMainProtection(mainProtection);
  if (tokenPolicy.default_workflow_permissions !== "read" || tokenPolicy.can_approve_pull_request_reviews !== false) throw new Error("Robot PRs require read-default workflow tokens without review approval permission");
  // Preserve the configured runner. Refuse to activate an unreviewed route to
  // a persistent/self-hosted runner, rather than silently choosing another.
  const hosted = ["ubuntu-latest", "ubuntu-24.04", "ubuntu-24.04-arm", "ubuntu-22.04", "ubuntu-22.04-arm"];
  if (!Array.isArray(runnerLabels) || runnerLabels.length !== 1 || !hosted.includes(runnerLabels[0])) throw new Error("Robot PR runner isolation requires review; runner selection was not changed");
  for (const name of requiredEnvironments) {
    const environment = environments[name];
    if (!environment) throw new Error(`Missing GitHub cloud environment protection: ${name}`);
    const branchPolicy = environment.deployment_branch_policy;
    const branches = environment.branches;
    const mainOnly = branchPolicy?.custom_branch_policies === true && branchPolicy.protected_branches === false && Array.isArray(branches) && branches.length === 1 && branches[0].type === "branch" && branches[0].name === "main";
    const reviewers = environment.protection_rules?.find((rule) => rule.type === "required_reviewers");
    const ownerApproval = environment.can_admins_bypass === false && reviewers?.prevent_self_review === true && reviewers.reviewers?.length === 1 && reviewers.reviewers[0].type === "User" && reviewers.reviewers[0].reviewer?.id === repository.owner.id;
    if (!mainOnly && !ownerApproval) throw new Error(`Unsafe robot PR AWS admission: ${name} needs main-only branches or non-bypassable owner approval`);
  }
}

export async function checkGithubAdmission(repository, binding, api) {
  const identity = await api.identity();
  if (identity.Account !== binding.accountId) throw new Error("AWS caller account does not match binding");
  const requiredEnvironments = verifyAwsPrTrust(await api.ciRoles(repository), binding, repository);
  const get = async (endpoint) => {
    const { stdout } = await exec("gh", ["api", "--hostname", "github.com", `repos/${repository}/${endpoint}`.replace(/\/$/u, "")], { timeout: 30000, maxBuffer: 1024 * 1024 });
    return JSON.parse(stdout);
  };
  const info = await get("");
  if (info.full_name !== repository || info.html_url !== `https://github.com/${repository}` || info.default_branch !== "main") throw new Error("GitHub.com repository identity mismatch");
  const mainProtection = await get("branches/main/protection");
  verifyMainProtection(mainProtection);
  const tokenPolicy = await get("actions/permissions/workflow");
  const variables = await get("actions/variables?per_page=100");
  if (!Array.isArray(variables.variables) || variables.total_count > 100) throw new Error("Unable to verify complete runner configuration");
  const label = variables.variables.find((item) => item.name === "RUNNER_LABEL")?.value;
  const environments = {};
  for (const name of requiredEnvironments) {
    const environment = await get(`environments/${name}`);
    if (environment.deployment_branch_policy?.custom_branch_policies) {
      const policies = await get(`environments/${name}/deployment-branch-policies?per_page=100`);
      if (!Array.isArray(policies.branch_policies) || policies.total_count > 100) throw new Error("Unable to verify complete deployment branch policy");
      environment.branches = policies.branch_policies;
    }
    environments[name] = environment;
  }
  verifyGithubAdmission({ repository: info, mainProtection, tokenPolicy, runnerLabels: label ? JSON.parse(label) : ["ubuntu-latest"], environments, requiredEnvironments });
}
