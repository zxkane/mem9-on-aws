import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { cloudEnvironments, verifyGithubAdmission, verifyAwsPrTrust, verifyMainProtection } from "./lib/continuum-github-admission.mjs";
import { classifyChangedPaths } from "./classify-infra-changes.mjs";

function input() {
  return {
    repository: { owner: { type: "User", id: 7 } },
    mainProtection: {
      required_pull_request_reviews: { required_approving_review_count: 1, dismiss_stale_reviews: true, require_last_push_approval: true },
      enforce_admins: { enabled: true }, allow_force_pushes: { enabled: false }, allow_deletions: { enabled: false },
      required_status_checks: { strict: true, contexts: ["Runbook & Public-Content Scan"] },
    },
    tokenPolicy: { default_workflow_permissions: "read", can_approve_pull_request_reviews: false },
    runnerLabels: ["ubuntu-24.04-arm"],
    environments: Object.fromEntries(cloudEnvironments.map((name) => [name, {
      deployment_branch_policy: { custom_branch_policies: true, protected_branches: false },
      branches: [{ type: "branch", name: "main" }],
    }])),
  };
}

describe("Continuum PR cloud admission", () => {
  it("accepts exact main-only cloud environments", () => expect(() => verifyGithubAdmission(input())).not.toThrow());
  it("accepts an owner-reviewed preview while preserving main-only prod", () => {
    const value = input();
    value.environments["preview-ci"] = {
      can_admins_bypass: false,
      protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 7 } }] }],
    };
    expect(() => verifyGithubAdmission(value)).not.toThrow();
    value.environments["preview-ci"].can_admins_bypass = true;
    expect(() => verifyGithubAdmission(value)).toThrow(/admission/i);
    value.environments["preview-ci"].can_admins_bypass = false;
    value.environments["preview-ci"].protection_rules[0].reviewers.push({ type: "User", reviewer: { id: 8 } });
    expect(() => verifyGithubAdmission(value)).toThrow(/admission/i);
  });
  it.each(["preview-ci", "preview-maintenance", "prod"])("blocks an unprotected %s", (name) => {
    const value = input();
    value.environments[name] = { deployment_branch_policy: null, protection_rules: [] };
    expect(() => verifyGithubAdmission(value)).toThrow(/admission/i);
  });
  it("rejects wildcard branches, tags, writable tokens and self-hosted runners", () => {
    for (const mutate of [
      (value) => { value.environments.prod.branches[0].name = "*"; },
      (value) => { value.environments.prod.branches[0].type = "tag"; },
      (value) => { value.tokenPolicy.default_workflow_permissions = "write"; },
      (value) => { value.tokenPolicy.can_approve_pull_request_reviews = true; },
      (value) => { value.runnerLabels = ["self-hosted", "linux"]; },
      (value) => { delete value.environments["preview-maintenance"]; },
    ]) {
      const value = input(); mutate(value);
      expect(() => verifyGithubAdmission(value)).toThrow();
    }
  });
  it("refuses automatic merging or App review bypasses even with main-only environments", () => {
    for (const mutate of [
      (value) => { value.required_pull_request_reviews.required_approving_review_count = 0; },
      (value) => { value.required_pull_request_reviews.dismiss_stale_reviews = false; },
      (value) => { value.required_pull_request_reviews.require_last_push_approval = false; },
      (value) => { value.required_pull_request_reviews.bypass_pull_request_allowances = { apps: [{ id: 1 }] }; },
      (value) => { value.enforce_admins.enabled = false; },
    ]) {
      const value = input(); mutate(value.mainProtection);
      expect(() => verifyGithubAdmission(value)).toThrow(/Main needs/);
    }
    expect(() => verifyMainProtection(null)).toThrow(/Main needs/);
  });
  it("keeps known template subjects covered by the live IAM inspection", async () => {
    const source = await readFile(new URL("../infra/cloudformation/github-actions-role.yaml", import.meta.url), "utf8");
    const subjects = [...source.matchAll(/repo:\$\{GitHubOrg\}\/\$\{GitHubRepo\}:([^\s"']+)/gu)].map((match) => match[1]);
    expect([...new Set(subjects)].sort()).toEqual([...cloudEnvironments.map((name) => `environment:${name}`), "environment:legacy-role-disabled", "ref:refs/heads/main", "pull_request"].sort());
  });
  it("rejects an enabled legacy PR trust and includes dormant environment subjects", () => {
    const binding = { accountId: "123456789012" };
    const role = (suffix, subject) => ({
      RoleName: `github-actions-repository${suffix}`,
      Arn: `arn:aws:iam::${binding.accountId}:role/github-actions-repository${suffix}`,
      AssumeRolePolicyDocument: { Statement: [{
        Effect: "Allow", Action: "sts:AssumeRoleWithWebIdentity",
        Principal: { Federated: `arn:aws:iam::${binding.accountId}:oidc-provider/token.actions.githubusercontent.com` },
        Condition: { StringEquals: { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com", "token.actions.githubusercontent.com:sub": `repo:owner/repository:${subject}` } },
      }] },
    });
    const roles = [role("-preview", "environment:preview-ci"), role("-prod", "environment:prod")];
    expect(verifyAwsPrTrust(roles, binding, "owner/repository")).toEqual(cloudEnvironments);
    expect(() => verifyAwsPrTrust([...roles, role("", "pull_request")], binding, "owner/repository")).toThrow(/unreviewed/);
    expect(verifyAwsPrTrust([...roles, role("", "environment:legacy-role-disabled")], binding, "owner/repository")).toContain("legacy-role-disabled");
    expect(() => verifyAwsPrTrust([], binding, "owner/repository")).toThrow(/verify/);
    roles[0].Arn = roles[0].Arn.replace(binding.accountId, "9".repeat(12));
    expect(() => verifyAwsPrTrust(roles, binding, "owner/repository")).toThrow(/identity/);
  });
  it("keeps only the independent declaration out of application deployment", () => {
    expect(classifyChangedPaths(["infra/continuum/environment.json", "scripts/deploy-continuum.mjs", "scripts/continuum/package-lock.json"])).toEqual({ workloadChanged: false, applicationInfrastructureChanged: false, awsMutationRequired: false });
    expect(classifyChangedPaths(["infra/continuum/other.ts"])).toMatchObject({ awsMutationRequired: true });
    expect(classifyChangedPaths(["infra/continuum/environment.json", "infra/ecs.ts"])).toMatchObject({ awsMutationRequired: true });
  });
});
