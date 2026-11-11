import { describe, expect, it } from "vitest";
import { verifyGithubAdmission, verifyAwsPrTrust, verifyMainProtection } from "./lib/continuum-github-admission.mjs";
import { continuumApp } from "./lib/continuum-auto-merge.mjs";
const repository = { id: 42, owner: { type: "User", id: 7 } };
function input() {
  return {
    repository,
    app: { ...continuumApp, owner: { login: "AWS-Continuum" }, permissions: { contents: "write", pull_requests: "write", metadata: "read" } },
    mainProtection: { required_pull_request_reviews: { required_approving_review_count: 0 }, enforce_admins: { enabled: true }, allow_force_pushes: { enabled: false }, allow_deletions: { enabled: false }, required_status_checks: { strict: true, checks: ["Runbook & Public-Content Scan", "Continuum PR admission", "Typecheck & Unit Tests"].map(context => ({ context, app_id: 15368 })) } },
    tokenPolicy: { default_workflow_permissions: "read", can_approve_pull_request_reviews: false },
    runnerLabels: ["ubuntu-24.04-arm"],
    environments: Object.fromEntries(["preview-maintenance", "prod"].map(name => [name, { deployment_branch_policy: { custom_branch_policies: true, protected_branches: false }, branches: [{ type: "branch", name: "main" }] }])),
  };
}
describe("Continuum PR cloud admission", () => {
  it("allows CI automatic merge without imposing human approval", () => expect(() => verifyGithubAdmission(input())).not.toThrow());
  it("rejects missing or forgeable required check provenance", () => {
    for (const change of [value => value.required_status_checks.checks.pop(), value => value.required_status_checks.checks[0].app_id = null, value => value.required_status_checks.strict = false, value => value.enforce_admins.enabled = false, value => value.allow_force_pushes.enabled = true]) {
      const protection = input().mainProtection; change(protection); expect(() => verifyMainProtection(protection)).toThrow();
    }
    expect(() => verifyMainProtection(null)).toThrow();
  });
  it("rejects wildcard or missing production environments and privileged test tokens", () => {
    for (const change of [value => value.environments.prod.branches[0].name = "*", value => delete value.environments.prod, value => value.tokenPolicy.default_workflow_permissions = "write", value => value.runnerLabels = ["self-hosted"], value => value.app.permissions.workflows = "write"]) {
      const value = input(); change(value); expect(() => verifyGithubAdmission(value)).toThrow();
    }
  });
  it("requires immutable owner-only preview trust and an explicitly retired legacy role", () => {
    const binding = { accountId: "123456789012" };
    const federated = `arn:aws:iam::${binding.accountId}:oidc-provider/token.actions.githubusercontent.com`;
    const role = (suffix, environment) => ({ RoleName: `github-actions-project${suffix}`, Arn: `arn:aws:iam::${binding.accountId}:role/github-actions-project${suffix}`, AssumeRolePolicyDocument: { Statement: [{ Effect: "Allow", Action: "sts:AssumeRoleWithWebIdentity", Principal: { Federated: federated }, Condition: { StringEquals: { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com", "token.actions.githubusercontent.com:sub": `repo:owner/project:environment:${environment}`, "token.actions.githubusercontent.com:repository_id": "42", "token.actions.githubusercontent.com:repository_owner_id": "7", ...(suffix === "-prod" ? { "token.actions.githubusercontent.com:ref": "refs/heads/main" } : { "token.actions.githubusercontent.com:actor_id": "7" }) } } }] } });
    const roles = [role("-preview", "preview-ci"), role("-prod", "prod")];
    const check = value => verifyAwsPrTrust(value, binding, "owner/project", repository);
    expect(check(roles)).toEqual(["preview-maintenance", "prod"]);
    for (const claim of ["actor_id", "repository_id", "repository_owner_id"]) {
      const copy = structuredClone(roles); delete copy[0].AssumeRolePolicyDocument.Statement[0].Condition.StringEquals[`token.actions.githubusercontent.com:${claim}`]; expect(() => check(copy)).toThrow();
    }
    const legacy = role("", "legacy-role-disabled");
    expect(() => check([...roles, legacy])).toThrow();
    legacy.AssumeRolePolicyDocument.Statement.push({ Effect: "Deny", Action: "sts:AssumeRoleWithWebIdentity", Principal: { Federated: federated } });
    expect(() => check([...roles, legacy])).not.toThrow();
    expect(() => check([])).toThrow();
  });
});
