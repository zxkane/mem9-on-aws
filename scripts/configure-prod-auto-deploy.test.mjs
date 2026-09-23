import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import {
  assertMainOnlyEnvironment,
  isProtectedMain,
  mainProtection,
  prodEnvironment,
  reconcileProdAutoDeploy,
} from "./configure-prod-auto-deploy.mjs";

const repo = "example/project";
const root = "repos/" + repo;
const environmentPath = root + "/environments/prod";
const protectionPath = root + "/branches/main/protection";
const policies = {
  total_count: 1,
  branch_policies: [{ name: "main", type: "branch" }],
};
const environment = {
  deployment_branch_policy: {
    protected_branches: false,
    custom_branch_policies: true,
  },
  protection_rules: [
    { type: "branch_policy" },
    { type: "required_reviewers", reviewers: [{ type: "User" }] },
  ],
};
const verifiedProtection = {
  required_status_checks: {
    strict: true,
    contexts: ["Runbook & Public-Content Scan"],
  },
  required_pull_request_reviews: { required_approving_review_count: 0 },
  enforce_admins: { enabled: true },
  allow_force_pushes: { enabled: false },
  allow_deletions: { enabled: false },
};

function fakeApi(options = {}) {
  let currentEnvironment = structuredClone(options.environment || environment);
  const currentPolicies = structuredClone(options.policies || policies);
  let protection = options.protection === undefined ? null : options.protection;
  const calls = [];
  const api = (method, path, payload) => {
    calls.push({ method, path, payload });
    if (method === "GET" && path === root) {
      return { default_branch: "main", permissions: { admin: options.admin !== false } };
    }
    if (method === "GET" && path === root + "/branches/main") {
      return { name: "main" };
    }
    if (method === "GET" && path === environmentPath) return currentEnvironment;
    if (method === "GET" && path === environmentPath + "/deployment-branch-policies") {
      return currentPolicies;
    }
    if (method === "GET" && path === protectionPath) return protection;
    if (method === "PUT" && path === protectionPath) {
      protection = structuredClone(options.protectionAfterWrite || verifiedProtection);
      return protection;
    }
    if (method === "PUT" && path === environmentPath) {
      currentEnvironment = {
        deployment_branch_policy: payload.deployment_branch_policy,
        protection_rules: [{ type: "branch_policy" }],
      };
      return currentEnvironment;
    }
    throw new Error("unexpected API call: " + method + " " + path);
  };
  return { api, calls };
}

describe("prod automatic deployment protection", () => {
  it("protects main before removing prod reviewers", () => {
    const fake = fakeApi();
    expect(reconcileProdAutoDeploy(fake.api, repo, true)).toEqual({
      protectedMain: true,
      approvalFree: true,
    });
    const writes = fake.calls.filter((call) => call.method === "PUT");
    expect(writes.map((call) => call.path)).toEqual([
      protectionPath,
      environmentPath,
    ]);
    expect(writes[0].payload).toEqual(mainProtection);
    expect(writes[1].payload).toEqual(prodEnvironment);
    expect(mainProtection.required_pull_request_reviews.required_approving_review_count).toBe(0);
    expect(mainProtection.allow_force_pushes).toBe(false);
    expect(mainProtection.allow_deletions).toBe(false);
  });

  it("checks without modifying settings and preserves adequate existing protection", () => {
    const fake = fakeApi({ protection: structuredClone(verifiedProtection) });
    expect(reconcileProdAutoDeploy(fake.api, repo)).toEqual({
      protectedMain: true,
      approvalFree: false,
    });
    expect(fake.calls.filter((call) => call.method === "PUT")).toEqual([]);
    expect(reconcileProdAutoDeploy(fake.api, repo, true).approvalFree).toBe(true);
    expect(fake.calls.filter((call) => call.method === "PUT").map((call) => call.path))
      .toEqual([environmentPath]);
  });

  it("refuses to weaken a non-main deployment policy or unknown rule", () => {
    for (const invalid of [
      { ...policies, branch_policies: [{ name: "feature", type: "branch" }] },
      { ...policies, total_count: 2 },
    ]) {
      const fake = fakeApi({ policies: invalid });
      expect(() => reconcileProdAutoDeploy(fake.api, repo, true)).toThrow("exactly the main");
      expect(fake.calls.filter((call) => call.method === "PUT")).toEqual([]);
    }
    const fake = fakeApi({
      environment: {
        ...environment,
        protection_rules: [...environment.protection_rules, { type: "custom_deployment_protection_rule" }],
      },
    });
    expect(() => reconcileProdAutoDeploy(fake.api, repo, true)).toThrow("unknown protection");
    expect(fake.calls.filter((call) => call.method === "PUT")).toEqual([]);
  });

  it("refuses to overwrite different main protection before touching prod", () => {
    const fake = fakeApi({ protection: { required_status_checks: null } });
    expect(() => reconcileProdAutoDeploy(fake.api, repo, true)).toThrow("refusing to overwrite");
    expect(fake.calls.filter((call) => call.method === "PUT")).toEqual([]);
    expect(isProtectedMain(verifiedProtection)).toBe(true);
    expect(assertMainOnlyEnvironment(environment, policies)).toBe(true);
  });

  it("requires admin access and verified branch protection before removing reviewers", () => {
    const noAdmin = fakeApi({ admin: false });
    expect(() => reconcileProdAutoDeploy(noAdmin.api, repo, true)).toThrow("admin access");
    expect(noAdmin.calls.filter((call) => call.method === "PUT")).toEqual([]);

    const failedProtection = fakeApi({ protectionAfterWrite: {} });
    expect(() => reconcileProdAutoDeploy(failedProtection.api, repo, true))
      .toThrow("reviewers remain in place");
    expect(failedProtection.calls.filter((call) => call.method === "PUT").map((call) => call.path))
      .toEqual([protectionPath]);
  });

  it("keeps the production workflow, OIDC subject, and universal PR scan bound together", () => {
    const infra = parse(readFileSync(new URL("../.github/workflows/infra-ci.yml", import.meta.url), "utf8"));
    const docs = parse(readFileSync(new URL("../.github/workflows/docs-security.yml", import.meta.url), "utf8"));
    const trust = readFileSync(
      new URL("../infra/cloudformation/github-actions-role.yaml", import.meta.url),
      "utf8",
    );
    expect(infra.jobs["build-and-push-image"].environment).toContain("prod");
    expect(infra.jobs["deploy-prod"].environment).toBe("prod");
    expect(infra.jobs["deploy-prod"].needs).toContain("typecheck");
    for (const job of Object.values(infra.jobs)) {
      for (const step of job.steps || []) {
        if (step.uses && !step.uses.startsWith("./")) {
          expect(step.uses).toMatch(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@[0-9a-f]{40}$/u);
        }
      }
    }
    expect(docs.on.pull_request.branches).toContain("main");
    expect(docs.on.pull_request.paths).toBeUndefined();
    expect(docs.jobs.validate.name).toBe("Runbook & Public-Content Scan");
    expect(trust).toContain("environment:prod");
  });
});
