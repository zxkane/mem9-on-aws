import {describe, expect, it} from "vitest";
import {
  DEPLOY_ROLE_NAME,
  QUARANTINE_POLICY_NAME,
  expectedRolePatterns,
  quarantinePolicyDocument,
  runBoundaryRollout,
} from "./lib/workload-permissions-boundary.mjs";

const identity = {partition: "aws", accountId: "123456789012"};
const names = [DEPLOY_ROLE_NAME, `${DEPLOY_ROLE_NAME}-preview`, `${DEPLOY_ROLE_NAME}-prod`].sort();
const boundaryArn = "arn:aws:iam::123456789012:policy/mem9-on-aws-workload-boundary";
const workload = "mem9-on-aws-prod-synthetic-worker";
const options = {...identity, boundaryArn, deployRoleName: DEPLOY_ROLE_NAME,
  reviewedCommit: "a".repeat(40), resumeCommand: "synthetic-resume"};

function fixture({incomplete, badScope, drift, failRelease, failEnforcement} = {}) {
  const calls = [], quarantined = new Set();
  let roleReads = 0, resumed = false;
  const adapter = {
    async verifyBoundaryRegion() {calls.push("region");},
    async verifyRetainedOperators() { return true; },
    async verifyRetainedOperatorEnforcement() { return true; },
    async resolveDeploymentRoles() {
      calls.push("deployment-roles");
      roleReads++;
      return incomplete || (drift && roleReads > 1) ? names.slice(0, 1) : [...names];
    },
    async putQuarantine({roleName, policyName, policyDocument}) {
      expect(names).toContain(roleName);
      expect(policyName).toBe(QUARANTINE_POLICY_NAME);
      expect(policyDocument).toEqual(quarantinePolicyDocument());
      quarantined.add(roleName); calls.push(`quarantine:${roleName}`);
    },
    async verifyQuarantine() {
      calls.push("verify-quarantine");
      return names.every(name => quarantined.has(name));
    },
    async deployBoundary() {
      expect([...quarantined].sort()).toEqual(names); calls.push("boundary");
    },
    async listAttachedPolicies({roleName}) {calls.push(`policies:${roleName}`); return {policies: []};},
    async listInlinePolicies() {return {policyNames: ["scope"]};},
    async getInlinePolicy({roleName}) {
      return {document: {Version: "2012-10-17", Statement: [{Effect: "Allow", Action: "iam:PassRole",
        Resource: roleName === badScope ? "*" : expectedRolePatterns(identity),
        Condition: {StringEquals: {"iam:PassedToService": ["lambda.amazonaws.com", "ecs-tasks.amazonaws.com"]}}}]}};
    },
    async listRoles() {return {roles: [{name: workload, arn: `arn:aws:iam::123456789012:role/${workload}`}]};},
    async verifyProductionRuntimeBindings() {return [workload];},
    async getRole() {return {permissionsBoundaryArn: boundaryArn};},
    async putRoleBoundary() {throw Error("unexpected boundary attachment");},
    async deployPermanentEnforcement() {calls.push("enforcement");},
    async verifyPermanentEnforcement({roleNames}) {
      expect(roleNames).toEqual(names); calls.push("verify-enforcement");
      return !failEnforcement;
    },
    async activateProductionBoundary() {calls.push("activate");},
    async verifyFinalGithubInterlock() {calls.push("interlock");},
    async deleteQuarantines({roleNames, policyName}) {
      expect(roleNames).toEqual(names); expect(policyName).toBe(QUARANTINE_POLICY_NAME);
      calls.push("release-all");
      if (failRelease) throw Error("release uncertain; quarantine retained");
      quarantined.clear();
    },
    async deleteQuarantine() {throw Error("single-role release forbidden");},
    async resumeDeployments() {resumed = true; calls.push("resume");},
  };
  return {adapter, calls, quarantined, resumed: () => resumed};
}

describe("authorization maintenance deployment-role coverage", () => {
  it("quarantines, reads and verifies every declared deployment role before coordinated release", async () => {
    const f = fixture();
    await expect(runBoundaryRollout(f.adapter, options)).resolves.toMatchObject({status: "complete"});
    expect(f.calls.filter(c => c.startsWith("quarantine:"))).toEqual(names.map(n => `quarantine:${n}`));
    for (const name of names) expect(f.calls).toContain(`policies:${name}`);
    expect(f.calls.filter(c => c === "release-all")).toHaveLength(1);
    expect(f.calls.at(-1)).toBe("resume"); expect(f.quarantined.size).toBe(0);
  });
  it("rejects incomplete deployment-role discovery before quarantine", async () => {
    const f = fixture({incomplete: true});
    await expect(runBoundaryRollout(f.adapter, options)).rejects.toThrow(/deployment.role/i);
    expect(f.quarantined.size).toBe(0); expect(f.calls).not.toContain("boundary");
  });
  it("does not let a valid legacy role conceal an unsafe production PassRole scope", async () => {
    const f = fixture({badScope: `${DEPLOY_ROLE_NAME}-prod`});
    await expect(runBoundaryRollout(f.adapter, options)).rejects.toThrow(/PassRole/);
    expect([...f.quarantined].sort()).toEqual(names); expect(f.resumed()).toBe(false);
  });
  it("holds quarantine when the declared role set changes during the rollout", async () => {
    const f = fixture({drift: true});
    await expect(runBoundaryRollout(f.adapter, options)).rejects.toThrow(/deployment.role/i);
    expect([...f.quarantined].sort()).toEqual(names); expect(f.resumed()).toBe(false);
  });
  it("does not release any role when permanent enforcement is incomplete", async () => {
    const f = fixture({failEnforcement: true});
    await expect(runBoundaryRollout(f.adapter, options)).rejects.toThrow(/enforcement/);
    expect(f.calls).not.toContain("release-all"); expect(f.resumed()).toBe(false);
  });
  it("reports an uncertain coordinated release without claiming deployment resumed", async () => {
    const f = fixture({failRelease: true});
    await expect(runBoundaryRollout(f.adapter, options)).rejects.toMatchObject({quarantineRemoved: false});
    expect([...f.quarantined].sort()).toEqual(names); expect(f.resumed()).toBe(false);
  });
});
