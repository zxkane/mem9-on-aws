import {describe, expect, it, vi} from "vitest";
import {readFileSync} from "node:fs";
import {parse} from "yaml";
import {createAwsCliAdapter} from "./lib/workload-permissions-boundary-aws.mjs";
import {DEPLOY_ROLE_NAME, QUARANTINE_POLICY_NAME, quarantinePolicyDocument} from "./lib/workload-permissions-boundary.mjs";
import {createRetainedOperatorFixture} from "./test-fixtures/retained-operator.mjs";

const accountId = "123456789012", applicationRegion = "ap-northeast-1";
const names = [DEPLOY_ROLE_NAME, `${DEPLOY_ROLE_NAME}-preview`, `${DEPLOY_ROLE_NAME}-prod`].sort();
const arn = name => `arn:aws:iam::${accountId}:role/${name}`;
const arg = (args, name) => args[args.indexOf(name) + 1];
const boundaryArn = `arn:aws:iam::${accountId}:policy/mem9-on-aws-workload-boundary`;
const denyArn = `arn:aws:iam::${accountId}:policy/mem9-on-aws-deny-dangerous`;
const computeArn = `arn:aws:iam::${accountId}:policy/synthetic-compute`;
function enforcementPolicies() {
  const template = parse(readFileSync(new URL("../infra/cloudformation/github-actions-role.yaml", import.meta.url), "utf8"), {
    customTags: ["!Ref", "!Sub", "!GetAtt"].map(tag => ({tag, resolve: value => value}))
      .concat(["!If", "!Equals", "!Not"].map(tag => ({tag, collection: "seq", resolve: value => value}))),
  });
  const values = {"AWS::Partition": "aws", "AWS::AccountId": accountId, "AWS::Region": "us-west-2",
    "AWS::URLSuffix": "amazonaws.com", ApplicationRegion: applicationRegion, ProjectName: "mem9-on-aws",
    GitHubRepo: "mem9-on-aws", DecisionArtifactBucketName: `mem9-audit-${accountId}`};
  const render = value => Array.isArray(value) ? value.map(render) : value && typeof value === "object"
    ? Object.fromEntries(Object.entries(value).map(([k, v]) => [k, render(v)])) : typeof value === "string"
      ? Object.hasOwn(values, value) ? values[value] : value.replace(/\$\{([^}]+)\}/g, (_, key) => values[key] ?? `unresolved:${key}`)
      : value;
  return new Map([[denyArn, render(template.Resources.DenyPolicy.Properties.PolicyDocument)],
    [computeArn, render(template.Resources.ComputePolicy.Properties.PolicyDocument)],
    [`arn:aws:iam::${accountId}:policy/synthetic-scaffold`,render(template.Resources.ScaffoldPolicy.Properties.PolicyDocument)]]);
}

function fixture() {
  const calls = [], quarantined = new Set();
  const operators = createRetainedOperatorFixture();
  const stack = operators.stacks[DEPLOY_ROLE_NAME];
  const roles = new Map(Object.entries(operators.roles));
  let failDelete, failRestore, deletionStarted = false;
  let recoveryRead;
  let missingDenyFor;
  const policies = enforcementPolicies();
  const invokeAws = async args => {
    calls.push(args);
    const op = args.slice(0, 2).join(" "), name = arg(args, "--role-name");
    if (args[0] === 'cloudformation') return operators.invokeAws(args);
    switch (op) {
      case "cloudformation describe-stacks":
        expect(arg(args, "--stack-name")).toBe(DEPLOY_ROLE_NAME);
        expect(arg(args, "--region")).toBe("us-west-2");
        return {Stacks: [structuredClone(stack)]};
      case "iam get-role": return {Role: structuredClone(roles.get(name))};
      case "iam put-role-policy":
        expect(names).toContain(name); expect(arg(args, "--policy-name")).toBe(QUARANTINE_POLICY_NAME);
        if (deletionStarted && name === failRestore) throw Error("synthetic restore failure");
        quarantined.add(name); return {};
      case "iam get-role-policy":
        if (deletionStarted && recoveryRead) recoveryRead(name);
        if (!quarantined.has(name)) throw Error("synthetic missing policy");
        return {PolicyDocument: quarantinePolicyDocument()};
      case "iam simulate-custom-policy": {
        const start = args.indexOf("--action-names") + 1;
        const end = args.findIndex((v, index) => index >= start && v.startsWith("--"));
        return {EvaluationResults: args.slice(start, end < 0 ? undefined : end).map(EvalActionName => ({EvalActionName,
          ...(args.includes("--resource-arns") ? {EvalResourceName: arg(args, "--resource-arns"), MatchedStatements: [{SourcePolicyId: "synthetic"}]} : {}),
          EvalDecision: "explicitDeny"}))};
      }
      case "iam list-attached-role-policies": return {AttachedPolicies: [...policies.keys()]
        .filter(policyArn => name !== missingDenyFor || policyArn !== denyArn).map(PolicyArn => ({PolicyArn})), IsTruncated: false};
      case "iam get-policy": return {Policy: {DefaultVersionId: "v1"}};
      case "iam get-policy-version": return {PolicyVersion: {Document: policies.get(arg(args, "--policy-arn"))}};
      case "iam delete-role-policy":
        deletionStarted = true; quarantined.delete(name);
        if (name === failDelete) throw Error("synthetic lost delete response");
        return {};
      case "iam list-role-policies": return {PolicyNames: quarantined.has(name) ? [QUARANTINE_POLICY_NAME] : [], IsTruncated: false};
      default: throw Error(`unexpected synthetic command ${op}`);
    }
  };
  const deadlineAt = Date.now() + 60000;
  const adapter = createAwsCliAdapter({identity: {partition: "aws", accountId}, applicationRegion,
    invokeAws, consistencyAttempts: 1, sleep: async () => {}, deadlineAt});
  return {adapter, calls, stack, roles, quarantined, failDelete: name => {failDelete = name;},
    failRestore: name => {failRestore = name;}, missingDeny: name => {missingDenyFor = name;},
    deadlineAt, onRecoveryRead: fn => {recoveryRead = fn;}};
}

describe("authenticated deployment-role adapter", () => {
  it("resolves every owner-stack role including the retained disabled legacy role", async () => {
    const f = fixture();
    await expect(f.adapter.resolveDeploymentRoles()).resolves.toEqual(names);
    expect([...new Set(f.calls.filter(c => c[0] === "iam").map(c => arg(c, "--role-name")))].sort())
      .toEqual([...names, 'mem9-on-aws-preview-human-acceptance'].sort());
  });
  for (const kind of ["missing-output", "foreign-output", "wrong-stack", "wrong-region", "duplicate-output"]) {
    it(`rejects ${kind} before any IAM mutation`, async () => {
      const f = fixture();
      if (kind === "missing-output") f.stack.Outputs.pop();
      if (kind === "foreign-output") f.stack.Outputs[2].OutputValue = arn(names[1]).replace(accountId, "9".repeat(12));
      if (kind === "wrong-stack") f.stack.StackId += "/foreign";
      if (kind === "wrong-region") f.stack.Parameters.find(p => p.ParameterKey === 'ApplicationRegion').ParameterValue = "us-west-2";
      if (kind === "duplicate-output") f.stack.Outputs.push(f.stack.Outputs[0]);
      await expect(f.adapter.resolveDeploymentRoles()).rejects.toThrow(/deployment.role|ownership|catalog/i);
      expect(f.calls.some(c => /put|delete/.test(c[1]))).toBe(false);
    });
  }
  it("detects deletion and recreation with the same role ARN", async () => {
    const f = fixture(); await f.adapter.resolveDeploymentRoles();
    f.roles.get(names[1]).RoleId += "REPLACED";
    await expect(f.adapter.resolveDeploymentRoles()).rejects.toThrow(/deployment.role|ownership|catalog/i);
  });
  it("does not accept quarantine on only the legacy role", async () => {
    const f = fixture(); await f.adapter.resolveDeploymentRoles();
    f.quarantined.add(names[0]);
    await expect(f.adapter.verifyQuarantine()).resolves.toBe(false);
    for (const name of names) f.quarantined.add(name);
    await expect(f.adapter.verifyQuarantine()).resolves.toBe(true);
  });
  it("restores every role after a partially successful removal", async () => {
    const f = fixture(); await f.adapter.resolveDeploymentRoles();
    for (const name of names) f.quarantined.add(name);
    f.failDelete(names[1]);
    await expect(f.adapter.deleteQuarantines({roleNames: names, policyName: QUARANTINE_POLICY_NAME})).rejects.toThrow(/quarantine/i);
    expect([...f.quarantined].sort()).toEqual(names);
  });
  it("reports failed group recovery and still attempts all peers", async () => {
    const f = fixture(); await f.adapter.resolveDeploymentRoles();
    for (const name of names) f.quarantined.add(name);
    f.failDelete(names[1]); f.failRestore(names[0]);
    await expect(f.adapter.deleteQuarantines({roleNames: names, policyName: QUARANTINE_POLICY_NAME})).rejects.toThrow(/recovery/i);
    const putNames = f.calls.filter(c => c[1] === "put-role-policy").map(c => arg(c, "--role-name"));
    for (const name of names) expect(putNames).toContain(name);
  });
  it("does not let per-role recovery starve restoration of already released peers", async () => {
    let clock = Date.now();
    const spy = vi.spyOn(Date, "now").mockImplementation(() => clock);
    try {
      const f = fixture(); await f.adapter.resolveDeploymentRoles();
      for (const name of names) f.quarantined.add(name);
      f.failDelete(names[1]);
      f.onRecoveryRead(name => {
        if (name === names[1]) {
          clock = f.deadlineAt + 30001;
          throw Error("synthetic recovery observation deadline");
        }
      });
      await expect(f.adapter.deleteQuarantines({roleNames: names, policyName: QUARANTINE_POLICY_NAME})).rejects.toThrow(/recovery/);
      expect([...f.quarantined].sort()).toEqual(names);
      const restored = f.calls.filter(c => c[1] === "put-role-policy").map(c => arg(c, "--role-name"));
      for (const name of names) expect(restored).toContain(name);
    } finally {spy.mockRestore();}
  });
  it("removes the complete verified set and rejects a subset request", async () => {
    const f = fixture(); await f.adapter.resolveDeploymentRoles();
    for (const name of names) f.quarantined.add(name);
    await expect(f.adapter.deleteQuarantines({roleNames: names.slice(0, 1), policyName: QUARANTINE_POLICY_NAME})).rejects.toThrow(/deployment.role/i);
    expect(f.quarantined.size).toBe(3);
    await expect(f.adapter.deleteQuarantines({roleNames: names, policyName: QUARANTINE_POLICY_NAME})).resolves.toBeUndefined();
    expect(f.quarantined.size).toBe(0);
  });
  it("checks permanent policies and their actual deny attachment for every deployment role", async () => {
    const f = fixture(); await f.adapter.resolveDeploymentRoles();
    await expect(f.adapter.verifyPermanentEnforcement({boundaryArn, roleNames: names})).resolves.toBe(true);
    const inspected = f.calls.filter(c => c[1] === "list-attached-role-policies").map(c => arg(c, "--role-name"));
    for (const name of names) expect(inspected).toContain(name);
  });
  for (const name of names) it(`does not conceal missing permanent enforcement on ${name}`, async () => {
    const f = fixture(); await f.adapter.resolveDeploymentRoles();
    for (const roleName of names) f.quarantined.add(roleName);
    f.missingDeny(name);
    await expect(f.adapter.verifyPermanentEnforcement({boundaryArn, roleNames: names})).resolves.toBe(false);
  });
});
