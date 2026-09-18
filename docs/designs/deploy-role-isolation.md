# Deploy role isolation

## Objective

Separate pull-request preview lifecycle permissions from production deployment
permissions while retaining one operator-owned CloudFormation stack and the
existing SST application account.

## Identity boundary

- `github-actions-mem9-on-aws-preview` trusts only the unprotected `preview-ci`
  environment used by PR deploy/build/cleanup jobs and the dedicated
  `preview-maintenance` environment used by scheduled reconciliation.
- `github-actions-mem9-on-aws-prod` trusts only this repository's protected
  `prod` Environment subject.
- The legacy shared role remains available during rollout. Retirement disables
  its OIDC trust while retaining the resource for boundary-tool compatibility.

Both roles reuse the existing resource-type managed policies. Each role carries
an inline explicit-deny policy for the opposite stage, including tagged
resources, SSM paths, SST state objects, secrets, ECS, Lambda, RDS, and workload
IAM role names. The split trust policy is the primary boundary; stage denies are
defense in depth.

## Workflow boundary

A repository-owned classifier groups changed paths into:

- workload-image inputs;
- application IaC;
- workflow/IAM/test/documentation-only changes.

Only workload inputs build the complete four-image shared-tag release. An
application-IaC-only production deployment reads the currently deployed image
tag from stage SSM. A workflow/IAM/test/documentation-only push performs tests
but creates no ECR tag, task-definition revision, ECS rollout, or SST mutation.

Every credential-bearing production job is directly associated with the
protected `prod` GitHub Environment, and the production role trusts only that
environment subject. Pull-request mutations use the unprotected `preview-ci`
environment and the preview role.

## Rollout

1. Configure and read back `prod`, `preview-ci`, and `preview-maintenance`
   Environment branch/protection rules.
2. Deploy the additive role-stack revision with the legacy role retained.
3. Configure the new role secrets.
4. Merge the workflow change; changed-path classification must skip application
   mutation for that merge.
5. Verify a disposable preview using only the preview role.
6. Verify the production approval wait, then approve one production deployment.
7. Verify representative opposite-stage requests are denied.
8. Redeploy the owner stack with the legacy trust disabled and remove the old
   repository secret.

Rollback before step 8 restores the old repository secret/workflow reference.
After step 8, rollback uses the explicit `--enable-legacy` operator action.
Ordinary stack updates preserve the deployed disabled state and cannot silently
restore shared trust. Rollback never broadens trust to fork pull requests.
