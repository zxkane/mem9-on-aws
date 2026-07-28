# Design Canvas - workload permissions boundary

Feature: Enforced boundary for passable workload roles
Date: 2026-07-27
Status: Approved

## Component Architecture

```text
Operator identity
  |
  +-- deploy-workload-permissions-boundary.sh
  |     `-- retained CloudFormation stack
  |           `-- AWS::IAM::ManagedPolicy
  |                 name: mem9-on-aws-workload-boundary
  |
  `-- rollout-workload-permissions-boundary.sh
        `-- run-workload-permissions-boundary-rollout.mjs
              `-- rollout-workload-permissions-boundary.mjs
                    |
                    +-- install inline quarantine on github-actions-mem9-on-aws
                    +-- read every deployed managed and inline policy
                    +-- derive exact iam:PassRole resource patterns
                    +-- enumerate roles
                    +-- discover every live ECS, Lambda, and AgentCore role binding
                    +-- verify every live production ECS secret reference
                    +-- verify every live llm-proxy uses the boundary stack project
                    +-- attach/read back the boundary
                    +-- re-read the PassRole policy set and require equality
                    +-- deploy permanent GitHub-role enforcement
                    +-- verify scope, boundaries, and enforcement
                    +-- activate/read back the production boundary transform
                    +-- revalidate reviewed GitHub state and maintenance interlocks
                    +-- recheck and remove quarantine after every check passes
                    `-- enable/read back both deployment workflows, then unpause

SST application
  `-- global aws.iam.Role transform
        `-- permissionsBoundary =
              arn:${partition}:iam::${account}:policy/
              mem9-on-aws-workload-boundary
```

The boundary stack and migration run under the operator profile. Pull-request
and production deployment jobs can reference the boundary but cannot modify its
policy, ownership stack, or the deploy-role stack.

Pre-migration GitHub AWS jobs intentionally skip while the production activation
flag is false, so the implementation PR has no AWS preview. The boundary stack
must instead be prepared before a manual non-production deployment or the first
post-migration GitHub preview. Preparation creates only the unattached managed
policy required by role creation; it does not migrate existing roles or activate
permanent deploy-role enforcement. Any later stack update and all role mutations
remain one guarded maintenance-window operation.

## Boundary Contract

The common boundary is an explicit-deny maximum-permission ceiling for the
current runtime roles:

- ECS image pull, log delivery, and Secrets Manager startup injection.
- ECS Exec control/data channels for the server and bootstrap task roles.
- Lambda log delivery and VPC network-interface lifecycle.
- The OAuth facade's SSM reads and KMS decrypt, constrained to Parameter Store
  in the application region and the project parameter hierarchy.
- Alert-router failure delivery to project/stage-prefixed SQS queues.
- AgentCore Gateway invocation of the proxy Lambda.
- Bedrock Mantle inference and project reads from the ECS task role.

Role identity policies keep their existing resource-level least privilege. The
boundary grants nothing by itself because identity or resource policies must
still allow each request. Its `Allow "*"` is paired with an explicit
`Deny`/`NotAction` ceiling: every action outside the reviewed runtime set is
explicitly denied. This shape is required because a same-account resource policy
that names an assumed-role session does not require an explicit boundary allow;
[AWS still applies an explicit boundary deny](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html).
An implicit action allow-list would therefore leave a bypass.

Additional explicit denies constrain otherwise permitted actions to project
resources, Parameter Store KMS context and service, and short-term Mantle
bearers. ENI actions are exposed only to the generated VPC proxy Lambda role and
are denied whenever `lambda:SourceFunctionArn` is present, so function code
cannot use the Lambda service's VPC permissions. Permanent deploy-role
enforcement also prevents a matching VPC proxy role from being passed to ECS or
AgentCore. Before attachment and at every frozen-state check, rollout verifies
that every proxy-pattern role in the complete project IAM inventory has exactly
one Lambda-only trust statement. Production ECS task definitions and the
AgentCore Gateway independently reject proxy-pattern roles. The generated
role-name match is not treated as an authorization factor by itself: exact
Lambda-only trust, the `iam:PassedToService=lambda.amazonaws.com` restriction,
and the function-code deny are all required. Under the documented
trusted-writer model, creating another matching VPC Lambda can let only the
Lambda service perform its VPC attachment lifecycle; it does not expose those
EC2 actions to function code or another workload service.

This common policy is a project-wide action/resource ceiling, not a stage
isolation boundary. Pull-request and production jobs currently assume the same
deploy role, which can write identity policies on any bounded project role.
Separating preview and production trust requires distinct OIDC deploy roles and
is not claimed by this design.

The repository variables and workflow gates are mechanical maintenance
interlocks, not an authorization boundary against someone who can modify the
workflow itself. This private repository assumes trusted writers and no
concurrent workflow or repository-settings changes during rollout. If
untrusted pull requests or additional writers enter the threat model, the
operator must remove the `pull_request` subject from the deploy role's OIDC
trust out of band before the implementation window and restore it only after
permanent enforcement is verified.

GitHub repository state and AWS IAM state cannot participate in one atomic
transaction. The rollout therefore revalidates the reviewed GitHub state at the
last possible point, then rechecks quarantine before deleting it. This narrows
the cross-system observation-to-mutation window but does not make it atomic; the
trusted-writer and no-concurrent-settings-change assumptions are required.

The managed policy has `DeletionPolicy: Retain` and
`UpdateReplacePolicy: Retain`. Its fixed name is functional: the deploy-role
conditions, rollout verifier, and SST transform must all reference one stable
ARN. Existing-stack updates also change `PolicyRevision`, which is used only in
a statement SID. That forces CloudFormation to publish the desired policy
document and repair direct drift without changing effective permissions.

## Migration State Machine

```text
verify exact reviewed workflow blobs, clean exact-head checkout, and idle runs
  -> PUT and verify deploy-role quarantine
  -> install/verify boundary stack
  -> read PassRole scope A
  -> enumerate matching roles
  -> require every proxy-pattern role in the full inventory to trust only Lambda
  -> read the complete boundary ownership stack in us-west-2
  -> require its ApplicationRegion and BedrockProjectArn parameters
  -> read prod cluster/service/bootstrap parameters in ap-northeast-1
  -> inspect every service deployment, RUNNING/PENDING task, and bootstrap task definition
  -> require MEM9_DB_SECRET and MEM9_TENANT_ID to reference current-account,
     current-region mem9-on-aws-* Secrets Manager ARNs
  -> require exactly one llm-proxy in every service task definition and require
     LLM_PROXY_OPENAI_PROJECT to equal the boundary stack project ID
  -> list every mem9-on-aws-prod-* Lambda and read the production AgentCore Gateway
  -> collect ECS task/execution, Lambda execution, and Gateway service role ARNs
  -> reject proxy-pattern ECS or AgentCore bindings
  -> require every bound role to belong to the complete migration inventory
  -> attach and read back every boundary
  -> read PassRole scope B
  -> require A == B
  -> deploy permanent enforcement
  -> read PassRole scope C
  -> verify C == A, live role bindings are unchanged, and all boundaries match
  -> verify permanent policy statements
  -> redeploy/read back the exact active boundary default policy version
  -> set/read back WORKLOAD_BOUNDARY_PROD_ENABLED=true
  -> repeat scope, live binding, boundary, and enforcement checks
  -> require the default branch still equals the reviewed commit
  -> require both reviewed workflow blobs are unchanged
  -> require DEPLOYMENT_MAINTENANCE_PAUSED=true
  -> require both deployment workflows remain disabled_manually
  -> require zero queued, in_progress, requested, waiting, and pending runs
  -> recheck quarantine after the complete GitHub interlock
  -> DELETE deploy-role quarantine
  -> enable/read back Infra CI and preview reconciliation
  -> set/read back DEPLOYMENT_MAINTENANCE_PAUSED=false
```

Any error before verified quarantine removal exits with quarantine treated as
installed. A failure while resuming deployments happens only after permanent
enforcement and quarantine removal; the controller restores and reads back the
pause, then disables and reads back every workflow that this invocation enabled.
If either rollback fails, output explicitly says the deployment state is unsafe
instead of claiming restoration. Every failure prints a redacted resume command,
never role inventories, account identifiers, complete ARNs, or policy documents.
Before mutation, the shell wrapper writes the effective non-secret profile and
region settings, VPC and template-bucket selectors, plus the expected AWS
account and partition to the gitignored, mode-`0600`
`.env.workload-boundary-resume` file. The printed command sets
`WORKLOAD_BOUNDARY_SKIP_DOTENV=false` and reloads that normalized context, and
the wrapper refuses an identity mismatch before any IAM mutation. Successful
completion removes the file. While retained state exists, an initial invocation
is rejected before any GitHub or AWS call; only the printed resume command can
reload it. This preserves a custom
`WORKLOAD_BOUNDARY_ENV_FILE`, an ambient `AWS_PROFILE`, and every non-secret
selector consumed by the two downstream deployment scripts without putting
credentials or the account identifier in terminal output.
The shell wrapper holds a nonblocking checkout-local `flock` for its complete
run, so concurrent invocations cannot overwrite or remove another invocation's
resume file. During the IAM phase it traps `SIGINT` and `SIGTERM`, forwards the
signal to the bounded Node process, waits until the child has completed its
quarantine recovery path, and preserves exit code 130 or 143.
Quarantine removal is successful only when the delete call succeeds and a
bounded, paginated read proves the inline policy absent. A failed delete,
lost-success response, unreadable listing, or unverified absence is ambiguous:
the adapter reinstalls the exact quarantine, verifies its policy and simulator
effects, then fails the rollout without resuming deployments. If that recovery
also fails, the result explicitly reports unsafe ambiguity. A delete error enters
recovery immediately instead of spending consistency retries on the aborted or
expired operational context. Deletion runs outside the operational deadline
proxy because an interrupted response is itself the state that must be
recovered. Reinstallation and verification use a fresh, non-aborted signal, a
five-second cap per AWS command, and an independent budget that cannot pass the
original hard deadline.

Workflow-enable or unpause failure uses the same recovery rule as ambiguous
quarantine deletion: pause restoration and workflow disable/read-back run with
a fresh signal, five-second command caps, and the original 30-second hard
deadline reserve. An already-aborted operational signal cannot short-circuit
that rollback.

The reusable Node module exports only dependency-injected test seams. Live AWS
and GitHub wiring is in a dedicated CLI that refuses to run unless the shell
wrapper marks its exact-head, workflow-blob, pause, and two drain checks as
complete. The exact-head push run must be completed with the non-AWS
`Typecheck & Unit Tests` job successful. Its AWS jobs are expected to fail or
skip while the migration flag remains false, so rollout never requires a
pre-migration production deploy. The wrapper passes the reviewed commit as a
required CLI argument; the state machine does not infer or default it.

`CREATE_COMPLETE` and `UPDATE_COMPLETE` are normal ownership-stack states.
`UPDATE_ROLLBACK_COMPLETE` can be repaired only inside the guarded rollout and
forces an update even when the current managed-policy document matches;
`--verify-only` rejects it. `UPDATE_ROLLBACK_FAILED` requires an explicit
CloudFormation `continue-update-rollback` operation before the guarded retry.

Every AWS CLI call has a 60-second process timeout, GitHub CLI calls have a
30-second timeout, deploy subprocesses have a 20-minute timeout, and the whole
shell-preflight-through-resume operation shares one absolute 45-minute
hard deadline. The operational deadline is 30 seconds earlier so Node can abort
AWS, GitHub, and deploy subprocess groups, send `SIGTERM`, escalate to
`SIGKILL`, observe leader and process-group closure, and complete its failure
path before the outer shell issues a final hard kill. Failure to observe cleanup
inside the bounded grace is reported as a distinct cleanup error rather than
being treated as successful termination. `SIGINT` and `SIGTERM`, including a
signal delivered only to the shell wrapper PID, use the same abort path and
preserve conventional exit codes 130 and 143. The shell clamps every GitHub call
and the Node process to the remaining budget; Node receives that original
operational deadline instead of starting a new window. If
interruption or deadline expiry makes the final quarantine delete ambiguous,
the reserved 30-second window permits the independent recovery context above to
reinstall and verify quarantine before exit. IAM, ECS, and Lambda pagination has
both page and item ceilings in addition to repeated-token detection. Exceeding
any limit fails closed while quarantine remains installed.

## PassRole Scope Rules

- Read both managed and inline deploy-role policies with full pagination.
- Accept only explicit `iam:PassRole` allows. Wildcard actions, `NotAction`, and
  unrecognized policy shapes fail closed.
- Accept only the three deployed project role patterns, including SST's known
  truncation variants. Wildcards are allowed only as the final character.
- Require `iam:PassedToService` to remain within Lambda, ECS tasks, and Bedrock
  AgentCore.
- Derive the migration set by matching the deployed patterns against the
  paginated IAM role inventory. Never enumerate from tags or a hard-coded list.
- Re-read the deployed policy set before and after permanent enforcement.

## Permanent Enforcement

The GitHub Actions role:

- requires the exact boundary on `CreateRole` and
  `PutRolePermissionsBoundary`;
- permits `PutRolePolicy` and `AttachRolePolicy` only when the target role
  already carries the exact boundary;
- explicitly denies `DeleteRolePermissionsBoundary`;
- prevents VPC proxy Lambda roles from being passed to non-Lambda services;
- keeps read, detach, inline-policy delete, and role delete for preview cleanup;
- explicitly denies mutation of the boundary policy and the operator-owned
  boundary, deploy-role, and ECR scanning ownership stacks.
- can read only the fixed boundary managed policy so every normal AWS deployment
  verifies the exact active default policy document through `--verify-only`.

Role deletion does not remove the boundary first. IAM deletes the role and its
boundary association together.

## Pulumi Role And Lifecycle Evidence

One infrastructure test derives the workload-role inventory from the project
source and the installed SST component implementation. It proves that the three
Lambda roles, ECS service task/execution roles, bootstrap task/execution roles,
and explicit AgentCore Gateway role are exactly eight AWS IAM role resources and
that every one receives the exact boundary through the real Pulumi transform.

A separate test uses Pulumi Automation API with a local file backend and two
updates across dynamic fixtures derived from all eight actual role descriptors.
The real Pulumi engine executes create, update, and destroy. The provider fails
every create, update, or delete that does not carry the exact boundary, exported
pre-destroy state retains that boundary in all eight inputs and outputs, and
engine summaries prove eight role creates, updates, and deletes plus the stack
resource. The provider exposes no boundary-detach operation.

The state-machine mutation tests rewrite and import the real rollout module.
Moving the quarantine block after discovery or weakening the missing-boundary
read-back check makes the invariant harness fail. This proves the tests guard
the implementation ordering and coverage logic rather than only a fake adapter.

The unfiltered Documentation Security workflow checks out full history, resolves
the event base to a merge base, and scans every commit message, changed path, and
target blob in each commit through the event head. A credential added in one
commit and deleted in a later commit therefore still fails the change. The
testable scanner covers account IDs, accountless S3/Route 53 ARNs, RDS, API
Gateway, Cognito hosted-domain, and AgentCore Gateway endpoints, variable-length
Cognito pool IDs, Cognito client IDs, AWS and GitHub credentials, private keys,
bearer/API credentials, client secrets, private repository references, and
comment permalinks. It reports commit, path or commit-message location, line,
and category without credential values; a path that itself contains a detected
value is replaced with `<redacted-path>`. Patterns and adversarial fixtures are
encoded so they cannot match their own source.

## Recovery And Rollback

- Run the printed resume command after correcting an error. It reloads the
  retained local context, verifies the AWS identity and existing quarantine,
  rejects nonterminal or failed rollback stack state, forces a guarded policy
  rewrite for drift or `UPDATE_ROLLBACK_COMPLETE`, and resumes idempotently. A
  structurally invalid or unsupported deployed PassRole scope must be corrected
  first; retrying it unchanged fails closed again with quarantine retained.
- Never remove quarantine manually while the discovered role set is partially
  bounded.
- Rollback is forward-fix only. It may narrow the explicit runtime ceiling, but
  it must retain the role transform, production activation, future-role boundary
  enforcement, and boundary-removal denial.
- Never deploy a revision that omits the boundary, explicitly sets the
  production activation variable back to `false`, or removes it. A missing value
  fails synthesis; `false` asks Pulumi to remove boundaries and permanent IAM
  enforcement denies that mutation. Keep maintenance paused, restore the
  boundary-aware exact head, verify every boundary, and redeploy.
- Rollout to the live account and production smoke verification belong to the
  release-verification issue, not this implementation change.
