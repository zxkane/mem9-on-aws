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
- ECS startup decrypt for only the DB and tenant secret families, mediated by
  Secrets Manager in the application region and limited to the four
  execution-role types (server, bootstrap, consolidation, cleanup).
- ECS Exec control/data channels for the server and bootstrap task roles.
- Lambda log delivery and VPC network-interface lifecycle.
- The OAuth facade's SSM reads and KMS decrypt, constrained to Parameter Store
  in the application region and the project parameter hierarchy. Lambda cold
  starts may also decrypt only with a
  `kms:EncryptionContext:aws:lambda:FunctionArn` matching a project function.
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
resources, the project Parameter Store, Lambda function, or Secrets Manager
`SecretARN` KMS contexts, and short-term Mantle bearers. The boundary does not
require `kms:ViaService` for Lambda's default environment-key grant. Every other
decrypt must be mediated by application-region SSM or Secrets Manager. A
`SecretARN` path is further restricted to the four ECS execution-role types and
the known DB/tenant secret families; a Lambda source remains denied on this path.
AWS returns the IAM role ARN, not an STS session ARN, for
[`aws:PrincipalArn`](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html).
The negated `...IfExists` operators intentionally remain fail closed when their
keys are absent. The facade identity policy independently pins the SSM service
and project parameter context. A decrypt without an approved project context
remains denied by the boundary. ENI actions are exposed only to
the generated VPC proxy Lambda role and
are denied whenever `lambda:SourceFunctionArn` is present, so function code
cannot use the Lambda service's VPC permissions. Permanent deploy-role
enforcement prevents every allowlisted Lambda role type from being passed to ECS
or AgentCore and every allowlisted ECS execution-role type from being passed to
Lambda or AgentCore. This is a `PassRole` control, not proof of role provenance:
`CreateRole` does not expose the submitted trust policy as an IAM condition key,
so a repository writer could create a matching role that is directly assumable.
The accepted trusted-writer model excludes that caller. Before any workflow can
give untrusted pull-request code a GitHub OIDC token, the emitted subject must
be identified and every matching deploy-role trust entry removed out of band.
Before any stack module is imported, one global
`sst.aws.Function` component transform overrides every generated execution role
with one exact trust statement for `lambda.amazonaws.com`. This also covers
future application Functions. It compensates for the pinned SST version
constructing an account-root principal alongside Lambda when its
development-mode `Output` is tested as a plain boolean.

The boundary verifier enforces both policy shape and evaluated behavior. Every
guarded rollout and normal deployment preflight custom-simulates 17
`kms:Decrypt` cases against the live default boundary version:

- Project Lambda function context without `kms:ViaService`: allowed.
- Optional facade-authorizer Lambda context without `kms:ViaService`: allowed.
- Project SSM parameter context from function code via SSM: allowed.
- Project DB secret from the server execution role via Secrets Manager: allowed.
- Project tenant secret from the bootstrap execution role via Secrets Manager:
  allowed.
- Direct call with a project SSM parameter context: explicit deny.
- Direct call with a project secret context: explicit deny.
- Out-of-project secret via Secrets Manager: explicit deny.
- Project secret via Secrets Manager from an ECS task role: explicit deny.
- Project secret via Secrets Manager from a Lambda role: explicit deny.
- Project secret through a cross-region Secrets Manager path: explicit deny.
- Project secret through SSM: explicit deny.
- Project parameter through Secrets Manager: explicit deny.
- Direct function-code call with a forged project Lambda context: explicit deny.
- Non-Lambda workload role with a forged project Lambda context: explicit deny.
- Out-of-project Lambda function context: explicit deny.
- No approved encryption context: explicit deny.

This matrix catches policy-semantics regressions before deployment and rechecks
that the simulated version remains the active default. It does not prove which
context keys AWS services supply. A forced Lambda cold start, ECS replacement,
and bootstrap task remain the integration checks; an existing warm workload can
hide a decrypt regression.

During initial migration discovery only, rollout may repair the exact legacy
shape emitted by that bug: one otherwise exact assume-role statement whose
principal contains only Lambda plus the current-account root. It first
classifies the complete role inventory, so an unknown principal or extra field
stops all trust writes. For each eligible role it re-reads trust immediately
before `UpdateAssumeRolePolicy`, writes the exact Lambda-only policy, and reads
it back. A retry accepts roles already repaired and continues with the
remainder. Every later frozen-state check is validation-only and rejects any
non-Lambda-only trust.

Production ECS task definitions and the AgentCore Gateway independently reject
proxy-pattern roles. The generated role-name match is not treated as an
authorization factor by itself: exact Lambda-only trust, the
`iam:PassedToService=lambda.amazonaws.com` restriction, and the function-code
deny are all required. Under the documented trusted-writer model, creating
another matching VPC Lambda can let only the Lambda service perform its VPC
attachment lifecycle; it does not expose those EC2 actions to function code or
another workload service.

This common policy is a project-wide action/resource ceiling, not a stage
isolation boundary. Pull-request and production jobs currently assume the same
deploy role, which can write identity policies on any bounded project role.
Separating preview and production trust requires distinct OIDC deploy roles and
is not claimed by this design.

The repository variables and workflow gates are mechanical maintenance
interlocks, not an authorization boundary against someone who can modify the
workflow itself. This public repository accepts untrusted fork pull requests.
[GitHub documents](https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions#using-secrets-in-a-workflow)
that fork-triggered workflows do not receive repository secrets except
`GITHUB_TOKEN`.
[It also documents](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#how-permissions-are-calculated-for-a-workflow-job)
that fork-triggered `pull_request` runs have every requested write permission
reduced to read-only. The `id-token` permission supports only `write` or `none`,
and
[GitHub requires `id-token: write`](https://docs.github.com/en/actions/reference/security/oidc#workflow-permissions-for-the-requesting-the-oidc-token)
to request an OIDC token. A public-fork run therefore cannot mint the token
needed by `AssumeRoleWithWebIdentity`. The role ARN enters the checked-in
workflow only as `secrets.AWS_ROLE_ARN`, so the fork-triggerable AWS jobs also
skip their official AWS path when that secret is absent. That gate is an
operational interlock. A role ARN is an identifier, not an authorization
boundary; IAM authorizes the token against the role's audience and subject
conditions.

The deploy role's `pull_request` subject remains in its OIDC trust for
same-repository preview runs. This argument does not rely on whether `vars.*`
reaches fork-triggered workflows. Writers who can modify same-repository
workflow code are trusted, and no concurrent workflow or repository-settings
changes are allowed during rollout. Before any workflow can give untrusted
pull-request code `id-token: write`, including a `pull_request_target` path, the
operator must identify the subject that workflow emits and remove every
matching subject from the deploy-role trust out of band. Trust is restored only
after permanent enforcement is verified.

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
  -> PUT and read back the exact deploy-role quarantine
  -> custom-simulate its cross-service probes against the default * resource
  -> re-read the exact quarantine
  -> install/verify boundary stack
  -> read PassRole scope A
  -> enumerate matching roles
  -> classify all alert-router, OAuth-facade, and VPC-proxy Lambda role trusts
  -> fail before trust mutation unless every non-current policy is the exact
     Lambda plus current-account-root legacy shape
  -> for each exact legacy role: re-read, update to Lambda-only, and read back
  -> read the complete boundary ownership stack in us-west-2
  -> require its ApplicationRegion and BedrockProjectArn parameters
  -> read prod cluster/service/bootstrap parameters in the sst.config.ts application region
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
  -> require A == B and every known Lambda role still has Lambda-only trust
  -> deploy permanent enforcement
  -> read PassRole scope C
  -> verify C == A, live role bindings are unchanged, and all boundaries match
  -> verify permanent policy statements
  -> require the exact permanent deny managed policy to be attached
  -> custom-simulate the permanent deny policy alone
  -> re-read its attachment/default version and the complete policy aggregate
  -> redeploy/read back the exact active boundary default policy version
  -> set/read back WORKLOAD_BOUNDARY_PROD_ENABLED=true
  -> require the default branch still equals the reviewed commit
  -> require both reviewed workflow blobs are unchanged
  -> require DEPLOYMENT_MAINTENANCE_PAUSED=true
  -> require both deployment workflows remain disabled_manually
  -> require zero queued, in_progress, requested, waiting, and pending runs
  -> repeat validation-only trust, scope, live binding, boundary, and enforcement checks
  -> recheck quarantine after the complete GitHub and frozen-state interlock
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

Quarantine and permanent-enforcement probes use `SimulateCustomPolicy` on
documents read back from the target role. The quarantine document is an exact
`Deny`, `Action: "*"`, `Resource: "*"` policy, so its cross-service probe omits
resource ARNs and evaluates each action against the simulator's default `*`.
Passing one IAM role ARN for CloudFormation, ECR, ECS, Lambda, S3, and SSM
actions yields resource-type mismatches instead of testing the deny.

The permanent probe first requires the fixed
`mem9-on-aws-deny-dangerous` managed-policy ARN in the role's paginated attached
policy inventory, then simulates only that policy. The temporary quarantine
therefore cannot mask missing permanent denies. Principal simulation is not a
reliable substitute here: AWS documents that SCPs do not affect principals in
an Organizations management account and that simulator results can differ from
live authorization. In this account, the management-account SCP view
short-circuited principal simulation before role policies were matched.

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

The read-only deployment preflight keeps every mismatch fatal but reports its
cause. Exact-document drift emits only a bounded list of added, removed, or
changed statement Sids and actions; resources, complete documents, account ids,
and uncontrolled text are never logged. Tokens present only in the live policy
are always redacted and counted; only expected, checked-in tokens are named. On
pull requests, the script also
verifies the deployed document with the verifier from the trusted base commit.
A base match is an expected pre-rollout change and points to the guarded
rollout. A non-match, unavailable base, or non-pull-request invocation is
unexplained deployed drift and must be investigated as a possible out-of-band
IAM change. KMS simulation failure and a default-version race have separate
messages and remain mutation-free.

Every AWS CLI call has a 60-second process timeout, GitHub CLI calls have a
30-second timeout, deploy subprocesses have a 20-minute timeout, and the whole
shell-preflight-through-resume operation shares one absolute 60-minute hard
deadline. This covers repeated exact read-backs for large retained preview-role
inventories without weakening any fail-closed gate. The operational deadline is
30 seconds earlier so Node can abort
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
- prevents all four allowlisted Lambda execution-role types, including the
  optional facade authorizer, from being passed to non-Lambda services;
- keeps read, detach, inline-policy delete, and role delete for preview cleanup;
- explicitly denies mutation of the boundary policy and the operator-owned
  boundary, deploy-role, and ECR scanning ownership stacks.
- can read only the fixed boundary managed policy and custom-simulate its
  repository-verified document so every normal AWS deployment verifies the
  exact active default policy and KMS behavior through `--verify-only`.

Role deletion does not remove the boundary first. IAM deletes the role and its
boundary association together.

## Pulumi Role And Lifecycle Evidence

One infrastructure test derives both switch-state workload-role inventories
from the project source and installed SST component implementation. It proves
that the default graph contains exactly eight AWS IAM roles, the enabled graph
adds only the facade-authorizer role, and every role in both graphs receives the
exact boundary through the real Pulumi transform.

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

The accountless-S3 detector decides on the BUCKET SEGMENT alone, because S3
bucket names are one global namespace and a name is a targeting hint with or
without an account id in the ARN. Three shapes disclose no name and are exempt:
a wildcard or interpolated segment (a pattern, not a name), a name suffixed with
the documentation account id (the placeholder the account-id detector already
blesses), and the bare noun `bucket` that prose about `bucket/*` versus `bucket`
matching has to say out loud. The object key is deliberately excluded from the
decision — keying off the whole ARN would let the trailing `/*` that every real
S3 policy resource already ends in vouch for the name in front of it. Before
#150 no accountless S3 ARN existed anywhere in the tree, so this rule had never
run against real policy content; the exemptions and their limits are pinned by
adversarial fixtures rather than by inspection.

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
