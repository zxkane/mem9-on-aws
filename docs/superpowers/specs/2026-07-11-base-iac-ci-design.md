# mem9-on-aws — Base IaC + CI (design spec)

Date: 2026-07-11
Status: **approved design, review-hardened, implementing**
Scope owner: single operator (`zxkane`), deploys to AWS Tokyo.

> **Review-hardened 2026-07-11** — a 3-model llm-team panel (codex/GPT-5.4,
> deepseek, glm5) reviewed this spec. Adopted fixes are folded in below and
> marked **[R]**. Adjudications: `getVpcOutput()` usage is correct (kept as-is,
> rejecting a rewrite suggestion); `iam:CreateServiceLinkedRole` deferred to the
> AgentCore-Lattice follow-up. Synthesis:
> `~/.llm-team-sessions/mem9-spec-review/round-001/synthesis.md`.

## Goal

Stand up the **base IaC scaffold** for mem9-on-aws (an SST v4 app) plus a
GitHub Actions CI pipeline where **push to `main` deploys to AWS as prod**.
Reference implementation: `zxkane/llm-wiki`'s `infra-ci.yml` + `sst.config.ts`.
This is the foundation every later stack (Aurora, ECS, AgentCore Gateway,
Cognito) builds on — those are explicitly **out of scope** here and land in
follow-up PRs/issues.

## Non-goals (deferred to follow-up work)

- Aurora PostgreSQL / pgvector (`infra/db.ts`)
- ECS Fargate 3-container task (mnemo-server + qwen3 sidecar + token-refresh)
- Internal ALB + public ACM cert + AgentCore Gateway + managed VPC Lattice
- Cognito M2M pool + interceptor Lambda
- Bedrock Mantle auth + Bedrock Project + qwen3 embedding
- Schema-bootstrap one-shot task
- Any E2E test job (no mem9 service to probe yet)

## Hard rules honored (from `~/.claude/CLAUDE-AWS.md` + project CLAUDE.md)

- **Node.js 24 everywhere**: `.nvmrc=24`, `engines.node>=24`, CI `setup-node: 24`,
  `$transform` forces `nodejs24.x` on any Lambda.
- **NO Lambda Function URL** — ever. The scaffold has no Lambda; when the
  AgentCore interceptor Lambda lands later it is invoked by the Gateway (resource
  policy scoped to the service), never via a Function URL.
- **OIDC deploy role is out-of-band CloudFormation**, pinned to `us-west-2`,
  reuses the account OIDC provider, split ManagedPolicies (<6144 bytes each),
  explicit deny for dangerous IAM/Org/CloudTrail/GuardDuty, `iam:PassRole` gated
  by `iam:PassedToService`.
- **prod**: `removal: "retain"` + `protect: true`.
- **CI auth via GitHub OIDC** (no long-lived keys); store only the role ARN.
- **Self-hosted runners** via the `RUNNER_LABEL` ternary (personal `zxkane/*`
  repo): `runs-on: ${{ vars.RUNNER_LABEL && fromJSON(vars.RUNNER_LABEL) || 'ubuntu-latest' }}`.
- **No secrets committed**: `<aws-account-id>` placeholders; no ARNs with account
  numbers, no API keys.

## Verified environment facts (probed 2026-07-11, `kane-global-mengxinz`)

Deploy profile: **`kane-global-mengxinz`** (IAM user `kane`, account
`<aws-account-id>`, global partition) — used for local `sst deploy` and
bootstrapping the OIDC role. CI itself uses OIDC, not this profile.

Tokyo (`ap-northeast-1`) **default VPC** (172.31.0.0/16) is customized and
production-ready (concrete resource ids omitted — they leak account topology):

| Resource | Fact |
|---|---|
| Private subnets | `private-1a/1c/1d` across 3 AZs (172.31.96/112/128.0/20), `MapPublicIpOnLaunch=false` |
| NAT | 1 NAT gateway (available, in `public-1c`) |
| Private routing | all 3 private subnets route `0.0.0.0/0` → the NAT (verified) |
| Public subnets | `public-1a/1c/1d` route via the IGW (main RT) |
| Secondary | extra `secondary-private-subnet-2a/2c/2d` in a second CIDR (172.32.x) — **excluded** by the `private-1*` name filter |

→ Confirms ARCHITECTURE.md's assumption: the default VPC has NAT-routed private
subnets, so ECS + Aurora can live there with no dedicated VPC. This fact is also
recorded in `docs/mem9-facts.md`.

## Repo layout

```
mem9-on-aws/
├── sst.config.ts              # SST v4 root (region, prod retain/protect, $transform nodejs24.x)
├── .nvmrc                     # 24
├── package.json               # root: engines>=24, test/typecheck (vitest + tsc)
├── package-lock.json          # [R] REQUIRED — CI's root `npm ci` fails without it
├── tsconfig.json
├── vitest.config.ts
├── infra/
│   ├── package.json           # mem9-on-aws-infra, pnpm, engines>=24
│   ├── pnpm-lock.yaml
│   ├── tsconfig.json
│   ├── sst-types.d.ts         # ambient shim (llm-wiki pattern)
│   ├── vpc.ts                 # VPC resolver (MEM9_VPC_ID env → import; else default VPC)
│   ├── meta.ts                # SSM placeholder stack
│   ├── config.test.ts
│   ├── vpc.test.ts
│   └── meta.test.ts
├── infra/cloudformation/
│   └── github-actions-role.yaml    # out-of-band OIDC deploy role (us-west-2)
├── scripts/
│   └── deploy-github-role.sh
└── .github/workflows/
    └── infra-ci.yml
```

## Component 1 — `sst.config.ts`

- `app()`: name `mem9-on-aws`, `home: "aws"`, region `ap-northeast-1`,
  `removal: stage==="prod" ? "retain" : "remove"`, `protect: stage==="prod"`,
  `defaultTags: { Project: "mem9-on-aws", Stage, ManagedBy: "sst" }`.
- `run()`: `$transform(aws.lambda.Function, …)` → set `nodejs24.x` (skip
  `packageType: "Image"`). Lazy `import("./infra/meta")` then call `meta()`.
- Header comment records the two standing rules: **nodejs24.x** and **no Lambda
  Function URL**.

## Component 2 — `infra/vpc.ts` (lookup only, no billable resources)

```ts
export function resolveVpc() {
  const explicitId = process.env.MEM9_VPC_ID?.trim();
  const vpc = explicitId
    ? aws.ec2.getVpcOutput({ id: explicitId })   // import existing
    : aws.ec2.getVpcOutput({ default: true });   // account default VPC
  const privateSubnets = aws.ec2.getSubnetsOutput({
    filters: [
      { name: "vpc-id", values: [vpc.id] },
      { name: "tag:Name", values: ["private-1*"] },  // 3 NAT-routed private subnets
    ],
  });
  return { vpcId: vpc.id, privateSubnetIds: privateSubnets.ids };
}
```

- `MEM9_VPC_ID` set → imports that VPC (fails loud at deploy if the ID is absent
  in-region — no silent fallback).
- unset → the account default VPC.
- Deploy-role impact: read-only `ec2:DescribeVpcs/DescribeSubnets/DescribeRouteTables`.

## Component 3 — `infra/meta.ts` (SSM placeholder stack)

Cheap deployable stack that proves the pipeline + establishes the SSM namespace.

SSM namespace convention (locked for the whole project):
`/mem9-on-aws/${stage}/<component>/<key>`

| Parameter | Value | Type |
|---|---|---|
| `/mem9-on-aws/${stage}/meta/stage` | `$app.stage` | String |
| `/mem9-on-aws/${stage}/vpc/id` | resolved VPC id | String |
| `/mem9-on-aws/${stage}/vpc/private-subnet-ids` | comma-joined subnet ids | StringList |

Future stacks extend: `.../db/endpoint`, `.../gateway/url`, `.../cognito/client-id`.

Deploy-role impact: `ssm:PutParameter/GetParameter/DeleteParameter/
AddTagsToResource/ListTagsForResource` on `arn:aws:ssm:ap-northeast-1:<aws-account-id>:parameter/mem9-on-aws/*`.

## Component 4 — out-of-band OIDC deploy role

`infra/cloudformation/github-actions-role.yaml` (deployed via
`scripts/deploy-github-role.sh`, pinned `us-west-2`):

- Role `mem9-on-aws-github-actions`, trust policy for the existing GitHub OIDC
  provider. **Reuse** the account OIDC provider (never create a duplicate).
  - **[R] Trust policy is tight**: `aud (…:aud) = sts.amazonaws.com` (required by
    `configure-aws-credentials`), and `sub (…:sub)` scoped to exactly the refs
    CI uses — `repo:zxkane/mem9-on-aws:ref:refs/heads/main` and
    `repo:zxkane/mem9-on-aws:pull_request` — via `StringLike`, NOT the broad
    `repo:zxkane/mem9-on-aws:*`.
- ManagedPolicies (each < 6144 bytes). **[R] The role carries DIRECT
  resource-level grants for everything the deploy touches** — it does NOT lean on
  `cloudformation:*` to provision resources. SST v4 provisions via **Pulumi**
  (S3/DynamoDB state backend), not CloudFormation, so `cloudformation:*` would be
  useless for creating app resources; the role must be able to create the actual
  resources directly:
  - `mem9-SstState` — S3 (broad, for Pulumi bucket probes on `sst-state-*`) +
    SSM `ssm:GetParameter*`/`PutParameter`/`DeleteParameter`/`DescribeParameters`
    on `/sst/bootstrap*` (state-lock + bootstrap markers SST reads/writes) +
    `s3:*` on the `sst-state-*` bucket for the state backend.
  - `mem9-Scaffold` — the actual scaffold resource grants:
    - `ec2:DescribeVpcs`/`DescribeSubnets`/`DescribeRouteTables` (RO, Component 2 lookup)
    - `ssm:PutParameter`/`GetParameter`/`GetParameters`/`DeleteParameter`/
      `AddTagsToResource`/`RemoveTagsFromResource`/`ListTagsForResource` on
      `arn:aws:ssm:ap-northeast-1:<aws-account-id>:parameter/mem9-on-aws/*`
      **[R] — this is the grant that lets the `meta` stack actually create its
      SSM params; without it the first deploy 403s.**
    - `sts:GetCallerIdentity`/`sts:AssumeRole` (self, for the preflight check).
    - **[R] `iam:PassRole` with an explicit `Resource`** (`arn:aws:iam::<aws-account-id>:role/mem9-on-aws-*`
      + the SST-truncation variants) **AND** an `iam:PassedToService` condition —
      never `Resource: "*"`, never unconstrained.
  - `mem9-Deny` — explicit deny for dangerous IAM/Org/account/CloudTrail/GuardDuty.
- Allow-lists SST's Lambda-role-name truncation variants proactively (in the
  `iam:PassRole` resource list + any future Lambda-role grants).
- **Grants are scaffold-scoped**: every future resource TYPE (Aurora, ECS, ALB,
  AgentCore — the last needs `iam:CreateServiceLinkedRole` for managed Lattice,
  per the panel) needs new grants added to this template + re-bootstrap **before**
  that PR can deploy. Documented in the template header.

Operator one-time step: run `deploy-github-role.sh` (profile
`kane-global-mengxinz`), then store the printed role ARN as the repo's
**`AWS_ROLE_ARN`** GitHub Actions secret.

## Component 5 — `.github/workflows/infra-ci.yml`

Mirrors llm-wiki's `infra-ci.yml`, minus app-specific E2E. Region
`ap-northeast-1`; `runs-on` via the `RUNNER_LABEL` ternary (self-hosted).

| Job | Trigger | Behavior |
|---|---|---|
| `typecheck` | every PR (not closed) + push-to-main | pnpm infra install/typecheck/test + root npm ci/typecheck/test. Node 24. Always runs (no AWS). |
| `deploy-preview` | PR opened/sync/reopened, base=`main` | Gate on `AWS_ROLE_ARN` (skip if unset) → OIDC → **[R] preflight** → strip stale Pulumi → `sst unlock` → `sst deploy --stage pr-N` → PR comment. Auto-cleanup on deploy failure. |
| `cleanup-preview` | PR closed, base=`main` | Check SST state exists (via `/sst/bootstrap` SSM → state bucket → head-object) → `sst remove --stage pr-N` (refuses non-`pr-*`). |
| `deploy-prod` | push to `main` | `environment: prod`, singleton **non-cancelable** concurrency, **[R] hard-fail (exit 1) if `AWS_ROLE_ARN` unset**, OIDC → **[R] preflight** → stale-lock recovery by age (>30 min, from S3 lock-object `LastModified`), `sst deploy --stage prod`, auto-file GH issue on failure. |

**[R] Pre-deploy preflight** (shared step in every deploy/cleanup job, right
after OIDC): run `aws sts get-caller-identity` + `aws iam get-role
--role-name mem9-on-aws-github-actions`; on failure emit `::error::` naming the
likely cause (role not bootstrapped / bad `AWS_ROLE_ARN` / OIDC trust mismatch)
and exit 1 — so a missing role fails red with a clear message instead of a
cryptic Pulumi timeout.

**[R] Concurrency**: `push` → singleton `infra-deploy-prod`, `cancel-in-progress:
false` (never interrupt a prod deploy). PR → **per-PR group**
`infra-ci-pr-<number>`, `cancel-in-progress: true` (repeated `synchronize`
events supersede, never race the same `pr-N` stage's unlock/deploy).

Shared: OIDC (`configure-aws-credentials@v6`, `id-token: write`),
"Remove conflicting Pulumi installation" step (self-hosted cache hygiene),
path filters (`infra/**`, `sst.config.ts`, the workflow, `scripts/**`, root
manifests; **exclude** `infra/cloudformation/**`). **[R] Gate asymmetry**:
`deploy-prod` HARD-FAILS on missing `AWS_ROLE_ARN` (a silent skip would violate
"main deployment must work"); `deploy-preview`/`cleanup-preview` skip gracefully
(a fork/contributor PR without secrets still gets `typecheck`). `typecheck`
always runs.

## Component 6 — testing & verification

Unit tests (Vitest + Pulumi mock harness, side-effect-free factory imports):

- `config.test.ts` — region, prod retain/protect, `$transform` → nodejs24.x, defaultTags.
- `vpc.test.ts` — `MEM9_VPC_ID` set vs unset paths; private-subnet filter shape.
- `meta.test.ts` — SSM param names/types; `/mem9-on-aws/${stage}/...` prefix invariant.

Verification ladder before merge:
1. Typecheck + unit tests green (infra + root).
2. Local deploy proof (`kane-global-mengxinz`): `sst deploy --stage <dev>` →
   assert the 3 SSM params + VPC resolution → `sst remove --stage <dev>`.
3. CI proof: after bootstrapping the OIDC role + `AWS_ROLE_ARN`, a PR gets a
   `pr-N` preview, close triggers cleanup, merge-to-main deploys `prod`.

## Open follow-ups (tracked separately, not this deliverable)

1. Aurora + pgvector stack (`infra/db.ts`) + Secrets Manager DB creds.
2. ECS Fargate 3-container task + arm64 image build + ECR (out-of-band).
3. Internal ALB + ACM + AgentCore Gateway + Cognito.
4. Bedrock Mantle auth + Bedrock Project + qwen3 embedding sidecar.
5. Schema-bootstrap one-shot task.
6. mem9 E2E job (once the ECS service exists).

Each follow-up must extend the OIDC role template + re-bootstrap **before** its
PR deploys (per the scaffold-scoped grants contract in Component 4).
