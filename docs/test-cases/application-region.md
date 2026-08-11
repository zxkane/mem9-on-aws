# Application region source of truth

The SST AWS provider in `sst.config.ts` is the single source of truth for the
application plane. Changing that one region must move SST resources, ECR image
references, the primary Mantle route, CI deployment commands, and operator
scripts together. Account-global IAM ownership stacks and the optional OpenAI
Responses route remain independently regional.

## Resolution

| ID | Scenario | Expected result |
| --- | --- | --- |
| TC-APPREGION-001 | Resolve the checked-in SST configuration | The resolver prints the AWS provider region and nothing else on stdout |
| TC-APPREGION-002 | Resolve a fixture whose SST provider uses `ap-southeast-1` | Every resolver caller receives `ap-southeast-1` without another source edit |
| TC-APPREGION-003 | The SST provider region is missing, non-string, or malformed | Resolution fails before any AWS command runs |
| TC-APPREGION-004 | Two callers resolve different SST fixtures concurrently | Temporary `$config` shims are serialized and the caller's original global is restored |

## Consumers

| ID | Scenario | Expected result |
| --- | --- | --- |
| TC-APPREGION-010 | Synthesize ECR image URIs, the primary Mantle Project ARN, proxy environment, and dashboard widgets | They use the active AWS provider region rather than a copied literal |
| TC-APPREGION-011 | Render the out-of-band IAM templates | `ApplicationRegion` is required and every application-plane ARN interpolates it |
| TC-APPREGION-012 | Run CI deployment or preview reconciliation | A resolver job reads `sst.config.ts`; all AWS jobs consume that output |
| TC-APPREGION-013 | Run an operator script without a region override | The script resolves the application region from `sst.config.ts` |
| TC-APPREGION-014 | Run the LLM proxy without `LLM_PROXY_REGION` but with the ECS-provided `AWS_REGION` | The primary chat route uses `AWS_REGION`; absence of both values fails instead of silently selecting Tokyo |
| TC-APPREGION-015 | Build the LLM proxy image for a non-Tokyo application region | The image trusts the documented RDS global CA bundle |
| TC-APPREGION-016 | A PR changes the application region after an earlier preview | Non-closed deploy events fail before AWS work; on close, cleanup uses the PR base region and base configuration where the prior preview was deployed |

## Independent model route

| ID | Scenario | Expected result |
| --- | --- | --- |
| TC-APPREGION-020 | The selected OpenAI GPT model is unavailable in the application region | Prefix routing sends it to the separately configured Responses region |
| TC-APPREGION-021 | No Responses region is configured | The existing fallback remains `us-west-2`, with that region's bearer, IAM grant, and Bedrock Project |
| TC-APPREGION-022 | The application region is also `us-west-2` | Primary and Responses routes may share a token, but route selection and Project configuration remain explicit |
| TC-APPREGION-023 | Set the `MEM9_LLM_RESPONSES_REGION` repository variable | Preview/prod synthesis and boundary verification receive the same custom fallback region |
| TC-APPREGION-024 | Build the shared `llm-proxy` image after consolidation imports the region resolver | Every relative module in the copied entrypoint graph is also copied into the image |
| TC-APPREGION-025 | Provision a Mantle Project with explicit `PROJECT_REGION` | The operator output names `MEM9_BEDROCK_PROJECT_OPENAI`; application-region provisioning names `MEM9_BEDROCK_PROJECT` |
| TC-APPREGION-026 | Start a boundary rollout against a retained stack from another application region | The read-only boundary-region preflight rejects the mismatch before quarantine or any IAM mutation |

## Existing deployments

| ID | Scenario | Expected result |
| --- | --- | --- |
| TC-APPREGION-040 | `sst.config.ts` differs from an existing workload-boundary stack's `ApplicationRegion` | Verification and guarded rollout fail before any mutation; live relocation requires a dedicated dual-region migration after old-region previews are removed |

## Documentation

| ID | Scenario | Expected result |
| --- | --- | --- |
| TC-APPREGION-030 | Read current deployment and operator guidance | It refers to the `sst.config.ts` application region rather than presenting Tokyo as immutable |
| TC-APPREGION-031 | Read empirical or rejected-alternative records | The original observed region and date remain intact |
