# Ingest pre-screen shadow test cases

The policy is permanently pass-through in this change. `would-skip` is an
observed counterfactual, never an instruction to suppress extraction.

## Scorer and worker

| ID | Scenario | Expected result |
| --- | --- | --- |
| TC-PRESCREEN-001 | Score zero messages with policy `msg-count-le-1-v1` | The pure scorer returns `would-skip=true`; the durable envelope validator still rejects an empty message list |
| TC-PRESCREEN-002 | Score exactly one message | The pure scorer returns the bounded policy version and `would-skip=true` |
| TC-PRESCREEN-003 | Score two or more messages | The pure scorer returns `would-skip=false` at two and above |
| TC-PRESCREEN-004 | Worker plans a one-message smart job | The processor is invoked exactly once and its fact-producing plan/result is preserved even though the shadow decision is `would-skip` |
| TC-PRESCREEN-005 | Worker plans a multi-message smart job | The processor is invoked exactly once and its zero-fact plan/result is preserved with a pass-through decision |
| TC-PRESCREEN-006 | Worker resumes a persisted plan | The persisted decision is reused and extraction/scoring is not repeated |
| TC-PRESCREEN-007 | Raw-mode or malformed input is not an eligible shadow sample | Raw mode carries no pre-screen fields; malformed canonical input follows the existing planning error path rather than becoming an active skip |
| TC-PRESCREEN-008 | A smart-mode job falls back to raw because no LLM is configured | The raw action is preserved and no pre-screen decision or counter is persisted because no real extraction outcome exists |

## EMF telemetry and privacy

| ID | Scenario | Expected result |
| --- | --- | --- |
| TC-PRESCREEN-010 | Successful one-message zero-fact plan | Emit `PrescreenEvaluated=1`, `PrescreenWouldSkip=1`, and `PrescreenFalseSkip=0` |
| TC-PRESCREEN-011 | Successful one-message fact-producing plan | Emit all three counters with `PrescreenFalseSkip=1` |
| TC-PRESCREEN-012 | Successful multi-message plan | Emit `PrescreenEvaluated=1` and zero for both decision counters |
| TC-PRESCREEN-013 | Inspect every pre-screen EMF directive | Dimensions are exactly `stage` and `policy_version`; the policy value is from a fixed allow-list |
| TC-PRESCREEN-014 | Attempt to emit an unknown policy version | The version is bounded to `other`; the supplied value is not serialized |
| TC-PRESCREEN-015 | Serialize telemetry around private job fixtures | JSON is valid EMF and contains no content, tenant, agent, app, session, job, request, payload, identifier, hash, measured length, or lexical-match field/value |
| TC-PRESCREEN-016 | Production telemetry is disabled or absent | Extraction and plan application still run; no pre-screen EMF is written |

## Dashboard and existing semantics

| ID | Scenario | Expected result |
| --- | --- | --- |
| TC-PRESCREEN-020 | Render the production durable-ingest dashboard | Would-skip rate is `PrescreenWouldSkip / PrescreenEvaluated` and false-skip rate is `PrescreenFalseSkip / PrescreenEvaluated`, guarded for a zero denominator |
| TC-PRESCREEN-021 | Inspect pre-screen dashboard source metrics | Every source metric selects the fixed production stage and `msg-count-le-1-v1`; no search expression or unbounded dimension is used |
| TC-PRESCREEN-022 | Compare existing alarm and zero-fact resources | No alarm is added or changed, and `ZeroFactSuccess` remains the extraction outcome counter with its existing dimensions and semantics |

## PostgreSQL integration and patch stack

| ID | Scenario | Expected result |
| --- | --- | --- |
| TC-PRESCREEN-030 | Run a one-message smart job whose fake LLM returns no facts through the PostgreSQL worker | The fake LLM is invoked, the job reaches `succeeded`, the existing zero-fact/session outcome is preserved, and shadow counters are `1/1/0` |
| TC-PRESCREEN-031 | Run a one-message smart job whose fake LLM returns a durable fact through the PostgreSQL worker | The fake LLM is invoked, the job reaches `succeeded`, the existing memory/session outcome is preserved, and shadow counters are `1/1/1` |
| TC-PRESCREEN-040 | Apply patches `0001` through `0008` to the pinned upstream commit | Application is clean; the Docker builder's command, handler, service, and LLM Go package groups pass |
| TC-PRESCREEN-041 | Run `scripts/run-ingest-queue-integration.sh` | The repository, PostgreSQL repository, ingest queue, handler, service, config, and command package groups pass against PostgreSQL |
