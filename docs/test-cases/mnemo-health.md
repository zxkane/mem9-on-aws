# Test cases: mnemo-server ECS liveness health check (issue #50)

The `/healthz` endpoint is process liveness only. A successful response proves
that the mnemo-server HTTP process is serving requests; it does not prove
database, embedding, LLM, or end-to-end readiness.

## IaC unit tests (`infra/ecs.test.ts`)

| ID | Scenario | Expected |
|---|---|---|
| TC-MNEMO-HEALTH-001 | mnemo-server health command | Command is exactly `["CMD-SHELL", "wget -q -O /dev/null http://localhost:8080/healthz \|\| exit 1"]` |
| TC-MNEMO-HEALTH-002 | ECS health timing | `startPeriod="60 seconds"`, `interval="30 seconds"`, `timeout="5 seconds"`, and `retries=3` |
| TC-MNEMO-HEALTH-003 | Startup grace | Failures during the first 60 seconds do not count toward the retry limit; a success during that period establishes container health |
| TC-MNEMO-HEALTH-004 | Essential-container task health | mnemo-server, qwen3-embed, and llm-proxy are all essential and each defines an ECS health check |

## Container smoke test (`scripts/run-mnemo-health-smoke.sh`)

| ID | Scenario | Expected |
|---|---|---|
| TC-MNEMO-HEALTH-005 | Runtime image tooling | The built Alpine image provides the BusyBox `wget` applet; the Dockerfile adds no health-check package |
| TC-MNEMO-HEALTH-006 | Healthy mnemo-server | Start the image against a local PostgreSQL container; the exact ECS command exits 0 against `/healthz` |
| TC-MNEMO-HEALTH-007 | Stopped or unreachable mnemo-server | Stop the server, run the exact command in an isolated image container, and observe a nonzero exit |
