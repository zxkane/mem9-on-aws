# Durable Ingest Telemetry Test Cases

Design:
[`docs/designs/durable-ingest-telemetry.md`](../designs/durable-ingest-telemetry.md)

These cases cover the application serializer and the ECS stdout transport
boundary. The container smoke validates local bytes through Docker's selected
terminal mode; it does not prove CloudWatch-side extraction.

| ID | Scenario | Expected |
|---|---|---|
| TC-EMF-001 | Serialize accepted, retry, success, dead, heartbeat, and queue-age records | Every record is one complete JSON object whose first root member is `_aws`; metadata retains a millisecond timestamp, the `mem9-on-aws/DurableIngest` namespace, declared units, and only bounded `stage`, `result_class`, and `error_class` dimensions |
| TC-EMF-002 | Serialize zero-valued metrics and concurrent records | Required zero values remain present, and the writer mutex prevents records from interleaving or disappearing |
| TC-EMF-003 | Serialize fixtures containing tenant, agent, app, session, job, request, payload, message, fact, and embedding markers | No marker, memory content, or identifier appears in a metric record |
| TC-EMF-004 | Synthesize the raw `mnemo-server` container definition | `pseudoTerminal` is exactly `false`, `interactive` remains unset, and the transport remains `awslogs` with its generated group, region, and stream-prefix options unchanged |
| TC-EMF-005 | Synthesize the two sidecar container definitions | Their existing terminal and logging properties are unchanged by the `mnemo-server`-only override |
| TC-EMF-006 | Emit sampler records from the built arm64 image with the selected task-definition terminal mode | Docker captures at least one `_aws`-first `SamplerHeartbeat=1` JSON document; every captured sampler document ends in LF without a preceding CR, and its namespace, stage dimension, unit, timestamp, and content-free root shape validate |
| TC-EMF-007 | Validate one event with no suffix or only CR, LF, spaces, or their combinations after the JSON document | The frame is accepted; suffix whitespace alone does not invalidate an otherwise exact EMF document |
| TC-EMF-008 | Validate invalid JSON or a frame with bytes before the JSON object | The frame is rejected before its EMF metadata can be trusted |
| TC-EMF-009 | Validate two JSON documents in one container event | The frame is rejected instead of accepting the first document and ignoring the second |
| TC-EMF-010 | Validate a syntactically valid JSON document with the wrong namespace, timestamp type, stage dimension, unit, metric value, or extra content-bearing root field | The frame is rejected because it does not match the content-free sampler contract |
| TC-EMF-011 | Inspect the `Build & push workload images` job | A named post-build `mnemo-server` EMF framing smoke runs the validator against the just-built arm64 image under non-TTY Docker settings |
