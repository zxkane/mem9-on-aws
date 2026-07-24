# Test Cases: alert delivery failure queues

Related issue: #47

## TC-ALERT-001: production alarms use the project topic

**Given** the observability stack is synthesized for `prod` with a configured
Slack webhook
**When** CloudWatch alarms are created
**Then** one project SNS alarm topic exists and every alarm action targets it.

Also assert that production synthesis throws when the managed Slack sink is not
configured, while a preview stage can omit the sink.

## TC-ALERT-002: SNS transport failures use their own queue

**Given** the alert-router Lambda subscription
**When** its IaC properties are inspected
**Then** its redrive policy targets the transport failure queue, and that queue
policy allows only `sns.amazonaws.com` to call `sqs:SendMessage`, constrained to
the exact alarm topic and current account.

## TC-ALERT-003: handler execution failures use their own queue

**Given** the alert-router Lambda asynchronous invocation configuration
**When** its failure destination is inspected
**Then** `OnFailure` targets the execution failure queue, not the transport
queue, and the Lambda role can send only to that queue.

## TC-ALERT-004: asynchronous retry exhaustion is bounded

**Given** an alert-router invocation continues to fail
**When** Lambda applies the asynchronous invocation configuration
**Then** it retries at most two times, retains the event for at most 7,200
seconds, and sends an invocation record with `condition=RetriesExhausted` and an
approximate invoke count of three to the execution queue.

## TC-ALERT-005: missing invocation configuration fails closed

**Given** the alert-router Lambda is invoked without `SLACK_WEBHOOK_URL`
**When** it handles an SNS event
**Then** it rejects with a fixed wiring-error message and does not call Slack.

## TC-ALERT-006: successful Slack delivery completes

**Given** Slack returns any 2xx status
**When** the handler posts a formatted alarm
**Then** the handler resolves and logs only a generic delivery-success message.

## TC-ALERT-007: every non-2xx Slack response fails

**Given** Slack returns a 3xx, 4xx, or 5xx status
**When** the handler processes the response
**Then** the handler rejects so Lambda can retry, without logging the response
body, webhook URL, or alarm payload.

## TC-ALERT-008: Slack network errors fail with redacted output

**Given** the HTTP client rejects with an error that contains the webhook value
**When** the handler catches the network failure
**Then** it logs and throws fixed redacted messages so Lambda can retry.

## TC-ALERT-009: each failure queue has an independent alarm

**Given** the two failure queues
**When** their CloudWatch alarms are synthesized
**Then** each queue has its own `ApproximateNumberOfMessagesVisible > 0` alarm,
and both alarms notify the project topic.

## TC-ALERT-010: queues and policies are bounded

**Given** either alert failure queue
**When** its resource properties are inspected
**Then** SSE-SQS encryption and 14-day retention are explicit, and no policy
grants data-plane access beyond the SNS transport writer or Lambda execution
destination writer.

## TC-ALERT-011: transport fixture matches only the SNS parser

**Given** a representative SNS subscription redrive message
**When** both failure-record parsers inspect it
**Then** the transport parser returns only SNS routing metadata and the Lambda
execution parser rejects it.

## TC-ALERT-012: execution fixture matches only the Lambda parser

**Given** a representative Lambda `OnFailure` invocation record after retry
exhaustion
**When** both failure-record parsers inspect it
**Then** the execution parser returns only failure metadata and the SNS
transport parser rejects it.

## TC-ALERT-013: logs never expose alert secrets or payload fields

**Given** webhook and alarm payload values that are unique test markers
**When** success, HTTP failure, network failure, and missing-configuration paths
run
**Then** captured console output contains neither marker nor any webhook value.
