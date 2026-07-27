# Design: alert delivery failure queues (issue #47)

Feature: Production alert delivery hardening
Date: 2026-07-24
Status: Approved (autonomous mode)

## Problem

Production alarms can currently exist without a notification action because the
SNS topic and Slack Lambda are conditional on `SLACK_WEBHOOK_URL`. The handler
also converts Slack failures into successful Lambda invocations, so AWS cannot
retry failed deliveries or route exhausted invocations to a failure destination.

SNS-to-Lambda delivery and Lambda handler execution are separate failure domains.
Combining them in one queue would hide whether SNS reached Lambda at all.

## Data Flow

```text
CloudWatch alarm ALARM or OK transition
  -> production SNS alarm topic
       -> SNS invokes alert-router Lambda
            transport failure -> alert transport failure queue
            accepted event    -> alert-router posts to Slack
                                  success -> complete
                                  failure -> Lambda async retry (maximum 2)
                                             or event age reaches 2 hours
                                             -> alert execution failure queue

transport queue visible messages > 0 -> transport queue alarm -> alarm topic
execution queue visible messages > 0 -> execution queue alarm -> alarm topic
```

Every production alarm, including both queue-depth alarms, uses the same project
SNS topic for ALARM and OK actions. The alert router formats an OK transition as
a recovery message; its transport and execution failure destinations remain the
separate queues above, so recovery wiring does not create a recursive
destination. Production synthesis fails before resource creation when the
IaC-managed Slack sink has no webhook configuration. Non-prod stages continue
to omit the complete observability stack and do not require the webhook.

## Resource Design

| Resource | Purpose | Reliability settings |
|---|---|---|
| Alarm SNS topic | Single action for every production alarm | Always created for prod |
| Transport failure queue | SNS could not deliver to Lambda | SNS subscription redrive target, 14-day retention |
| Execution failure queue | Lambda accepted the event but handler processing failed | Lambda async `OnFailure`, 14-day retention |
| Alert-router Lambda | Slack sink | Node 24 arm64, 2 retries, 2-hour event age |
| Two queue alarms | Independent operator signal | `ApproximateNumberOfMessagesVisible > 0` |

Both queues explicitly use SSE-SQS (`sqsManagedSseEnabled`). AWS documentation
requires a customer-managed KMS key when SNS writes to an SSE-KMS queue because
the immutable `alias/aws/sqs` key policy cannot grant SNS the required KMS
actions. SSE-SQS is therefore the service-managed encrypted option that preserves
working SNS redrive without adding a customer-managed key to this issue.

## IAM Boundaries

- SNS receives `sqs:SendMessage` only on the transport queue, constrained by the
  exact alarm topic ARN and current account.
- The alert Lambda execution role receives `sqs:SendMessage` only on the
  execution queue for its asynchronous failure destination.
- SNS receives `lambda:InvokeFunction` only on the alert Lambda and only from
  the alarm topic.
- Queue alarms read AWS/SQS metrics without queue data-plane permissions.
- The deployment role receives only the SQS lifecycle/policy operations and
  Lambda event-invoke-config operations needed to reconcile these resources.

## Failure Records

The runbook and tests preserve distinct record contracts:

- A transport queue body is the original SNS notification envelope. It contains
  SNS metadata such as `Type`, `MessageId`, `TopicArn`, and `Message`, but no
  Lambda `requestContext`.
- An execution queue body is a Lambda destination invocation record. It contains
  `requestContext.condition`, `approximateInvokeCount`, `requestPayload`,
  `responseContext`, and `responsePayload`.

Separate parsers reject the other queue's shape. They expose only routing and
failure metadata needed by an operator; they do not log or return alarm payload
content.

## Handler and Logging

- Every Slack 3xx, 4xx, 5xx, and network error rejects the invocation.
- Missing `SLACK_WEBHOOK_URL` rejects as an IaC wiring error.
- Network errors are replaced with a fixed error message instead of retaining an
  exception that may include the webhook URL.
- Logs contain fixed operation names and, for HTTP failures, only the response
  status. They never contain webhook values, response bodies, SNS messages, or
  formatted alarm payload fields.

## Verification

- Handler unit tests cover 2xx, each non-2xx class, network rejection, missing
  configuration, and redacted logs.
- IaC assertion tests cover the two queues, encryption, retention, policies,
  redrive, Lambda destination/retries/event age, queue alarms, and matching
  ALARM/OK topic actions without changing alarm semantics.
- Fixture tests cover representative SNS transport and Lambda execution records
  and prove each parser rejects the other shape.
- Production and non-prod synthesis behavior is tested separately.

## Rollback

Revert the resource and handler changes together. Removing only the queues or
async configuration would restore silent alert loss and is not a valid partial
rollback.
