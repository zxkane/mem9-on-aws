// Observability: CloudWatch metric filters + alarms + Slack alerting for the
// mnemo-server container (issues #26 and #47). Only created for the `prod`
// stage; PR-preview crash-loops must not page.
//
// Production requires an IaC-managed notification sink. The current sink is
// Slack, configured by the `SLACK_WEBHOOK_URL` GitHub secret. Missing prod
// configuration fails synthesis; preview/development stages omit this stack.
//
// Metrics extracted from the mnemo-server structured log lines:
//   1. recall_zero_hit — `confidence recall search` with `returned = 0`
//   2. recall_total   — `confidence recall search` (all)
//   3. ingest_llm_auth_failure — `extraction LLM call failed` containing `401`
//   4. ingest_dropped — `async ingest failed`
//
// Alarms:
//   - RecallZeroHitRate: metric math `zero/total > 0.7` over 1h
//   - IngestAuthFailure: ≥3 ingest_llm_auth_failure in 15 min
//
// Delivery:
//   - CloudWatch alarm -> SNS topic -> alert-router Lambda -> Slack webhook
//   - SNS-to-Lambda transport failures -> transport failure queue
//   - exhausted/expired Lambda executions -> execution failure queue

export interface ObservabilityInputs {
  stage: string;
  // The mnemo-server log group name, read from the SERVICE'S TASK DEFINITION
  // (an Output<string>) — never a hand-computed string. SST names container
  // log groups with a random physical-name hash AND creates them with
  // `ignoreChanges: ["name"]`, so a pinned `logging.name` silently never
  // materializes on a stack whose group already exists (prod incident:
  // metric filters 400'd ResourceNotFoundException on a name that would
  // never exist). Deriving from the task def both yields the REAL name and
  // threads a Pulumi dependency edge through the log group's creator.
  logGroupName: Output<string>;
  slackWebhookUrl?: string;
}

export function observability(inputs: ObservabilityInputs) {
  const { stage, logGroupName, slackWebhookUrl } = inputs;
  if (stage !== "prod") return;
  if (!slackWebhookUrl) {
    throw new Error("SLACK_WEBHOOK_URL is required for production alert delivery");
  }

  const namespace = "mem9-on-aws";
  const failureQueueRetentionSeconds = 14 * 24 * 60 * 60;

  // ─── Metric filters ──────────────────────────────────────────────────────

  new aws.cloudwatch.LogMetricFilter(
    "RecallZeroHitFilter",
    {
      logGroupName,
      pattern: '{ $.msg = "confidence recall search" && $.returned = 0 }',
      metricTransformation: {
        name: "recall_zero_hit",
        namespace,
        value: "1",
        defaultValue: "0",
      },
    },
  );

  new aws.cloudwatch.LogMetricFilter(
    "RecallTotalFilter",
    {
      logGroupName,
      pattern: '{ $.msg = "confidence recall search" }',
      metricTransformation: {
        name: "recall_total",
        namespace,
        value: "1",
        defaultValue: "0",
      },
    },
  );

  new aws.cloudwatch.LogMetricFilter(
    "IngestAuthFailureFilter",
    {
      logGroupName,
      pattern: '{ $.msg = "extraction LLM call failed" && $.err = "*401*" }',
      metricTransformation: {
        name: "ingest_llm_auth_failure",
        namespace,
        value: "1",
        defaultValue: "0",
      },
    },
  );

  new aws.cloudwatch.LogMetricFilter(
    "IngestDroppedFilter",
    {
      logGroupName,
      pattern: '{ $.msg = "async ingest failed" }',
      metricTransformation: {
        name: "ingest_dropped",
        namespace,
        value: "1",
        defaultValue: "0",
      },
    },
  );

  // ─── Alarm topic + independently observable delivery failures ───────────

  const topic = new aws.sns.Topic("Mem9AlertsTopic", {
    name: `mem9-on-aws-${stage}-alerts`,
  });
  const alarmActions = [topic.arn];

  const transportFailureQueue = new aws.sqs.Queue("AlertTransportFailureQueue", {
    messageRetentionSeconds: failureQueueRetentionSeconds,
    // SSE-SQS is compatible with SNS redrive without a customer-managed KMS key.
    sqsManagedSseEnabled: true,
  });
  const executionFailureQueue = new aws.sqs.Queue("AlertExecutionFailureQueue", {
    messageRetentionSeconds: failureQueueRetentionSeconds,
    sqsManagedSseEnabled: true,
  });

  const accountId = aws.getCallerIdentityOutput().accountId;
  const transportQueuePolicy = $jsonStringify({
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Principal: { Service: "sns.amazonaws.com" },
        Action: "sqs:SendMessage",
        Resource: transportFailureQueue.arn,
        Condition: {
          ArnEquals: { "aws:SourceArn": topic.arn },
          StringEquals: { "aws:SourceAccount": accountId },
        },
      },
    ],
  });

  const transportFailureQueuePolicy = new aws.sqs.QueuePolicy(
    "AlertTransportFailureQueuePolicy",
    {
      queueUrl: transportFailureQueue.url,
      policy: transportQueuePolicy,
    },
  );

  const alertRouter = new sst.aws.Function("Mem9AlertRouter", {
    handler: "infra/src/alert-router/handler.handler",
    runtime: "nodejs24.x",
    architecture: "arm64",
    timeout: "30 seconds",
    memory: "256 MB",
    environment: { SLACK_WEBHOOK_URL: slackWebhookUrl },
    permissions: [
      {
        actions: ["sqs:SendMessage"],
        resources: [executionFailureQueue.arn],
      },
    ],
  });

  const snsInvokePermission = new aws.lambda.Permission("Mem9AlertRouterSnsInvoke", {
    action: "lambda:InvokeFunction",
    function: alertRouter.name,
    principal: "sns.amazonaws.com",
    sourceArn: topic.arn,
  });

  new aws.sns.TopicSubscription(
    "Mem9AlertRouterSubscription",
    {
      topic: topic.arn,
      protocol: "lambda",
      endpoint: alertRouter.arn,
      redrivePolicy: $jsonStringify({
        deadLetterTargetArn: transportFailureQueue.arn,
      }),
    },
    { dependsOn: [transportFailureQueuePolicy, snsInvokePermission] },
  );

  new aws.lambda.FunctionEventInvokeConfig("Mem9AlertRouterAsyncFailures", {
    functionName: alertRouter.name,
    maximumRetryAttempts: 2,
    maximumEventAgeInSeconds: 2 * 60 * 60,
    destinationConfig: {
      onFailure: { destination: executionFailureQueue.arn },
    },
  });

  // ─── Alarms ──────────────────────────────────────────────────────────────

  new aws.cloudwatch.MetricAlarm("RecallZeroHitRateAlarm", {
    alarmDescription:
      "Recall zero-hit rate > 70% over 1h (issue #23 regression guard). " +
      "Check cutoff_reason in the confidence recall search log lines.",
    metricQueries: [
      {
        id: "zero",
        metric: {
          metricName: "recall_zero_hit",
          namespace,
          stat: "Sum",
          period: 3600,
        },
        returnData: false,
      },
      {
        id: "total",
        metric: {
          metricName: "recall_total",
          namespace,
          stat: "Sum",
          period: 3600,
        },
        returnData: false,
      },
      {
        id: "rate",
        expression: "IF(total > 10, zero / total, 0)",
        label: "Recall Zero-Hit Rate",
        returnData: true,
      },
    ],
    comparisonOperator: "GreaterThanThreshold",
    threshold: 0.7,
    evaluationPeriods: 1,
    treatMissingData: "notBreaching",
    alarmActions,
  });

  new aws.cloudwatch.MetricAlarm("IngestAuthFailureAlarm", {
    alarmDescription:
      "≥3 ingest LLM auth failures (401) in 15 min — llm-proxy bearer " +
      "may be dead (issue #24 regression guard). Check llm-proxy logs " +
      "for 're-minted bearer' or credential-rotation events.",
    namespace,
    metricName: "ingest_llm_auth_failure",
    statistic: "Sum",
    period: 900,
    evaluationPeriods: 1,
    threshold: 3,
    comparisonOperator: "GreaterThanOrEqualToThreshold",
    treatMissingData: "notBreaching",
    alarmActions,
  });

  new aws.cloudwatch.MetricAlarm("AlertTransportFailureQueueVisibleMessages", {
    alarmDescription:
      "SNS could not deliver an alarm event to the alert-router Lambda. " +
      "Follow the transport failure queue runbook.",
    namespace: "AWS/SQS",
    metricName: "ApproximateNumberOfMessagesVisible",
    dimensions: { QueueName: transportFailureQueue.name },
    statistic: "Maximum",
    period: 300,
    evaluationPeriods: 1,
    threshold: 0,
    comparisonOperator: "GreaterThanThreshold",
    treatMissingData: "notBreaching",
    alarmActions,
  });

  new aws.cloudwatch.MetricAlarm("AlertExecutionFailureQueueVisibleMessages", {
    alarmDescription:
      "The alert-router Lambda exhausted retries or event age after accepting " +
      "an alarm event. Follow the execution failure queue runbook.",
    namespace: "AWS/SQS",
    metricName: "ApproximateNumberOfMessagesVisible",
    dimensions: { QueueName: executionFailureQueue.name },
    statistic: "Maximum",
    period: 300,
    evaluationPeriods: 1,
    threshold: 0,
    comparisonOperator: "GreaterThanThreshold",
    treatMissingData: "notBreaching",
    alarmActions,
  });
}
