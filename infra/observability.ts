import { ECR_REGION } from "./ecr";

// Observability: CloudWatch metrics, dashboard, alarms, and Slack alerting for
// the mnemo-server container (issues #26, #47, and #55). Only created for `prod`
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
  slackWebhookUrl?: Input<string>;
  mantleProject?: string;
}

export interface ObservabilityOutputs {
  alertsTopicArn?: Output<string>;
}

export const DURABLE_FAILURE_RATIO_EXPRESSION =
  "IF(terminal >= 20, failures / terminal, 0)";

// The traffic guard is load-bearing: a quiet day with a handful of legitimately
// zero-fact jobs reads 100% and would otherwise page.
export const ZERO_FACT_RATE_EXPRESSION = "IF(succeeded > 50, zero_rate, 0)";
// Exactly 1.0: breach only when NOT ONE of the day's 50+ succeeded jobs
// extracted a fact. A fractional threshold reads as a comfortable margin over
// the 96% worst healthy day but is not one — at 200 jobs, 0.995 would page on a
// day that extracted a single real fact. "Any extraction at all" is the honest
// line for a blackout detector, and it cannot false-positive on traffic that is
// still producing memories.
export const ZERO_FACT_ALARM_THRESHOLD = 1;

export function observability(
  inputs: ObservabilityInputs,
): ObservabilityOutputs {
  const { stage, logGroupName, slackWebhookUrl, mantleProject } = inputs;
  if (stage !== "prod") return {};
  if (!slackWebhookUrl) {
    throw new Error("SLACK_WEBHOOK_URL is required for production alert delivery");
  }
  if (!mantleProject) {
    throw new Error("MEM9_BEDROCK_PROJECT is required for production observability");
  }

  const namespace = "mem9-on-aws";
  const durableNamespace = "mem9-on-aws/DurableIngest";
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

  // ─── Alarm topic + independently observable delivery failures ───────────

  const topic = new aws.sns.Topic("Mem9AlertsTopic", {
    name: `mem9-on-aws-${stage}-alerts`,
  });
  const alarmActions = [topic.arn];
  const okActions = alarmActions;

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

  // ─── Dashboard ───────────────────────────────────────────────────────────

  const providerMetric = (name: string, stat = "Sum") => [
    "AWS/BedrockMantle",
    name,
    "Project",
    mantleProject,
    { stat },
  ];
  const durableMetric = (
    name: string,
    resultClass?: "accepted" | "succeeded" | "retrying" | "dead",
    stat = "Sum",
  ) => [
    durableNamespace,
    name,
    "stage",
    stage,
    ...(resultClass ? ["result_class", resultClass] : []),
    { stat },
  ];
  const retryTransitions = () => [
    [
      {
        expression: "FILL(retry_transitions, 0)",
        id: "retry_transitions_filled",
        label: "Retry transitions",
      },
    ],
    [
      durableNamespace,
      "JobsRetrying",
      "stage",
      stage,
      {
        id: "retry_transitions",
        stat: "Sum",
        visible: false,
      },
    ],
  ];
  new aws.cloudwatch.Dashboard("DurableIngestDashboard", {
    dashboardName: `mem9-on-aws-${stage}-ingest`,
    dashboardBody: $jsonStringify({
      widgets: [
        {
          type: "text",
          x: 0,
          y: 0,
          width: 24,
          height: 1,
          properties: { markdown: "# Bedrock Mantle provider" },
        },
        {
          type: "metric",
          x: 0,
          y: 1,
          width: 12,
          height: 6,
          properties: {
            title: "Inference outcomes",
            region: ECR_REGION,
            period: 300,
            metrics: [
              providerMetric("Inferences"),
              providerMetric("InferenceClientErrors"),
            ],
          },
        },
        {
          type: "metric",
          x: 12,
          y: 1,
          width: 12,
          height: 6,
          properties: {
            title: "Token volume",
            region: ECR_REGION,
            period: 300,
            metrics: [
              providerMetric("TotalInputTokens"),
              providerMetric("TotalOutputTokens"),
            ],
          },
        },
        {
          type: "text",
          x: 0,
          y: 7,
          width: 24,
          height: 1,
          properties: { markdown: "# Durable ingest application" },
        },
        {
          type: "metric",
          x: 0,
          y: 8,
          width: 12,
          height: 6,
          properties: {
            title: "Job outcomes",
            region: ECR_REGION,
            period: 300,
            metrics: [
              durableMetric("JobsAccepted", "accepted"),
              durableMetric("JobsSucceeded", "succeeded"),
              durableMetric("JobsDead"),
              ...retryTransitions(),
            ],
          },
        },
        {
          type: "metric",
          x: 12,
          y: 8,
          width: 12,
          height: 6,
          properties: {
            title: "Queue and telemetry health",
            region: ECR_REGION,
            period: 300,
            metrics: [
              durableMetric("SamplerHeartbeat"),
              durableMetric("OldestQueuedAgeMs", undefined, "Maximum"),
              durableMetric("QueueWaitMs", "succeeded", "Average"),
              durableMetric("QueueWaitMs", "retrying", "Average"),
              durableMetric("QueueWaitMs", "dead", "Average"),
            ],
          },
        },
        {
          type: "metric",
          x: 0,
          y: 14,
          width: 12,
          height: 6,
          properties: {
            title: "Application phase duration",
            region: ECR_REGION,
            period: 300,
            metrics: [
              durableMetric("PlanDurationMs", "succeeded", "Average"),
              durableMetric("ApplyDurationMs", "succeeded", "Average"),
              durableMetric("TotalProcessingDurationMs", "succeeded", "Average"),
            ],
          },
        },
        {
          type: "metric",
          x: 12,
          y: 14,
          width: 12,
          height: 6,
          properties: {
            title: "Retries and warnings",
            region: ECR_REGION,
            period: 300,
            metrics: [
              ...retryTransitions(),
              durableMetric("Warnings"),
              durableMetric("TruncatedFacts"),
              durableMetric("ZeroFactSuccess"),
            ],
          },
        },
      ],
    }),
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
    okActions,
  });

  new aws.cloudwatch.MetricAlarm("IngestAuthFailureAlarm", {
    alarmDescription:
      "≥3 ingest LLM auth failures (401) in 15 min — llm-proxy bearer " +
      "may be dead (issue #24 regression guard). Check llm-proxy logs " +
      "for reason=auth_remint or credential-rotation events.",
    namespace,
    metricName: "ingest_llm_auth_failure",
    statistic: "Sum",
    period: 900,
    evaluationPeriods: 1,
    threshold: 3,
    comparisonOperator: "GreaterThanOrEqualToThreshold",
    treatMissingData: "notBreaching",
    alarmActions,
    okActions,
  });

  new aws.cloudwatch.MetricAlarm("DurableIngestDeadJobAlarm", {
    alarmDescription: "At least one durable ingest job reached dead state in 15 minutes.",
    namespace: durableNamespace,
    metricName: "JobsDead",
    dimensions: { stage },
    statistic: "Sum",
    period: 900,
    evaluationPeriods: 1,
    threshold: 1,
    comparisonOperator: "GreaterThanOrEqualToThreshold",
    treatMissingData: "notBreaching",
    alarmActions,
    okActions,
  });

  // Smart-extraction quality backstop. `ZeroFactSuccess` is emitted once per
  // SUCCEEDED job (0 or 1), so its Average over a window IS the zero-fact rate
  // — no second metric is needed for the ratio.
  //
  // Deliberately a blackout detector, not a sensitive quality monitor. Measured
  // healthy prod baseline: 96/82/91/90/77% by day, and SIX CONSECUTIVE 100%
  // hours (Jul 30) — most agent sessions genuinely carry no durable takeaway,
  // the documented correct outcome of rule D4. Those six hours total 134 jobs
  // with zero facts, which is why the window is DAILY and the threshold is
  // exactly 1.0: a sub-day window or a fractional threshold would page on that
  // healthy stretch. Over the calendar day those hours belong to, Jul 30
  // extracted 35 facts from 377 jobs and stays quiet.
  //
  // NOTE the evaluation window SLIDES: CloudWatch advances it by a minute and
  // does not align it to the wall clock, and @pulumi/aws at the pinned version
  // exposes no `evaluationWindow` to request wall-clock alignment. So this is
  // not literally a per-calendar-day check — some 24h window could enclose the
  // 134-job stretch plus quieter hours. That is an accepted residual: the
  // threshold of exactly 1.0 means any single fact-producing job anywhere in
  // the window clears it, and the stretch above is bracketed on both sides by
  // fact-producing hours in the real series.
  //
  // What it catches: "the extractor returns nothing, ever" — a bad model swap,
  // a broken prompt, a translation regression yielding empty content. What it
  // does NOT catch: subtle quality drift, which is not observable in this
  // metric at all (that is #104/#106's shadow scoring).
  new aws.cloudwatch.MetricAlarm("DurableIngestZeroFactRateAlarm", {
    alarmDescription:
      "Not one of 50+ succeeded ingest jobs extracted a fact in 24h. Suspect a " +
      "broken extractor (model swap, prompt, or llm-proxy translation), not " +
      "normal traffic: healthy days run 77-96% zero-fact but always extract " +
      "something. Check MNEMO_LLM_MODEL and the llm-proxy request log.",
    metricQueries: [
      {
        id: "zero_rate",
        metric: {
          namespace: durableNamespace,
          metricName: "ZeroFactSuccess",
          dimensions: { stage },
          stat: "Average",
          period: 86400,
        },
        returnData: false,
      },
      {
        id: "succeeded",
        metric: {
          namespace: durableNamespace,
          metricName: "JobsSucceeded",
          dimensions: { stage, result_class: "succeeded" },
          stat: "Sum",
          period: 86400,
        },
        returnData: false,
      },
      {
        id: "rate",
        expression: ZERO_FACT_RATE_EXPRESSION,
        label: "Zero-fact extraction rate (>50 jobs/day)",
        returnData: true,
      },
    ],
    threshold: ZERO_FACT_ALARM_THRESHOLD,
    evaluationPeriods: 1,
    comparisonOperator: "GreaterThanOrEqualToThreshold",
    // No ingest traffic is not a quality regression; the liveness alarm owns
    // "telemetry stopped".
    treatMissingData: "notBreaching",
    alarmActions,
    okActions,
  });

  new aws.cloudwatch.MetricAlarm("DurableIngestOldestQueuedAgeAlarm", {
    alarmDescription:
      "The oldest durable ingest job remained queued for more than 10 minutes.",
    namespace: durableNamespace,
    metricName: "OldestQueuedAgeMs",
    dimensions: { stage },
    statistic: "Maximum",
    period: 300,
    evaluationPeriods: 2,
    datapointsToAlarm: 2,
    threshold: 600_000,
    comparisonOperator: "GreaterThanThreshold",
    // Queue age is meaningful only when sampled. Missing telemetry does not
    // prove that a queued job exceeded the threshold and must not page during
    // a deploy, rollback, or transient database read failure.
    treatMissingData: "notBreaching",
    alarmActions,
    okActions,
  });

  const telemetryLivenessAlarm = new aws.cloudwatch.MetricAlarm(
    "DurableIngestTelemetryLivenessAlarm",
    {
      alarmDescription:
        "The once-per-minute durable ingest sampler stopped emitting ECS-origin telemetry.",
      metricQueries: [
        {
          id: "heartbeat",
          metric: {
            namespace: durableNamespace,
            metricName: "SamplerHeartbeat",
            dimensions: { stage },
            stat: "Maximum",
            period: 60,
          },
          returnData: false,
        },
        {
          id: "heartbeat_present",
          expression: "FILL(heartbeat, 0)",
          label: "Sampler heartbeat present",
          returnData: true,
        },
      ],
      evaluationPeriods: 5,
      datapointsToAlarm: 5,
      threshold: 1,
      comparisonOperator: "LessThanThreshold",
      // FILL makes every current missing period an explicit breach, so older
      // healthy points from CloudWatch's wider sliding range cannot defer it.
      treatMissingData: "breaching",
    },
  );

  const telemetryActionDelayGuard = new aws.cloudwatch.MetricAlarm(
    "DurableIngestTelemetryActionDelayGuard",
    {
      alarmDescription:
        "Always-OK guard that gives liveness alarm actions one bounded deployment grace period.",
      namespace: durableNamespace,
      metricName: "SamplerHeartbeat",
      dimensions: { stage },
      statistic: "Minimum",
      period: 60,
      evaluationPeriods: 1,
      threshold: 0,
      comparisonOperator: "LessThanThreshold",
      treatMissingData: "notBreaching",
    },
  );

  new aws.cloudwatch.CompositeAlarm("DurableIngestTelemetryLivenessNotification", {
    alarmName: `mem9-on-aws-${stage}-durable-ingest-telemetry-liveness`,
    alarmDescription:
      "Durable ingest telemetry was absent through the bounded deployment grace period.",
    alarmRule: telemetryLivenessAlarm.arn.apply((arn) => `ALARM("${arn}")`),
    actionsSuppressor: {
      alarm: telemetryActionDelayGuard.arn,
      waitPeriod: 300,
      extensionPeriod: 0,
    },
    alarmActions,
    // CloudWatch starts a new wait after a state change during suppression.
    // An OK action here could therefore send a recovery without a prior page.
  });

  new aws.cloudwatch.MetricAlarm("DurableIngestFailureRatioAlarm", {
    alarmDescription:
      "Deadline or Mantle transient failures are at least 10% of 20+ terminal jobs.",
    metricQueries: [
      {
        id: "failures",
        metric: {
          metricName: "DeadlineTransientTerminalFailures",
          namespace: durableNamespace,
          stat: "Sum",
          period: 900,
          dimensions: { stage },
        },
        returnData: false,
      },
      {
        id: "terminal",
        metric: {
          metricName: "JobsTerminated",
          namespace: durableNamespace,
          stat: "Sum",
          period: 900,
          dimensions: { stage },
        },
        returnData: false,
      },
      {
        id: "rate",
        expression: DURABLE_FAILURE_RATIO_EXPRESSION,
        label: "Deadline/Transient Terminal Failure Ratio",
        returnData: true,
      },
    ],
    evaluationPeriods: 1,
    threshold: 0.1,
    comparisonOperator: "GreaterThanOrEqualToThreshold",
    treatMissingData: "notBreaching",
    alarmActions,
    okActions,
  });

  new aws.cloudwatch.MetricAlarm("MantleClientErrorAlarm", {
    alarmDescription: "Bedrock Mantle reported a Project-scoped client error.",
    namespace: "AWS/BedrockMantle",
    metricName: "InferenceClientErrors",
    dimensions: { Project: mantleProject },
    statistic: "Sum",
    period: 900,
    evaluationPeriods: 1,
    threshold: 1,
    comparisonOperator: "GreaterThanOrEqualToThreshold",
    treatMissingData: "notBreaching",
    alarmActions,
    okActions,
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
    okActions,
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
    okActions,
  });

  return { alertsTopicArn: topic.arn };
}
