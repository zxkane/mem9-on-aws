// Observability: CloudWatch metric filters + alarms + Slack alerting for the
// mnemo-server container (issues #26, follow-up). Only created for the `prod`
// stage; PR-preview crash-loops must not page.
//
// Slack delivery is conditional on the `SlackWebhookUrl` SST secret being
// configured (set via `npx sst secret set SlackWebhookUrl <url> --stage prod`
// or via `SLACK_WEBHOOK_URL` GitHub secret). When absent, the alarms still fire
// (visible in the CloudWatch console) but have no action — no Lambda, no topic.
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
// When SlackWebhookUrl is set:
//   - SNS topic → alert-router Lambda → Slack webhook (Block Kit, #C0BKH5LPAJW
//     in the opentuna workspace)

export interface ObservabilityInputs {
  stage: string;
  logGroupName: string;
  slackWebhookUrl?: string;
}

export function observability(inputs: ObservabilityInputs) {
  const { stage, logGroupName, slackWebhookUrl } = inputs;
  if (stage !== "prod") return;

  const namespace = "mem9-on-aws";

  // ─── Metric filters ──────────────────────────────────────────────────────

  new aws.cloudwatch.LogMetricFilter("RecallZeroHitFilter", {
    logGroupName,
    pattern: '{ $.msg = "confidence recall search" && $.returned = 0 }',
    metricTransformation: {
      name: "recall_zero_hit",
      namespace,
      value: "1",
      defaultValue: "0",
    },
  });

  new aws.cloudwatch.LogMetricFilter("RecallTotalFilter", {
    logGroupName,
    pattern: '{ $.msg = "confidence recall search" }',
    metricTransformation: {
      name: "recall_total",
      namespace,
      value: "1",
      defaultValue: "0",
    },
  });

  new aws.cloudwatch.LogMetricFilter("IngestAuthFailureFilter", {
    logGroupName,
    pattern: '{ $.msg = "extraction LLM call failed" && $.err = "*401*" }',
    metricTransformation: {
      name: "ingest_llm_auth_failure",
      namespace,
      value: "1",
      defaultValue: "0",
    },
  });

  new aws.cloudwatch.LogMetricFilter("IngestDroppedFilter", {
    logGroupName,
    pattern: '{ $.msg = "async ingest failed" }',
    metricTransformation: {
      name: "ingest_dropped",
      namespace,
      value: "1",
      defaultValue: "0",
    },
  });

  // ─── SNS topic + alert-router Lambda (conditional on webhook) ────────────

  // alarmActions is either [topicArn] (Slack delivery enabled) or [] (console-only).
  let alarmActions: any[] = [];

  if (slackWebhookUrl) {
    const topic = new aws.sns.Topic("Mem9AlertsTopic", {
      name: `mem9-on-aws-${stage}-alerts`,
    });

    const alertRouter = new sst.aws.Function("Mem9AlertRouter", {
      handler: "infra/src/alert-router/handler.handler",
      runtime: "nodejs24.x",
      architecture: "arm64",
      timeout: "30 seconds",
      memory: "256 MB",
      environment: { SLACK_WEBHOOK_URL: slackWebhookUrl },
    });

    new aws.sns.TopicSubscription("Mem9AlertRouterSubscription", {
      topic: topic.arn,
      protocol: "lambda",
      endpoint: alertRouter.arn,
    });

    new aws.lambda.Permission("Mem9AlertRouterSnsInvoke", {
      action: "lambda:InvokeFunction",
      function: alertRouter.name,
      principal: "sns.amazonaws.com",
      sourceArn: topic.arn,
    });

    alarmActions = [topic.arn];
  }

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
}
