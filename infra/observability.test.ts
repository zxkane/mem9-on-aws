import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { parse } from "yaml";
import {
  DURABLE_FAILURE_RATIO_EXPRESSION,
  PRESCREEN_FALSE_SKIP_RATE_EXPRESSION,
  PRESCREEN_POLICY_VERSION,
  PRESCREEN_WOULD_SKIP_RATE_EXPRESSION,
  ZERO_FACT_ALARM_THRESHOLD,
  ZERO_FACT_RATE_EXPRESSION,
  observability,
} from "./observability";

interface ResourceRecord {
  args: Record<string, unknown>;
  kind: string;
  logicalName: string;
}

interface TestOutput<T> {
  apply: (fn: (value: T) => unknown) => unknown;
  value: T;
}

const out = <T>(value: T): TestOutput<T> => ({
  value,
  apply: (fn) => {
    const result = fn(value);
    return isOutput(result) ? result : out(result);
  },
});

function isOutput(value: unknown): value is TestOutput<unknown> {
  return typeof value === "object" && value !== null && "value" in value && "apply" in value;
}

function materialize(value: unknown): unknown {
  if (isOutput(value)) return materialize(value.value);
  if (Array.isArray(value)) return value.map(materialize);
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(
      Object.entries(value).map(([key, nested]) => [key, materialize(nested)]),
    );
  }
  return value;
}

let resources: ResourceRecord[];

function record(kind: string, logicalName: string, args: Record<string, unknown>) {
  resources.push({ kind, logicalName, args });
}

function installGlobals() {
  (globalThis as Record<string, unknown>).$jsonStringify = (value: unknown) =>
    out(JSON.stringify(materialize(value)));
  (globalThis as Record<string, unknown>).aws = {
    getCallerIdentityOutput: () => ({ accountId: out("123456789012") }),
    getRegionOutput: () => ({ name: out("ap-northeast-1") }),
    cloudwatch: {
      LogMetricFilter: class {
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("LogMetricFilter", logicalName, args);
        }
      },
      MetricAlarm: class {
        arn: TestOutput<string>;
        constructor(logicalName: string, args: Record<string, unknown>) {
          this.arn = out(
            `arn:aws:cloudwatch:ap-northeast-1:123456789012:alarm:` +
            `mem9-on-aws-prod-${logicalName}`,
          );
          record("MetricAlarm", logicalName, args);
        }
      },
      CompositeAlarm: class {
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("CompositeAlarm", logicalName, args);
        }
      },
      Dashboard: class {
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("Dashboard", logicalName, args);
        }
      },
    },
    lambda: {
      FunctionEventInvokeConfig: class {
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("FunctionEventInvokeConfig", logicalName, args);
        }
      },
      Permission: class {
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("LambdaPermission", logicalName, args);
        }
      },
    },
    sns: {
      Topic: class {
        arn = out("arn:aws:sns:ap-northeast-1:123456789012:mem9-on-aws-prod-alerts");
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("Topic", logicalName, args);
        }
      },
      TopicSubscription: class {
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("TopicSubscription", logicalName, args);
        }
      },
    },
    sqs: {
      Queue: class {
        arn: TestOutput<string>;
        name: TestOutput<string>;
        url: TestOutput<string>;
        constructor(logicalName: string, args: Record<string, unknown>) {
          const physicalName = `mem9-on-aws-prod-${logicalName}`;
          this.arn = out(`arn:aws:sqs:ap-northeast-1:123456789012:${physicalName}`);
          this.name = out(physicalName);
          this.url = out(`https://example.com/queues/${physicalName}`);
          record("Queue", logicalName, args);
        }
      },
      QueuePolicy: class {
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("QueuePolicy", logicalName, args);
        }
      },
    },
  };
  (globalThis as Record<string, unknown>).sst = {
    aws: {
      Function: class {
        arn = out(
          "arn:aws:lambda:ap-northeast-1:123456789012:function:mem9-on-aws-prod-alert-router",
        );
        name = out("mem9-on-aws-prod-alert-router");
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("Function", logicalName, args);
        }
      },
    },
  };
}

function one(kind: string): ResourceRecord {
  const matches = resources.filter((resource) => resource.kind === kind);
  expect(matches).toHaveLength(1);
  return matches[0];
}

function queue(logicalName: string): ResourceRecord {
  const match = resources.find(
    (resource) => resource.kind === "Queue" && resource.logicalName === logicalName,
  );
  expect(match).toBeDefined();
  return match!;
}

function named(kind: string, logicalName: string): ResourceRecord {
  const match = resources.find(
    (resource) => resource.kind === kind && resource.logicalName === logicalName,
  );
  expect(match).toBeDefined();
  return match!;
}

const prodInputs = {
  stage: "prod",
  logGroupName: out("/logs/mem9") as never,
  slackWebhookUrl: "https://example.com/hooks/test",
  mantleProject: "proj_testxyz",
};

function durableFailureRatio(failures: number, terminal: number): number {
  return terminal >= 20 ? failures / terminal : 0;
}

/** Mirrors ZERO_FACT_RATE_EXPRESSION — the zero-fact alarm's math. */
function zeroFactRate(zeroFactJobs: number, succeeded: number): number {
  return succeeded > 50 ? zeroFactJobs / succeeded : 0;
}

function zeroFactBreaches(zeroFactJobs: number, succeeded: number): boolean {
  return zeroFactRate(zeroFactJobs, succeeded) >= ZERO_FACT_ALARM_THRESHOLD;
}

function prescreenRate(counter: number, evaluated: number): number {
  return evaluated > 0 ? counter / evaluated : 0;
}

beforeEach(() => {
  resources = [];
  installGlobals();
});

afterEach(() => {
  for (const name of ["$jsonStringify", "aws", "sst"]) {
    delete (globalThis as Record<string, unknown>)[name];
  }
  vi.restoreAllMocks();
});

describe("observability alert delivery", () => {
  it("TC-ALERT-001: requires a managed sink only in production", () => {
    expect(() =>
      observability({
        stage: "prod",
        logGroupName: out("/logs/mem9") as never,
        mantleProject: "proj_testxyz",
      }),
    ).toThrow("SLACK_WEBHOOK_URL is required for production alert delivery");
    expect(resources).toHaveLength(0);

    expect(() =>
      observability({
        stage: "prod",
        logGroupName: out("/logs/mem9") as never,
        slackWebhookUrl: "https://example.com/hooks/test",
        mantleProject: "",
      }),
    ).toThrow("MEM9_BEDROCK_PROJECT is required for production observability");
    expect(resources).toHaveLength(0);

    expect(() =>
      observability({ stage: "pr-47", logGroupName: out("/logs/mem9") as never }),
    ).not.toThrow();
    expect(resources).toHaveLength(0);
  });

  it("TC-ALERT-001/009/014: attaches configured production actions to one topic", () => {
    observability(prodInputs);

    const topic = one("Topic");
    expect(topic.args).toEqual({ name: "mem9-on-aws-prod-alerts" });
    const alarms = resources.filter((resource) => resource.kind === "MetricAlarm");
    expect(alarms).toHaveLength(11);
    const actionBearingMetricAlarms = alarms.filter(
      (alarm) => alarm.args.alarmActions !== undefined,
    );
    expect(actionBearingMetricAlarms).toHaveLength(9);
    for (const alarm of actionBearingMetricAlarms) {
      expect(materialize(alarm.args.alarmActions)).toEqual([
        "arn:aws:sns:ap-northeast-1:123456789012:mem9-on-aws-prod-alerts",
      ]);
      expect(materialize(alarm.args.okActions)).toEqual(
        materialize(alarm.args.alarmActions),
      );
      expect(alarm.args.treatMissingData).toBe("notBreaching");
    }
    const composite = one("CompositeAlarm");
    expect(materialize(composite.args.alarmActions)).toEqual([
      "arn:aws:sns:ap-northeast-1:123456789012:mem9-on-aws-prod-alerts",
    ]);
    expect(composite.args.okActions).toBeUndefined();

    const queueAlarms = alarms.filter(
      (alarm) => alarm.args.metricName === "ApproximateNumberOfMessagesVisible",
    );
    expect(queueAlarms).toHaveLength(2);
    expect(
      queueAlarms
        .map((alarm) => materialize(alarm.args.dimensions))
        .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
    ).toEqual([
      { QueueName: "mem9-on-aws-prod-AlertExecutionFailureQueue" },
      { QueueName: "mem9-on-aws-prod-AlertTransportFailureQueue" },
    ]);
    for (const alarm of queueAlarms) {
      expect(alarm.args.comparisonOperator).toBe("GreaterThanThreshold");
      expect(alarm.args.threshold).toBe(0);
    }
  });

  it("TC-ALERT-002/003/004/010: separates redrive and execution destinations", () => {
    observability(prodInputs);

    const transport = queue("AlertTransportFailureQueue");
    const execution = queue("AlertExecutionFailureQueue");
    expect(transport.args).toEqual({
      messageRetentionSeconds: 1_209_600,
      sqsManagedSseEnabled: true,
    });
    expect(execution.args).toEqual({
      messageRetentionSeconds: 1_209_600,
      sqsManagedSseEnabled: true,
    });

    const subscription = one("TopicSubscription");
    expect(
      JSON.parse(materialize(subscription.args.redrivePolicy) as string),
    ).toEqual({
      deadLetterTargetArn:
        "arn:aws:sqs:ap-northeast-1:123456789012:mem9-on-aws-prod-AlertTransportFailureQueue",
    });

    const invokeConfig = one("FunctionEventInvokeConfig");
    expect(materialize(invokeConfig.args)).toMatchObject({
      destinationConfig: {
        onFailure: {
          destination:
            "arn:aws:sqs:ap-northeast-1:123456789012:mem9-on-aws-prod-AlertExecutionFailureQueue",
        },
      },
      maximumEventAgeInSeconds: 7_200,
      maximumRetryAttempts: 2,
    });
    expect(JSON.stringify(materialize(invokeConfig.args.destinationConfig))).not.toContain(
      "AlertTransportFailureQueue",
    );
  });

  it("TC-ALERT-002/003/010: scopes SNS and Lambda queue writes", () => {
    observability(prodInputs);

    const queuePolicy = one("QueuePolicy");
    const policy = JSON.parse(materialize(queuePolicy.args.policy) as string);
    expect(policy.Statement).toEqual([
      {
        Action: "sqs:SendMessage",
        Condition: {
          ArnEquals: {
            "aws:SourceArn":
              "arn:aws:sns:ap-northeast-1:123456789012:mem9-on-aws-prod-alerts",
          },
          StringEquals: { "aws:SourceAccount": "123456789012" },
        },
        Effect: "Allow",
        Principal: { Service: "sns.amazonaws.com" },
        Resource:
          "arn:aws:sqs:ap-northeast-1:123456789012:mem9-on-aws-prod-AlertTransportFailureQueue",
      },
    ]);

    const fn = one("Function");
    expect(materialize(fn.args.permissions)).toEqual([
      {
        actions: ["sqs:SendMessage"],
        resources: [
          "arn:aws:sqs:ap-northeast-1:123456789012:mem9-on-aws-prod-AlertExecutionFailureQueue",
        ],
      },
    ]);

    expect(materialize(one("LambdaPermission").args)).toMatchObject({
      action: "lambda:InvokeFunction",
      principal: "sns.amazonaws.com",
      sourceArn: "arn:aws:sns:ap-northeast-1:123456789012:mem9-on-aws-prod-alerts",
    });
  });

  it("TC-ALERT-010: deploy role has least-privilege alert control-plane access", () => {
    const source = readFileSync(
      new URL("./cloudformation/github-actions-role.yaml", import.meta.url),
      "utf8",
    );
    const template = parse(source, {
      customTags: [
        { tag: "!Ref", resolve: (value: string) => ({ Ref: value }) },
        { tag: "!Sub", resolve: (value: string) => ({ "Fn::Sub": value }) },
        {
          tag: "!Equals",
          collection: "seq",
          resolve: (value) => ({ "Fn::Equals": value.toJSON() }),
        },
        {
          tag: "!If",
          collection: "seq",
          resolve: (value) => ({ "Fn::If": value.toJSON() }),
        },
        {
          tag: "!GetAtt",
          resolve: (value: string) => ({ "Fn::GetAtt": value.split(".") }),
        },
      ],
    }) as {
      Resources: Record<string, { Properties: Record<string, unknown> }>;
    };

    expect(template.Resources.AlertDeliveryPolicy.Properties.PolicyDocument).toEqual({
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "SqsAlertQueueCreate",
          Effect: "Allow",
          Action: ["sqs:CreateQueue"],
          Resource: [
            {
              "Fn::Sub":
                "arn:${AWS::Partition}:sqs:*:${AWS::AccountId}:AlertTransportFailureQueue-*",
            },
            {
              "Fn::Sub":
                "arn:${AWS::Partition}:sqs:*:${AWS::AccountId}:AlertExecutionFailureQueue-*",
            },
          ],
          Condition: {
            StringEquals: {
              "aws:RequestTag/Project": { Ref: "ProjectName" },
              "aws:RequestTag/ManagedBy": "sst",
            },
          },
        },
        {
          Sid: "SqsAlertQueueManage",
          Effect: "Allow",
          Action: [
            "sqs:DeleteQueue",
            "sqs:GetQueueAttributes",
            "sqs:GetQueueUrl",
            "sqs:ListQueueTags",
            "sqs:SetQueueAttributes",
            "sqs:TagQueue",
            "sqs:UntagQueue",
          ],
          Resource: [
            {
              "Fn::Sub":
                "arn:${AWS::Partition}:sqs:*:${AWS::AccountId}:AlertTransportFailureQueue-*",
            },
            {
              "Fn::Sub":
                "arn:${AWS::Partition}:sqs:*:${AWS::AccountId}:AlertExecutionFailureQueue-*",
            },
          ],
        },
        {
          Sid: "LambdaAlertAsyncConfig",
          Effect: "Allow",
          Action: [
            "lambda:DeleteFunctionEventInvokeConfig",
            "lambda:GetFunctionEventInvokeConfig",
            "lambda:PutFunctionEventInvokeConfig",
          ],
          Resource: [
            {
              "Fn::Sub":
                "arn:${AWS::Partition}:lambda:*:${AWS::AccountId}:function:${ProjectName}-*",
            },
          ],
        },
      ],
    });

    const computePolicy = template.Resources.ComputePolicy.Properties.PolicyDocument as {
      Statement: Array<Record<string, unknown>>;
    };
    const topicStatement = computePolicy.Statement.find(
      (statement) => statement.Sid === "SnsAlerting",
    );
    expect(topicStatement).toMatchObject({
      Effect: "Allow",
      Resource: [
        {
          "Fn::Sub": "arn:${AWS::Partition}:sns:*:${AWS::AccountId}:mem9-on-aws-*",
        },
      ],
    });
    expect(topicStatement?.Action).not.toContain("sns:SetSubscriptionAttributes");

    expect(
      computePolicy.Statement.find(
        (statement) => statement.Sid === "CloudWatchAlarmsForScaling",
      ),
    ).toMatchObject({
      Effect: "Allow",
      Action: expect.arrayContaining([
        "cloudwatch:PutCompositeAlarm",
        "cloudwatch:PutMetricAlarm",
      ]),
      Resource: "*",
    });

    expect(
      computePolicy.Statement.find(
        (statement) => statement.Sid === "CloudWatchDashboards",
      ),
    ).toEqual({
      Sid: "CloudWatchDashboards",
      Effect: "Allow",
      Action: [
        "cloudwatch:DeleteDashboards",
        "cloudwatch:GetDashboard",
        "cloudwatch:PutDashboard",
      ],
      Resource: [
        {
          "Fn::Sub":
            "arn:${AWS::Partition}:cloudwatch::${AWS::AccountId}:dashboard/mem9-on-aws-*-ingest",
        },
      ],
    });

    expect(
      computePolicy.Statement.find(
        (statement) => statement.Sid === "CloudWatchDashboardList",
      ),
    ).toEqual({
      Sid: "CloudWatchDashboardList",
      Effect: "Allow",
      Action: "cloudwatch:ListDashboards",
      Resource: "*",
    });

    expect(
      computePolicy.Statement.find(
        (statement) => statement.Sid === "SnsSubscriptionRead",
      ),
    ).toEqual({
      Sid: "SnsSubscriptionRead",
      Effect: "Allow",
      Action: [
        "sns:GetSubscriptionAttributes",
        "sns:SetSubscriptionAttributes",
        "sns:Unsubscribe",
      ],
      Resource: "*",
    });

    expect(template.Resources.GitHubActionsRole.Properties.ManagedPolicyArns).toEqual([
      { Ref: "DenyPolicy" },
      { Ref: "CorePolicy" },
      { Ref: "ScaffoldPolicy" },
      { Ref: "DatabasePolicy" },
      { Ref: "ComputePolicy" },
      { Ref: "ImageBuildPolicy" },
      { Ref: "LambdaProxyPolicy" },
      { Ref: "GatewayMcpPolicy" },
      { Ref: "OAuth2FacadePolicy" },
      { Ref: "AlertDeliveryPolicy" },
    ]);
  });

  it("TC-INGEST-METRIC-015/019: separates Mantle and durable dashboard metrics", () => {
    observability(prodInputs);

    const dashboard = one("Dashboard");
    expect(dashboard.args.dashboardName).toBe("mem9-on-aws-prod-ingest");
    const body = JSON.parse(materialize(dashboard.args.dashboardBody) as string);
    const serialized = JSON.stringify(body);
    expect(serialized).toContain("Bedrock Mantle provider");
    expect(serialized).toContain("Durable ingest application");
    expect(serialized).toContain("AWS/BedrockMantle");
    expect(serialized).toContain("mem9-on-aws/DurableIngest");
    expect(serialized).toContain("proj_testxyz");
    for (const metric of [
      "Inferences",
      "TotalInputTokens",
      "TotalOutputTokens",
      "InferenceClientErrors",
    ]) {
      expect(serialized).toContain(metric);
    }
    expect(serialized).not.toContain("InvocationLatency");
    expect(serialized).not.toContain("TimeToFirstToken");
    expect(serialized).not.toContain("RetryCount");
    expect(serialized).toContain("SamplerHeartbeat");

    const retryWidget = body.widgets.find(
      (widget: { properties?: { title?: string } }) =>
        widget.properties?.title === "Retries and warnings",
    );
    expect(retryWidget.properties.metrics.slice(0, 2)).toEqual([
      [
        {
          expression: "FILL(retry_transitions, 0)",
          id: "retry_transitions_filled",
          label: "Retry transitions",
        },
      ],
      [
        "mem9-on-aws/DurableIngest",
        "JobsRetrying",
        "stage",
        "prod",
        {
          id: "retry_transitions",
          stat: "Sum",
          visible: false,
        },
      ],
    ]);
    expect(JSON.stringify(retryWidget)).not.toContain("SEARCH(");

    const providerMetrics = body.widgets
      .filter((widget: { type: string }) => widget.type === "metric")
      .flatMap((widget: { properties: { metrics?: unknown[] } }) =>
        widget.properties.metrics ?? [],
      )
      .filter((metric: unknown[]) => metric[0] === "AWS/BedrockMantle");
    expect(providerMetrics.length).toBeGreaterThan(0);
    for (const metric of providerMetrics) {
      expect(metric.slice(2, 4)).toEqual(["Project", "proj_testxyz"]);
    }
  });

  it("TC-PRESCREEN-020/021/022: renders bounded shadow rates without changing alarms", () => {
    expect(PRESCREEN_POLICY_VERSION).toBe("msg-count-le-1-v1");
    expect(PRESCREEN_WOULD_SKIP_RATE_EXPRESSION).toBe(
      "IF(prescreen_evaluated > 0, prescreen_would_skip / prescreen_evaluated, 0)",
    );
    expect(PRESCREEN_FALSE_SKIP_RATE_EXPRESSION).toBe(
      "IF(prescreen_evaluated > 0, prescreen_false_skip / prescreen_evaluated, 0)",
    );
    expect(prescreenRate(0, 0)).toBe(0);
    expect(prescreenRate(10, 100)).toBe(0.1);
    expect(prescreenRate(3, 683)).toBeCloseTo(0.004392, 6);

    observability(prodInputs);
    const body = JSON.parse(
      materialize(one("Dashboard").args.dashboardBody) as string,
    );
    const widget = body.widgets.find(
      (candidate: { properties?: { title?: string } }) =>
        candidate.properties?.title === "Extraction and pre-screen outcomes",
    );
    expect(widget).toBeDefined();
    expect(widget.properties.metrics).toEqual([
      [
        "mem9-on-aws/DurableIngest",
        "ZeroFactSuccess",
        "stage",
        "prod",
        { stat: "Sum" },
      ],
      [
        {
          expression: PRESCREEN_WOULD_SKIP_RATE_EXPRESSION,
          id: "prescreen_would_skip_rate",
          label: "Would-skip rate",
          yAxis: "right",
        },
      ],
      [
        {
          expression: PRESCREEN_FALSE_SKIP_RATE_EXPRESSION,
          id: "prescreen_false_skip_rate",
          label: "False-skip rate",
          yAxis: "right",
        },
      ],
      [
        "mem9-on-aws/DurableIngest",
        "PrescreenEvaluated",
        "stage",
        "prod",
        "policy_version",
        PRESCREEN_POLICY_VERSION,
        {
          id: "prescreen_evaluated",
          stat: "Sum",
          visible: false,
        },
      ],
      [
        "mem9-on-aws/DurableIngest",
        "PrescreenWouldSkip",
        "stage",
        "prod",
        "policy_version",
        PRESCREEN_POLICY_VERSION,
        {
          id: "prescreen_would_skip",
          stat: "Sum",
          visible: false,
        },
      ],
      [
        "mem9-on-aws/DurableIngest",
        "PrescreenFalseSkip",
        "stage",
        "prod",
        "policy_version",
        PRESCREEN_POLICY_VERSION,
        {
          id: "prescreen_false_skip",
          stat: "Sum",
          visible: false,
        },
      ],
    ]);
    expect(JSON.stringify(widget)).not.toContain("SEARCH(");
    expect(
      resources.filter(
        (resource) =>
          resource.kind === "MetricAlarm" ||
          resource.kind === "CompositeAlarm",
      ),
    ).toHaveLength(12);
  });

  it("TC-ALERT-015/TC-INGEST-METRIC-016/018/019/024..027: pins alarm semantics", () => {
    observability(prodInputs);

    const recall = named("MetricAlarm", "RecallZeroHitRateAlarm").args;
    expect(recall).toMatchObject({
      alarmDescription:
        "Recall zero-hit rate > 70% over 1h (issue #23 regression guard). " +
        "Check cutoff_reason in the confidence recall search log lines.",
      evaluationPeriods: 1,
      threshold: 0.7,
      comparisonOperator: "GreaterThanThreshold",
      treatMissingData: "notBreaching",
    });
    expect(
      (
        recall.metricQueries as Array<{
          metric?: Record<string, unknown>;
        }>
      ).flatMap((query) =>
        query.metric
          ? [{
              period: query.metric.period,
              dimensions: query.metric.dimensions,
            }]
          : [],
      ),
    ).toEqual([
      { period: 3600, dimensions: undefined },
      { period: 3600, dimensions: undefined },
    ]);
    expect(recall.dimensions).toBeUndefined();

    expect(named("MetricAlarm", "IngestAuthFailureAlarm").args).toMatchObject({
      alarmDescription:
        "≥3 ingest LLM auth failures (401) in 15 min — llm-proxy bearer " +
        "may be dead (issue #24 regression guard). Check llm-proxy logs " +
        "for reason=auth_remint or credential-rotation events.",
      namespace: "mem9-on-aws",
      metricName: "ingest_llm_auth_failure",
      statistic: "Sum",
      period: 900,
      evaluationPeriods: 1,
      threshold: 3,
      comparisonOperator: "GreaterThanOrEqualToThreshold",
      treatMissingData: "notBreaching",
    });

    expect(named("MetricAlarm", "DurableIngestDeadJobAlarm").args).toMatchObject({
      alarmDescription:
        "At least one durable ingest job reached dead state in 15 minutes.",
      namespace: "mem9-on-aws/DurableIngest",
      metricName: "JobsDead",
      dimensions: { stage: "prod" },
      statistic: "Sum",
      period: 900,
      evaluationPeriods: 1,
      threshold: 1,
      comparisonOperator: "GreaterThanOrEqualToThreshold",
      treatMissingData: "notBreaching",
    });
    expect(named("MetricAlarm", "DurableIngestOldestQueuedAgeAlarm").args).toMatchObject({
      alarmDescription:
        "The oldest durable ingest job remained queued for more than 10 minutes.",
      namespace: "mem9-on-aws/DurableIngest",
      metricName: "OldestQueuedAgeMs",
      dimensions: { stage: "prod" },
      statistic: "Maximum",
      period: 300,
      evaluationPeriods: 2,
      datapointsToAlarm: 2,
      threshold: 600_000,
      comparisonOperator: "GreaterThanThreshold",
      treatMissingData: "notBreaching",
    });
    expect(named("MetricAlarm", "DurableIngestZeroFactRateAlarm").args).toMatchObject({
      threshold: ZERO_FACT_ALARM_THRESHOLD,
      evaluationPeriods: 1,
      comparisonOperator: "GreaterThanOrEqualToThreshold",
      treatMissingData: "notBreaching",
    });
    expect(
      named("MetricAlarm", "DurableIngestZeroFactRateAlarm").args.metricQueries,
    ).toEqual([
      {
        id: "zero_rate",
        metric: {
          namespace: "mem9-on-aws/DurableIngest",
          metricName: "ZeroFactSuccess",
          dimensions: { stage: "prod" },
          // ZeroFactSuccess is 0/1 per succeeded job, so Average IS the rate.
          stat: "Average",
          // Daily, not hourly: healthy prod runs six consecutive 100% HOURS.
          period: 86400,
        },
        returnData: false,
      },
      {
        id: "succeeded",
        metric: {
          namespace: "mem9-on-aws/DurableIngest",
          metricName: "JobsSucceeded",
          dimensions: { stage: "prod", result_class: "succeeded" },
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
    ]);

    expect(named("MetricAlarm", "DurableIngestTelemetryLivenessAlarm").args).toEqual({
      alarmDescription:
        "The once-per-minute durable ingest sampler stopped emitting ECS-origin telemetry.",
      metricQueries: [
        {
          id: "heartbeat",
          metric: {
            namespace: "mem9-on-aws/DurableIngest",
            metricName: "SamplerHeartbeat",
            dimensions: { stage: "prod" },
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
      treatMissingData: "breaching",
    });
    expect(
      named("MetricAlarm", "DurableIngestTelemetryActionDelayGuard").args,
    ).toEqual({
      alarmDescription:
        "Always-OK guard that gives liveness alarm actions one bounded deployment grace period.",
      namespace: "mem9-on-aws/DurableIngest",
      metricName: "SamplerHeartbeat",
      dimensions: { stage: "prod" },
      statistic: "Minimum",
      period: 60,
      evaluationPeriods: 1,
      threshold: 0,
      comparisonOperator: "LessThanThreshold",
      treatMissingData: "notBreaching",
    });
    expect(
      materialize(
        named("CompositeAlarm", "DurableIngestTelemetryLivenessNotification").args,
      ),
    ).toEqual({
      alarmName: "mem9-on-aws-prod-durable-ingest-telemetry-liveness",
      alarmDescription:
        "Durable ingest telemetry was absent through the bounded deployment grace period.",
      alarmRule:
        'ALARM("arn:aws:cloudwatch:ap-northeast-1:123456789012:alarm:' +
        'mem9-on-aws-prod-DurableIngestTelemetryLivenessAlarm")',
      actionsSuppressor: {
        alarm:
          "arn:aws:cloudwatch:ap-northeast-1:123456789012:alarm:" +
          "mem9-on-aws-prod-DurableIngestTelemetryActionDelayGuard",
        waitPeriod: 300,
        extensionPeriod: 0,
      },
      alarmActions: [
        "arn:aws:sns:ap-northeast-1:123456789012:mem9-on-aws-prod-alerts",
      ],
    });

    const ratio = named("MetricAlarm", "DurableIngestFailureRatioAlarm").args;
    expect(ratio).toMatchObject({
      alarmDescription:
        "Deadline or Mantle transient failures are at least 10% of 20+ terminal jobs.",
      evaluationPeriods: 1,
      threshold: 0.1,
      comparisonOperator: "GreaterThanOrEqualToThreshold",
      treatMissingData: "notBreaching",
    });
    expect(ratio.metricQueries).toEqual([
      {
        id: "failures",
        metric: {
          metricName: "DeadlineTransientTerminalFailures",
          namespace: "mem9-on-aws/DurableIngest",
          stat: "Sum",
          period: 900,
          dimensions: { stage: "prod" },
        },
        returnData: false,
      },
      {
        id: "terminal",
        metric: {
          metricName: "JobsTerminated",
          namespace: "mem9-on-aws/DurableIngest",
          stat: "Sum",
          period: 900,
          dimensions: { stage: "prod" },
        },
        returnData: false,
      },
      {
        id: "rate",
        expression: DURABLE_FAILURE_RATIO_EXPRESSION,
        label: "Deadline/Transient Terminal Failure Ratio",
        returnData: true,
      },
    ]);

    expect(named("MetricAlarm", "MantleClientErrorAlarm").args).toMatchObject({
      alarmDescription: "Bedrock Mantle reported a Project-scoped client error.",
      namespace: "AWS/BedrockMantle",
      metricName: "InferenceClientErrors",
      dimensions: { Project: "proj_testxyz" },
      statistic: "Sum",
      period: 900,
      evaluationPeriods: 1,
      threshold: 1,
      comparisonOperator: "GreaterThanOrEqualToThreshold",
      treatMissingData: "notBreaching",
    });

    expect(
      materialize(
        named("MetricAlarm", "AlertTransportFailureQueueVisibleMessages").args,
      ),
    ).toMatchObject({
      alarmDescription:
        "SNS could not deliver an alarm event to the alert-router Lambda. " +
        "Follow the transport failure queue runbook.",
      namespace: "AWS/SQS",
      metricName: "ApproximateNumberOfMessagesVisible",
      dimensions: {
        QueueName: "mem9-on-aws-prod-AlertTransportFailureQueue",
      },
      statistic: "Maximum",
      period: 300,
      evaluationPeriods: 1,
      threshold: 0,
      comparisonOperator: "GreaterThanThreshold",
      treatMissingData: "notBreaching",
    });
    expect(
      materialize(
        named("MetricAlarm", "AlertExecutionFailureQueueVisibleMessages").args,
      ),
    ).toMatchObject({
      alarmDescription:
        "The alert-router Lambda exhausted retries or event age after accepting " +
        "an alarm event. Follow the execution failure queue runbook.",
      namespace: "AWS/SQS",
      metricName: "ApproximateNumberOfMessagesVisible",
      dimensions: {
        QueueName: "mem9-on-aws-prod-AlertExecutionFailureQueue",
      },
      statistic: "Maximum",
      period: 300,
      evaluationPeriods: 1,
      threshold: 0,
      comparisonOperator: "GreaterThanThreshold",
      treatMissingData: "notBreaching",
    });
  });

  it("TC-INGEST-METRIC-016/018/024..026: evaluates bounded alarm fixtures", () => {
    observability(prodInputs);

    const queueCases = [
      { name: "real backlog", samples: [600_001, 600_001], expected: true },
      { name: "missing queue age", samples: [undefined, undefined], expected: false },
    ];
    for (const { name, samples, expected } of queueCases) {
      const breaches = samples.filter(
        (sample) => sample !== undefined && sample > 600_000,
      );
      expect(breaches.length >= 2, name).toBe(expected);
    }

    const heartbeatCases: Array<{
      name: string;
      samples: Array<number | undefined>;
      expected: boolean;
    }> = [
      { name: "healthy", samples: [1, 1, 1, 1, 1], expected: false },
      {
        name: "latest sample delayed",
        samples: [1, 1, 1, 1, undefined],
        expected: false,
      },
      {
        name: "four-sample rollout gap",
        samples: [1, undefined, undefined, undefined, undefined],
        expected: false,
      },
      {
        name: "initial enablement",
        samples: [undefined, undefined, undefined, undefined, undefined],
        expected: true,
      },
      {
        name: "older healthy samples cannot extend the window",
        samples: [1, 1, 1, undefined, undefined, undefined, undefined, undefined],
        expected: true,
      },
    ];
    for (const { name, samples, expected } of heartbeatCases) {
      const current = samples.slice(-5).map((sample) => sample ?? 0);
      expect(current.every((sample) => sample < 1), name).toBe(expected);
    }

    const notification = named(
      "CompositeAlarm",
      "DurableIngestTelemetryLivenessNotification",
    ).args;
    expect(notification.actionsSuppressor).toMatchObject({
      waitPeriod: 300,
      extensionPeriod: 0,
    });
    expect(notification.okActions).toBeUndefined();
  });

  it("TC-INGEST-METRIC-017: gates failure ratio on twenty terminal jobs", () => {
    expect(DURABLE_FAILURE_RATIO_EXPRESSION).toBe(
      "IF(terminal >= 20, failures / terminal, 0)",
    );
    expect(durableFailureRatio(2, 19)).toBe(0);
    expect(durableFailureRatio(1, 20)).toBe(0.05);
    expect(durableFailureRatio(2, 20)).toBe(0.1);
    expect(durableFailureRatio(3, 30)).toBe(0.1);
  });

  it("TC-INGEST-METRIC-031/032: zero-fact alarm clears the measured healthy baseline", () => {
    // Pin the shipped expression as a LITERAL. The mirror below reimplements
    // this math, so comparing the constant to itself would let a mutation of
    // either the guard value or the branch order pass unnoticed.
    expect(ZERO_FACT_RATE_EXPRESSION).toBe("IF(succeeded > 50, zero_rate, 0)");
    // Exactly 1.0, not a fraction: at 200 jobs, 0.995 pages on a day that
    // extracted a single real fact.
    expect(ZERO_FACT_ALARM_THRESHOLD).toBe(1);

    // Real prod daily buckets (Jul 28 - Aug 1, 2026), zero-fact / succeeded.
    // Every one is a HEALTHY day: a high zero-fact rate is the correct outcome
    // of rule D4 for sessions with no durable takeaway.
    for (const [zero, succeeded] of [
      [97, 101], // 96%
      [144, 176], // 82%
      [342, 377], // 91%
      [280, 312], // 90%
      [231, 300], // 77%
    ]) {
      expect(zeroFactBreaches(zero, succeeded)).toBe(false);
    }

    // Six consecutive 100% HOURS from the same healthy baseline (Jul 30
    // 17:00-23:00). Aggregated they are 134 succeeded jobs with ZERO facts —
    // past the traffic guard and a breach at any threshold. This is the
    // concrete reason the window is a full day: evaluated hourly (or over any
    // sub-day window covering this stretch) the alarm would page on traffic
    // that was healthy.
    const healthyHours = [41, 3, 27, 8, 37, 18];
    const stretch = healthyHours.reduce((sum, jobs) => sum + jobs, 0);
    expect(stretch).toBe(134);
    expect(zeroFactBreaches(stretch, stretch)).toBe(true);
    // Over the real day those hours belong to, the same traffic stays quiet:
    // Jul 30 extracted 35 facts across 377 jobs.
    expect(zeroFactBreaches(342, 377)).toBe(false);

    // A quiet day that is entirely zero-fact still cannot page: too few jobs
    // to distinguish a blackout from normal low-signal traffic.
    expect(zeroFactBreaches(50, 50)).toBe(false);
    expect(zeroFactBreaches(51, 51)).toBe(true); // one job past the guard

    // The boundary that matters: ONE successful extraction keeps it quiet, at
    // the smallest healthy daily volume observed (101 jobs). The alarm asserts
    // a TOTAL blackout, never degraded quality (that is #104/#106's scope).
    expect(zeroFactBreaches(101, 101)).toBe(true);
    expect(zeroFactBreaches(100, 101)).toBe(false);
    expect(zeroFactBreaches(299, 300)).toBe(false);
  });

  it("TC-INGEST-METRIC-015/016/017/023: pins emitter metrics to dashboard and alarms", () => {
    const patch = readFileSync(
      new URL(
        "../docker/mnemo-server/patches/0006-durable-ingest-telemetry.patch",
        import.meta.url,
      ),
      "utf8",
    );
    const telemetryStart = patch.indexOf(
      "+++ b/server/internal/ingestqueue/telemetry.go",
    );
    const telemetryEnd = patch.indexOf(
      "diff --git a/server/internal/ingestqueue/telemetry_test.go",
    );
    expect(telemetryStart).toBeGreaterThanOrEqual(0);
    expect(telemetryEnd).toBeGreaterThan(telemetryStart);
    const emitter = patch.slice(telemetryStart, telemetryEnd);

    expect(emitter).toContain(
      'const DurableMetricNamespace = "mem9-on-aws/DurableIngest"',
    );
    for (const metric of [
      "JobsRetrying",
      "JobsDead",
      "JobsTerminated",
      "DeadlineTransientTerminalFailures",
      "SamplerHeartbeat",
      // Both feed DurableIngestZeroFactRateAlarm. If the emitter stops
      // publishing either, the metric vanishes from CloudWatch and the alarm
      // sits INSUFFICIENT_DATA → notBreaching → reads healthy forever. Pinning
      // the PRODUCER matters most on the one alarm whose failure mode is
      // silence.
      "ZeroFactSuccess",
      "JobsSucceeded",
    ]) {
      expect(emitter).toContain(`countMetric("${metric}")`);
    }
    expect(emitter).toContain('millisecondMetric("OldestQueuedAgeMs")');

    const prescreenPatch = readFileSync(
      new URL(
        "../docker/mnemo-server/patches/0008-ingest-prescreen-shadow.patch",
        import.meta.url,
      ),
      "utf8",
    );
    const prescreenEmitterStart = prescreenPatch.indexOf(
      "+++ b/server/internal/ingestqueue/telemetry.go",
    );
    const prescreenEmitterEnd = prescreenPatch.indexOf(
      "diff --git a/server/internal/ingestqueue/telemetry_test.go",
    );
    expect(prescreenEmitterStart).toBeGreaterThanOrEqual(0);
    expect(prescreenEmitterEnd).toBeGreaterThan(prescreenEmitterStart);
    const prescreenEmitter = prescreenPatch.slice(
      prescreenEmitterStart,
      prescreenEmitterEnd,
    );
    for (const metric of [
      "PrescreenEvaluated",
      "PrescreenWouldSkip",
      "PrescreenFalseSkip",
    ]) {
      expect(prescreenEmitter).toContain(`countMetric("${metric}")`);
    }
    expect(prescreenEmitter).toContain(
      '[]string{"stage", "policy_version"}',
    );
  });

  it("TC-INGEST-METRIC-020: removes the obsolete ingest_dropped metric", () => {
    observability(prodInputs);
    const filters = resources.filter((resource) => resource.kind === "LogMetricFilter");
    expect(filters).toHaveLength(3);
    expect(JSON.stringify(filters.map((filter) => filter.args))).not.toContain(
      "ingest_dropped",
    );
  });
});
