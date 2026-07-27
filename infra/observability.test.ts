import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { parse } from "yaml";
import {
  DURABLE_FAILURE_RATIO_EXPRESSION,
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
    cloudwatch: {
      LogMetricFilter: class {
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("LogMetricFilter", logicalName, args);
        }
      },
      MetricAlarm: class {
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("MetricAlarm", logicalName, args);
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

  it("TC-ALERT-001/009: attaches every production alarm to one topic", () => {
    observability(prodInputs);

    const topic = one("Topic");
    expect(topic.args).toEqual({ name: "mem9-on-aws-prod-alerts" });
    const alarms = resources.filter((resource) => resource.kind === "MetricAlarm");
    expect(alarms).toHaveLength(8);
    for (const alarm of alarms) {
      expect(materialize(alarm.args.alarmActions)).toEqual([
        "arn:aws:sns:ap-northeast-1:123456789012:mem9-on-aws-prod-alerts",
      ]);
      expect(alarm.args.treatMissingData).toBe("notBreaching");
    }

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
        (statement) => statement.Sid === "CloudWatchDashboards",
      ),
    ).toEqual({
      Sid: "CloudWatchDashboards",
      Effect: "Allow",
      Action: [
        "cloudwatch:DeleteDashboards",
        "cloudwatch:GetDashboard",
        "cloudwatch:ListDashboards",
        "cloudwatch:PutDashboard",
      ],
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

  it("TC-INGEST-METRIC-016/018/019: pins durable and Mantle alarms", () => {
    observability(prodInputs);

    expect(named("MetricAlarm", "DurableIngestDeadJobAlarm").args).toMatchObject({
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

    const ratio = named("MetricAlarm", "DurableIngestFailureRatioAlarm").args;
    expect(ratio).toMatchObject({
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

  it("TC-INGEST-METRIC-020: removes the obsolete ingest_dropped metric", () => {
    observability(prodInputs);
    const filters = resources.filter((resource) => resource.kind === "LogMetricFilter");
    expect(filters).toHaveLength(3);
    expect(JSON.stringify(filters.map((filter) => filter.args))).not.toContain(
      "ingest_dropped",
    );
  });
});
