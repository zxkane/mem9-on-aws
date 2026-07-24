import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { observability } from "./observability";

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

function policyStatement(template: string, sid: string): string {
  const start = template.indexOf(`          - Sid: ${sid}`);
  expect(start).toBeGreaterThan(-1);
  const remainder = template.slice(start + 1);
  const nextStatement = remainder.search(/\n          - Sid: |\n\n  #/);
  return template.slice(start, nextStatement === -1 ? undefined : start + 1 + nextStatement);
}

function iamActions(statement: string): string[] {
  return [...statement.matchAll(/^\s+- ((?:sqs|lambda):[A-Za-z*]+)$/gm)]
    .map((match) => match[1])
    .sort();
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
      observability({ stage: "prod", logGroupName: out("/logs/mem9") as never }),
    ).toThrow("SLACK_WEBHOOK_URL is required for production alert delivery");
    expect(resources).toHaveLength(0);

    expect(() =>
      observability({ stage: "pr-47", logGroupName: out("/logs/mem9") as never }),
    ).not.toThrow();
    expect(resources).toHaveLength(0);
  });

  it("TC-ALERT-001/009: attaches every production alarm to one topic", () => {
    observability({
      stage: "prod",
      logGroupName: out("/logs/mem9") as never,
      slackWebhookUrl: "https://example.com/hooks/test",
    });

    const topic = one("Topic");
    expect(topic.args).toEqual({ name: "mem9-on-aws-prod-alerts" });
    const alarms = resources.filter((resource) => resource.kind === "MetricAlarm");
    expect(alarms).toHaveLength(4);
    for (const alarm of alarms) {
      expect(materialize(alarm.args.alarmActions)).toEqual([
        "arn:aws:sns:ap-northeast-1:123456789012:mem9-on-aws-prod-alerts",
      ]);
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
    observability({
      stage: "prod",
      logGroupName: out("/logs/mem9") as never,
      slackWebhookUrl: "https://example.com/hooks/test",
    });

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
    observability({
      stage: "prod",
      logGroupName: out("/logs/mem9") as never,
      slackWebhookUrl: "https://example.com/hooks/test",
    });

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

  it("TC-ALERT-010: deploy role has only tagged SQS control-plane access", () => {
    const template = readFileSync(
      new URL("./cloudformation/github-actions-role.yaml", import.meta.url),
      "utf8",
    );
    const create = policyStatement(template, "SqsAlertQueueCreate");
    const manage = policyStatement(template, "SqsAlertQueueManage");
    const asyncConfig = policyStatement(template, "LambdaAlertAsyncConfig");

    expect(iamActions(create)).toEqual(["sqs:CreateQueue"]);
    expect(create).toContain("arn:${AWS::Partition}:sqs:*:${AWS::AccountId}:*");
    expect(create).toContain("aws:RequestTag/Project: !Ref ProjectName");
    expect(create).toContain("aws:RequestTag/ManagedBy: sst");

    expect(iamActions(manage)).toEqual([
      "sqs:DeleteQueue",
      "sqs:GetQueueAttributes",
      "sqs:GetQueueUrl",
      "sqs:ListQueueTags",
      "sqs:SetQueueAttributes",
      "sqs:TagQueue",
      "sqs:UntagQueue",
    ]);
    expect(manage).toContain("arn:${AWS::Partition}:sqs:*:${AWS::AccountId}:*");
    expect(manage).toContain("aws:ResourceTag/Project: !Ref ProjectName");
    expect(manage).toContain("aws:ResourceTag/ManagedBy: sst");

    expect(iamActions(asyncConfig)).toEqual([
      "lambda:DeleteFunctionEventInvokeConfig",
      "lambda:GetFunctionEventInvokeConfig",
      "lambda:PutFunctionEventInvokeConfig",
    ]);
    expect(asyncConfig).toContain(
      "arn:${AWS::Partition}:lambda:*:${AWS::AccountId}:function:${ProjectName}-*",
    );

    const managedPolicyStart = template.indexOf("      ManagedPolicyArns:");
    const attachments = template.slice(
      managedPolicyStart,
      template.indexOf("      Tags:", managedPolicyStart),
    );
    expect([...attachments.matchAll(/^\s+- !Ref ([A-Za-z0-9]+)$/gm)].map((match) => match[1]))
      .toEqual([
        "DenyPolicy",
        "CorePolicy",
        "ScaffoldPolicy",
        "DatabasePolicy",
        "ComputePolicy",
        "ImageBuildPolicy",
        "LambdaProxyPolicy",
        "GatewayMcpPolicy",
        "OAuth2FacadePolicy",
        "AlertDeliveryPolicy",
      ]);
  });
});
