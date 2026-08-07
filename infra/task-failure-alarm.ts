import { boundedNamePrefix } from "./consolidation";

// The failure alarm shared by the two scheduled/triggered ECS tasks: the weekly
// consolidation (#113) and the Slack-approved cleanup apply (#123).
//
// Both tasks have the same problem. They run unattended, every error path inside
// them ends in a log line, and a log line pages nobody — for cleanup the operator
// has already been told "Apply started", and for consolidation nobody is watching
// at all. The next signal without an alarm is a human noticing months of
// un-consolidated or un-tidied memories.
//
// An EventBridge rule on ECS task state change is used rather than a metric filter
// over the task's OWN logs because the most likely first-deploy failure produces no
// application log whatsoever: a task killed in the ECS agent's secret-fetch phase
// never runs its entrypoint. That is also why the exit-code filter is
// `anything-but: 0` and not a `> 0` comparison — such a task reports NO exitCode,
// which is exactly what a numeric filter drops.
//
// The rule is pinned to the task definition REVISION, never to the cluster: the
// cluster is shared with the server and the other task, so a cluster-wide rule
// would alarm one feature's topic on every unrelated task failure.
//
// Extracted because the two copies had already drifted — the cleanup copy carries
// `stoppedReason` (see `includeStoppedReason`) and the consolidation copy does not
// — and a third copy of ~110 lines of resource wiring is how the next one drifts
// further. The logical names stay caller-supplied so that extracting this changed
// no deployed resource's URN.

export interface TaskFailureAlarmArgs {
  /**
   * Logical-name stem, e.g. `ConsolidationTaskFailure`. Concatenated with
   * `Events`/`Rule`/`LogPolicy`/`LogTarget`/`Filter`/`Alarm` to reproduce the
   * exact logical names the two stacks already deployed. Changing a stem
   * RENAMES resources, which for the log group and the rule means Pulumi
   * replaces them and the alarm goes briefly blind.
   */
  stem: string;
  /** Log group name, e.g. `/sst/consolidation/{stage}/task-failures`. */
  logGroupName: string;
  /** `namePrefix` for the rule, budgeted against Pulumi's 26-char suffix. */
  rulePrefix: string;
  /** What the prefix is, for `boundedNamePrefix`'s error message. */
  ruleWhat: string;
  ruleDescription: string;
  /** `LogResourcePolicy` policy name — a NAME, so it must be stage-unique. */
  policyName: string;
  /** The `event` field, matched by the metric filter, e.g. `..._task_failed`. */
  eventName: string;
  metricName: string;
  alarmDescription: string;
  /** The task definition revision ARN this rule is pinned to. */
  taskDefinitionArn: Input<string>;
  alertsTopicArn: Input<string>;
  tags: Record<string, Input<string>>;
  /**
   * Carry `stoppedReason` into the log event. It is the ONLY field where a
   * startup failure names itself (`ResourceInitializationError` on the secret
   * fetch), so it is on for the cleanup task, whose execution role sits outside
   * the boundary's secret-decrypt exception list.
   *
   * Off for consolidation only because turning it on would change that stack's
   * deployed `inputTransformer` — a diff unrelated to whatever change is being
   * shipped. Worth doing on its own.
   */
  includeStoppedReason?: boolean;
}

const FAILURE_NAMESPACE = "mem9-on-aws";

/** EventBridge caps a rule NAME at 64 characters. */
const EVENT_RULE_NAME_MAX = 64;

export function taskFailureAlarm(args: TaskFailureAlarmArgs): void {
  const logGroup = new aws.cloudwatch.LogGroup(`${args.stem}Events`, {
    name: args.logGroupName,
    retentionInDays: 30,
    tags: args.tags,
  });

  const rule = new aws.cloudwatch.EventRule(`${args.stem}Rule`, {
    namePrefix: boundedNamePrefix(
      args.rulePrefix,
      EVENT_RULE_NAME_MAX,
      args.ruleWhat,
    ),
    description: args.ruleDescription,
    eventPattern: $jsonStringify({
      source: ["aws.ecs"],
      "detail-type": ["ECS Task State Change"],
      detail: {
        lastStatus: ["STOPPED"],
        taskDefinitionArn: [args.taskDefinitionArn],
        containers: { exitCode: [{ "anything-but": 0 }] },
      },
    }),
    tags: args.tags,
  });

  const logPolicy = new aws.cloudwatch.LogResourcePolicy(
    `${args.stem}LogPolicy`,
    {
      policyName: args.policyName,
      policyDocument: $jsonStringify({
        Version: "2012-10-17",
        Statement: [
          {
            Effect: "Allow",
            Principal: {
              Service: ["events.amazonaws.com", "delivery.logs.amazonaws.com"],
            },
            Action: ["logs:CreateLogStream", "logs:PutLogEvents"],
            Resource: $interpolate`${logGroup.arn}:*`,
          },
        ],
      }),
    },
  );

  new aws.cloudwatch.EventTarget(
    `${args.stem}LogTarget`,
    {
      arn: logGroup.arn,
      rule: rule.name,
      inputTransformer: {
        inputPaths: {
          exitCode: "$.detail.containers[0].exitCode",
          ...(args.includeStoppedReason
            ? { stoppedReason: "$.detail.stoppedReason" }
            : {}),
        },
        inputTemplate: JSON.stringify({
          event: args.eventName,
          stage: $app.stage,
          exitCode: "<exitCode>",
          ...(args.includeStoppedReason
            ? { stoppedReason: "<stoppedReason>" }
            : {}),
        }),
      },
    },
    // The policy must exist before EventBridge is asked to deliver to the group,
    // or the first PutTargets is rejected.
    { dependsOn: [logPolicy] },
  );

  new aws.cloudwatch.LogMetricFilter(`${args.stem}Filter`, {
    logGroupName: logGroup.name,
    pattern:
      `{ $.event = "${args.eventName}" && ` + `$.stage = "${$app.stage}" }`,
    metricTransformation: {
      name: args.metricName,
      namespace: FAILURE_NAMESPACE,
      value: "1",
      dimensions: { stage: "$.stage" },
    },
  });

  new aws.cloudwatch.MetricAlarm(`${args.stem}Alarm`, {
    alarmDescription: args.alarmDescription,
    namespace: FAILURE_NAMESPACE,
    metricName: args.metricName,
    dimensions: { stage: $app.stage },
    statistic: "Sum",
    period: 300,
    evaluationPeriods: 1,
    datapointsToAlarm: 1,
    threshold: 1,
    comparisonOperator: "GreaterThanOrEqualToThreshold",
    // A stage with no failures emits no datapoints at all, and `missing` would
    // hold the alarm in INSUFFICIENT_DATA forever rather than OK.
    treatMissingData: "notBreaching",
    alarmActions: [args.alertsTopicArn],
  });
}
