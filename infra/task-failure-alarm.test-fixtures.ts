/**
 * Pulumi `aws.cloudwatch` stubs for the six resources `taskFailureAlarm` creates.
 *
 * Shared by `consolidation.test.ts` and `slack-approval.test.ts` because the stub
 * SET is exactly that helper's resource set: a seventh resource added there needs
 * one stub added here, not two identical blocks kept in sync. The two harnesses
 * keep their own `record`/`out` (each owns its own resource log), so those are
 * passed in rather than imported.
 *
 * Only the attributes the real code reads back are exposed — `logGroup.arn` for the
 * resource policy, `rule.name` for the target, and `metricAlarm.arn` for a composite
 * alarm's rule and suppressor (#154). A stub with more attributes than the real code
 * consumes invites an assertion on a value nothing produces.
 */
export interface TaskFailureAlarmStubOptions {
  /** Recorder the host harness uses to log created resources. */
  record: (kind: string, logicalName: string, args: Record<string, unknown>) => void;
  /** The host harness's `Output` wrapper. */
  out: <T>(value: T) => unknown;
  /** Stand-in rule ARN/name; only the name is read (by the event target). */
  ruleName: string;
  /** Stand-in log group name; its ARN is read by the resource policy. */
  logGroupName: string;
}

export function cloudwatchStubs(options: TaskFailureAlarmStubOptions) {
  const { record, out, ruleName, logGroupName } = options;
  return {
    EventRule: class {
      arn = out(`arn:aws:events:ap-northeast-1:123456789012:rule/${ruleName}`);
      name = out(ruleName);
      constructor(logicalName: string, args: Record<string, unknown>) {
        record("EventRule", logicalName, args);
      }
    },
    EventTarget: class {
      constructor(logicalName: string, args: Record<string, unknown>) {
        record("EventTarget", logicalName, args);
      }
    },
    LogGroup: class {
      arn = out(
        `arn:aws:logs:ap-northeast-1:123456789012:log-group:${logGroupName}`,
      );
      name = out(logGroupName);
      constructor(logicalName: string, args: Record<string, unknown>) {
        record("LogGroup", logicalName, args);
      }
    },
    LogResourcePolicy: class {
      constructor(logicalName: string, args: Record<string, unknown>) {
        record("LogResourcePolicy", logicalName, args);
      }
    },
    LogMetricFilter: class {
      constructor(logicalName: string, args: Record<string, unknown>) {
        record("LogMetricFilter", logicalName, args);
      }
    },
    MetricAlarm: class {
      // The ARN is read back by a composite alarm's `alarmRule` and by its
      // `actionsSuppressor` (#154), the same way observability.test.ts's stub
      // exposes it. Derived from the logical name so a rule naming the wrong alarm
      // is visible in the assertion rather than matching by accident.
      arn: unknown;
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
  };
}
