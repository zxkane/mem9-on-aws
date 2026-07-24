/**
 * Slack Block-Kit formatter for CloudWatch alarm SNS payloads.
 *
 * Pure functions only — no `process.env` reads, no I/O. The handler in
 * `./handler.ts` owns transport and env wiring.
 *
 * Pattern lifted from a sibling project's alert router (SNS-delivered
 * CloudWatch alarm JSON → Block Kit). mem9's two alarms are plain metric
 * alarms (no composites), so the formatter handles just that shape plus an
 * unparseable-input fallback — silent dropping is the failure mode this
 * channel exists to prevent.
 */

interface AlarmPayload {
  AlarmName?: string;
  NewStateValue?: string;
  NewStateReason?: string;
  StateChangeTime?: string;
  Region?: string;
  AlarmDescription?: string;
}

const REASON_MAX = 300;

/**
 * Build the Slack webhook body for an SNS-delivered CloudWatch alarm
 * notification. Returns a JSON string ready for `body:` on the POST.
 */
export function formatAlarmMessage(snsMessage: string): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(snsMessage);
  } catch {
    return JSON.stringify({
      text: `:warning: mem9 unparseable alarm payload: ${snsMessage.slice(0, REASON_MAX)}`,
    });
  }

  const alarm = parsed as AlarmPayload;
  const name = alarm.AlarmName ?? "Unknown Alarm";
  const state = alarm.NewStateValue ?? "UNKNOWN";
  const time = alarm.StateChangeTime ?? "";
  const region = alarm.Region ?? "";

  const isOk = state === "OK";
  const emoji = isOk ? ":white_check_mark:" : ":rotating_light:";
  const label = isOk ? "RESOLVED" : "ALARM";

  const blocks: Record<string, unknown>[] = [
    {
      type: "section",
      text: { type: "mrkdwn", text: `${emoji} *[${label}] mem9: ${name}*` },
    },
    {
      type: "section",
      fields: [
        { type: "mrkdwn", text: `*State:* ${state}` },
        ...(region ? [{ type: "mrkdwn", text: `*Region:* ${region}` }] : []),
        ...(time ? [{ type: "mrkdwn", text: `*Time:* ${time}` }] : []),
      ],
    },
  ];

  if (alarm.AlarmDescription) {
    blocks.push({
      type: "section",
      text: { type: "mrkdwn", text: `*About:* ${alarm.AlarmDescription}` },
    });
  }
  if (alarm.NewStateReason) {
    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: `*Reason:* ${alarm.NewStateReason.slice(0, REASON_MAX)}`,
      },
    });
  }

  // `text` is the notification-preview fallback; `blocks` is the rendered body.
  return JSON.stringify({ text: `${label}: ${name} (${state})`, blocks });
}
