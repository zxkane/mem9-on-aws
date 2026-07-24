/**
 * AlertRouter Lambda — SNS → Slack webhook bridge (mem9 observability).
 *
 * Subscribed directly to the `Mem9AlertsTopic` SNS topic (created in
 * `infra/observability.ts` only when the Slack webhook secret is configured).
 * POSTs Block-Kit messages to the Slack incoming webhook URL in
 * `SLACK_WEBHOOK_URL`.
 *
 * Direct SNS→Lambda (no delay queue): mem9's alarms carry everything needed
 * in the alarm payload itself — no CloudWatch Logs Insights enrichment, so
 * there is no log-indexing lag to outrun.
 *
 * Best-effort delivery: a non-2xx from Slack is logged but NOT thrown. The
 * CloudWatch alarm stays visible in the AWS console, and throwing would make
 * SNS redeliver — alert flooding once Slack recovers is worse than one
 * missed message.
 */

import { formatAlarmMessage } from "./slack-formatter";

interface SnsRecord {
  Sns?: { Message?: string };
}

interface SnsEvent {
  Records?: SnsRecord[];
}

export async function handler(event: SnsEvent): Promise<void> {
  const webhookUrl = process.env.SLACK_WEBHOOK_URL ?? "";
  if (!webhookUrl) {
    // Deploy wiring bug — the Lambda only exists when the secret was set.
    console.error("alert-router: SLACK_WEBHOOK_URL is empty; dropping event");
    return;
  }

  for (const record of event.Records ?? []) {
    const message = record.Sns?.Message;
    if (!message) continue;

    const body = formatAlarmMessage(message);
    try {
      const res = await fetch(webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body,
      });
      if (!res.ok) {
        console.error(
          `alert-router: Slack webhook returned ${res.status}: ${(await res.text()).slice(0, 200)}`,
        );
      } else {
        console.log("alert-router: delivered alarm notification to Slack");
      }
    } catch (err) {
      console.error(
        `alert-router: Slack webhook POST failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }
}
