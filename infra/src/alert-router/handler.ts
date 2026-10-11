/**
 * AlertRouter Lambda — SNS → Slack webhook bridge (mem9 observability).
 *
 * Subscribed directly to the production `Mem9AlertsTopic` SNS topic. POSTs
 * Block-Kit messages using the exact stage-scoped webhook SecureString.
 *
 * Direct SNS→Lambda (no delay queue): mem9's alarms carry everything needed
 * in the alarm payload itself — no CloudWatch Logs Insights enrichment, so
 * there is no log-indexing lag to outrun.
 *
 * Every network or non-2xx failure throws so Lambda can apply its bounded
 * asynchronous retry policy and route exhausted invocations to the execution
 * failure queue. Logs intentionally exclude webhook, response, and payload
 * values.
 */

import { formatAlarmMessage } from "./slack-formatter";
import { createRuntimeSecretReader } from "../../gateway/runtime-secrets.mjs";

const readSecret = createRuntimeSecretReader();

interface SnsRecord {
  Sns?: { Message?: string };
}

interface SnsEvent {
  Records?: SnsRecord[];
}

export async function handler(event: SnsEvent): Promise<void> {
  let webhookUrl: string;
  try { webhookUrl = await readSecret("webhook"); }
  catch {
    console.error("alert-router: webhook configuration is unavailable");
    throw new Error("Slack webhook configuration is unavailable");
  }

  for (const record of event.Records ?? []) {
    const message = record.Sns?.Message;
    if (!message) continue;

    const body = formatAlarmMessage(message);
    let response: Response;
    try {
      response = await fetch(webhookUrl, {
        method: "POST",
        redirect: "manual",
        headers: { "Content-Type": "application/json" },
        body,
      });
    } catch {
      console.error("alert-router: Slack webhook request failed");
      throw new Error("Slack webhook request failed");
    }

    if (!response.ok) {
      console.error(`alert-router: Slack webhook returned status ${response.status}`);
      throw new Error(`Slack webhook returned status ${response.status}`);
    }

    console.log("alert-router: delivered alarm notification to Slack");
  }
}
