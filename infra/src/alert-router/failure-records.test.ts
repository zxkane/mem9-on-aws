import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parseExecutionFailure, parseTransportFailure } from "./failure-records";

const fixture = (name: string) =>
  readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8");

describe("alert failure record parsers", () => {
  const transport = fixture("sns-transport-failure.json");
  const execution = fixture("lambda-execution-failure.json");

  it("TC-ALERT-011: accepts only the SNS transport failure shape", () => {
    expect(parseTransportFailure(transport)).toEqual({
      messageId: "transport-message-id",
      notificationType: "Notification",
      topicArn: "arn:aws:sns:ap-northeast-1:123456789012:mem9-on-aws-prod-alerts",
    });
    expect(() => parseExecutionFailure(transport)).toThrow(
      "not a Lambda execution failure record",
    );
  });

  it("TC-ALERT-012: accepts only the Lambda execution failure shape", () => {
    expect(parseExecutionFailure(execution)).toEqual({
      approximateInvokeCount: 3,
      condition: "RetriesExhausted",
      functionArn:
        "arn:aws:lambda:ap-northeast-1:123456789012:function:mem9-on-aws-prod-alert-router:$LATEST",
      requestId: "execution-request-id",
    });
    expect(() => parseTransportFailure(execution)).toThrow(
      "not an SNS transport failure record",
    );
  });
});
