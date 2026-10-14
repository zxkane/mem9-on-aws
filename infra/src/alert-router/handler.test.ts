import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
let handler: typeof import("./handler").handler;
vi.mock("@aws-sdk/client-ssm", async importOriginal => ({...await importOriginal<object>(), SSMClient: class { async send(command: {input:{Names:string[]}}) { return {Parameters:[{ARN:command.input.Names[0],Name:"/mem9-on-aws/prod/observability/slack-webhook-url",Type:"SecureString",Value:WEBHOOK_URL}]}; } }}));

const WEBHOOK_URL = "https://example.com/hooks/test-webhook-secret";
const ALARM_MARKER = "SensitiveAlarmFieldMarker";

const snsEvent = (message: string) => ({
  Records: [{ Sns: { Message: message } }],
});

function capturedOutput(...spies: ReturnType<typeof vi.spyOn>[]): string {
  return spies
    .flatMap((spy) => spy.mock.calls)
    .flat()
    .map(String)
    .join(" ");
}

describe("alert-router handler", () => {
  beforeEach(async () => {
    vi.resetModules();
    vi.stubEnv("STAGE", "prod");
    vi.stubEnv("AWS_REGION", "ap-northeast-1");
    vi.stubEnv("MEM9_SECRET_ACCOUNT_ID", "123456789012");
    vi.stubEnv("SLACK_WEBHOOK_URL_PARAMETER_ARN", "arn:aws:ssm:ap-northeast-1:123456789012:parameter/mem9-on-aws/prod/observability/slack-webhook-url");
    ({handler}=await import("./handler"));
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it.each([200, 201, 204, 299])(
    "TC-ALERT-006: resolves when Slack returns %i",
    async (status) => {
      const fetchMock = vi
        .spyOn(globalThis, "fetch")
        .mockResolvedValue(new Response(status === 204 ? null : "ok", { status }));
      const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

      await handler(
        snsEvent(JSON.stringify({ AlarmName: ALARM_MARKER, NewStateValue: "ALARM" })),
      );

      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toBe(WEBHOOK_URL);
      expect(init?.redirect).toBe("manual");
      expect(String(init?.body)).toContain(ALARM_MARKER);
      expect(capturedOutput(logSpy)).not.toContain(WEBHOOK_URL);
      expect(capturedOutput(logSpy)).not.toContain(ALARM_MARKER);
    },
  );

  it.each([300, 302, 399, 400, 404, 499, 500, 503, 599])(
    "TC-ALERT-007: rejects when Slack returns %i",
    async (status) => {
      vi.spyOn(globalThis, "fetch").mockResolvedValue(
        new Response("sensitive-response-body", { status }),
      );
      const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

      await expect(
        handler(snsEvent(JSON.stringify({ AlarmName: ALARM_MARKER }))),
      ).rejects.toThrow(`Slack webhook returned status ${status}`);

      const output = capturedOutput(errSpy);
      expect(output).not.toContain(WEBHOOK_URL);
      expect(output).not.toContain(ALARM_MARKER);
      expect(output).not.toContain("sensitive-response-body");
    },
  );

  it("TC-ALERT-008: rejects network errors without retaining sensitive details", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(
      new Error(`request to ${WEBHOOK_URL} failed for ${ALARM_MARKER}`),
    );
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const rejection = handler(snsEvent(JSON.stringify({ AlarmName: ALARM_MARKER })));
    await expect(rejection).rejects.toThrow("Slack webhook request failed");
    await rejection.catch((error: unknown) => {
      expect(String(error)).not.toContain(WEBHOOK_URL);
      expect(String(error)).not.toContain(ALARM_MARKER);
    });

    const output = capturedOutput(errSpy);
    expect(output).not.toContain(WEBHOOK_URL);
    expect(output).not.toContain(ALARM_MARKER);
  });

  it("TC-ALERT-005: rejects when the webhook reference is unset", async () => {
    delete process.env.SLACK_WEBHOOK_URL_PARAMETER_ARN;
    const fetchMock = vi
      .spyOn(globalThis, "fetch");
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    await expect(handler(snsEvent("{}"))).rejects.toThrow(
      "Slack webhook configuration is unavailable",
    );
    expect(fetchMock).not.toHaveBeenCalled();
    expect(capturedOutput(errSpy)).not.toContain(WEBHOOK_URL);
  });

  it("skips records without an SNS message", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch");
    await handler({ Records: [{}] });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
