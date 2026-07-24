import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { handler } from "./handler";

const snsEvent = (message: string) => ({
  Records: [{ Sns: { Message: message } }],
});

describe("alert-router handler", () => {
  beforeEach(() => {
    process.env.SLACK_WEBHOOK_URL = "https://hooks.slack.example/T000/B000/xxx";
  });
  afterEach(() => {
    delete process.env.SLACK_WEBHOOK_URL;
    vi.restoreAllMocks();
  });

  it("POSTs the formatted alarm to the webhook", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response("ok", { status: 200 }));

    await handler(snsEvent(JSON.stringify({ AlarmName: "IngestAuthFailureAlarm", NewStateValue: "ALARM" })));

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://hooks.slack.example/T000/B000/xxx");
    expect(String(init?.body)).toContain("IngestAuthFailureAlarm");
  });

  it("does not throw on a non-2xx Slack response (no SNS redelivery flood)", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("no_service", { status: 404 }));
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    await expect(handler(snsEvent("{}"))).resolves.toBeUndefined();
    expect(errSpy).toHaveBeenCalled();
  });

  it("does not throw when fetch rejects (network failure)", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("ECONNREFUSED"));
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    await expect(handler(snsEvent("{}"))).resolves.toBeUndefined();
    expect(errSpy).toHaveBeenCalled();
  });

  it("drops events silently when SLACK_WEBHOOK_URL is unset (wiring bug guard)", async () => {
    delete process.env.SLACK_WEBHOOK_URL;
    const fetchMock = vi.spyOn(globalThis, "fetch");
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    await handler(snsEvent("{}"));
    expect(fetchMock).not.toHaveBeenCalled();
    expect(errSpy).toHaveBeenCalled();
  });

  it("skips records without an SNS message", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch");
    await handler({ Records: [{}] });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
