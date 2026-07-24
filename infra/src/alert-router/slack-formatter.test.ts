import { describe, expect, it } from "vitest";
import { formatAlarmMessage } from "./slack-formatter";

const alarmPayload = (overrides: Record<string, unknown> = {}) =>
  JSON.stringify({
    AlarmName: "RecallZeroHitRateAlarm",
    NewStateValue: "ALARM",
    NewStateReason: "Threshold Crossed: 1 datapoint [0.85] was greater than 0.7.",
    StateChangeTime: "2026-07-24T03:00:00.000+0000",
    Region: "Asia Pacific (Tokyo)",
    AlarmDescription: "Recall zero-hit rate > 70% over 1h",
    ...overrides,
  });

describe("formatAlarmMessage", () => {
  it("formats an ALARM transition with rotating_light + all fields", () => {
    const body = JSON.parse(formatAlarmMessage(alarmPayload()));
    expect(body.text).toBe("ALARM: RecallZeroHitRateAlarm (ALARM)");
    const flat = JSON.stringify(body.blocks);
    expect(flat).toContain(":rotating_light:");
    expect(flat).toContain("RecallZeroHitRateAlarm");
    expect(flat).toContain("Threshold Crossed");
    expect(flat).toContain("Recall zero-hit rate");
    expect(flat).toContain("Tokyo");
  });

  it("formats an OK transition as RESOLVED with white_check_mark", () => {
    const body = JSON.parse(formatAlarmMessage(alarmPayload({ NewStateValue: "OK" })));
    expect(body.text).toContain("RESOLVED");
    expect(JSON.stringify(body.blocks)).toContain(":white_check_mark:");
  });

  it("falls back to a warning text for unparseable payloads", () => {
    const body = JSON.parse(formatAlarmMessage("not-json-at-all"));
    expect(body.text).toContain(":warning:");
    expect(body.text).toContain("not-json-at-all");
    expect(body.blocks).toBeUndefined();
  });

  it("tolerates missing optional fields", () => {
    const body = JSON.parse(formatAlarmMessage(JSON.stringify({ AlarmName: "X" })));
    expect(body.text).toContain("X");
    // No Region/Time fields when absent; no crash.
    expect(JSON.stringify(body.blocks)).not.toContain("*Time:*");
  });

  it("truncates very long reasons", () => {
    const long = "y".repeat(1000);
    const body = JSON.parse(formatAlarmMessage(alarmPayload({ NewStateReason: long })));
    const reason = JSON.stringify(body.blocks);
    expect(reason.length).toBeLessThan(1200);
  });
});
