import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";

import {
  extractSamplerEventFromDockerLogs,
  validateSamplerEvent,
} from "./validate-emf-event.mjs";

const TIMESTAMP_MS = 1_785_179_972_000;

function sampler(overrides = {}) {
  const record = {
    _aws: {
      Timestamp: TIMESTAMP_MS,
      CloudWatchMetrics: [
        {
          Namespace: "mem9-on-aws/DurableIngest",
          Dimensions: [["stage"]],
          Metrics: [{ Name: "SamplerHeartbeat", Unit: "Count" }],
        },
      ],
    },
    stage: "prod",
    SamplerHeartbeat: 1,
    ...overrides,
  };
  return JSON.stringify(record);
}

describe("validateSamplerEvent", () => {
  it.each(["", "\r", "\n", " ", " \r\n", "\n  "])(
    "TC-EMF-007: accepts an exact sampler with suffix %j",
    (suffix) => {
      expect(validateSamplerEvent(Buffer.from(sampler() + suffix))).toMatchObject({
        stage: "prod",
        SamplerHeartbeat: 1,
      });
    },
  );

  it.each([
    ["invalid JSON", '{"_aws":'],
    ["non-JSON prefix", `prefix ${sampler()}`],
    ["multiple documents", `${sampler()} ${sampler()}`],
  ])("TC-EMF-008/009: rejects %s", (_name, frame) => {
    expect(() => validateSamplerEvent(Buffer.from(frame))).toThrow();
  });

  it.each([
    ["second timestamp", { _aws: { ...JSON.parse(sampler())._aws, Timestamp: 1_785_179_972 } }],
    [
      "wrong namespace",
      {
        _aws: {
          ...JSON.parse(sampler())._aws,
          CloudWatchMetrics: [
            {
              Namespace: "Other",
              Dimensions: [["stage"]],
              Metrics: [{ Name: "SamplerHeartbeat", Unit: "Count" }],
            },
          ],
        },
      },
    ],
    [
      "unbounded dimension",
      {
        _aws: {
          ...JSON.parse(sampler())._aws,
          CloudWatchMetrics: [
            {
              Namespace: "mem9-on-aws/DurableIngest",
              Dimensions: [["stage", "tenant_id"]],
              Metrics: [{ Name: "SamplerHeartbeat", Unit: "Count" }],
            },
          ],
        },
      },
    ],
    [
      "wrong unit",
      {
        _aws: {
          ...JSON.parse(sampler())._aws,
          CloudWatchMetrics: [
            {
              Namespace: "mem9-on-aws/DurableIngest",
              Dimensions: [["stage"]],
              Metrics: [{ Name: "SamplerHeartbeat", Unit: "None" }],
            },
          ],
        },
      },
    ],
    ["wrong value", { SamplerHeartbeat: 0 }],
    ["content-bearing field", { memory: "forbidden" }],
  ])("TC-EMF-010: rejects %s", (_name, overrides) => {
    expect(() => validateSamplerEvent(Buffer.from(sampler(overrides)))).toThrow();
  });
});

describe("extractSamplerEventFromDockerLogs", () => {
  it("TC-EMF-006: selects one non-TTY LF-framed sampler event", () => {
    const event = extractSamplerEventFromDockerLogs(
      Buffer.from(`startup log\n${sampler()}\nworker ready\n`),
    );

    expect(event.subarray(-2).toString()).not.toBe("\r\n");
    expect(event.subarray(-1).toString()).toBe("\n");
    expect(validateSamplerEvent(event).SamplerHeartbeat).toBe(1);
  });

  it("rejects TTY CRLF framing for the selected non-TTY smoke path", () => {
    expect(() =>
      extractSamplerEventFromDockerLogs(Buffer.from(`${sampler()}\r\n`)),
    ).toThrow(/non-TTY/);
  });

  it("accepts multiple complete sampler events from a slow smoke run", () => {
    const event = extractSamplerEventFromDockerLogs(
      Buffer.from(`${sampler()}\nworker log\n${sampler()}\n`),
    );

    expect(validateSamplerEvent(event).SamplerHeartbeat).toBe(1);
  });

  it("validates every captured sampler event", () => {
    expect(() =>
      extractSamplerEventFromDockerLogs(
        Buffer.from(`${sampler()}\n{"SamplerHeartbeat":1}\n`),
      ),
    ).toThrow(/frame must start/);
  });

  it("rejects a stream without sampler events", () => {
    expect(() => extractSamplerEventFromDockerLogs(Buffer.from("startup\n"))).toThrow(
      /at least one/,
    );
  });
});
