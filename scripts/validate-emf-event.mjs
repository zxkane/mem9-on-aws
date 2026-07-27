#!/usr/bin/env node

import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const NAMESPACE = "mem9-on-aws/DurableIngest";
const METRIC = "SamplerHeartbeat";

function fail(message) {
  throw new Error(`invalid EMF sampler event: ${message}`);
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  const keys = Object.keys(value);
  if (
    keys.length !== expected.length ||
    keys.some((key, index) => key !== expected[index])
  ) {
    fail(`${label} keys must be ${expected.join(",")}`);
  }
}

export function validateSamplerEvent(input) {
  const bytes = Buffer.isBuffer(input) ? input : Buffer.from(input);
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail("frame is not valid UTF-8");
  }
  if (text.includes("\t")) fail("only CR, LF, and space suffixes are allowed");
  if (!text.startsWith('{"_aws":')) fail('frame must start with {"_aws":');

  const document = text.replace(/[ \r\n]+$/, "");
  let record;
  try {
    record = JSON.parse(document);
  } catch {
    fail("frame must contain exactly one valid JSON document");
  }

  exactKeys(record, ["_aws", "stage", METRIC], "root");
  exactKeys(record._aws, ["Timestamp", "CloudWatchMetrics"], "_aws");
  if (
    !Number.isSafeInteger(record._aws.Timestamp) ||
    record._aws.Timestamp < 1_000_000_000_000 ||
    record._aws.Timestamp >= 10_000_000_000_000
  ) {
    fail("_aws.Timestamp must be Unix epoch milliseconds");
  }
  if (record.stage !== "prod") fail("stage must be prod");
  if (record[METRIC] !== 1) fail(`${METRIC} must be 1`);

  const directives = record._aws.CloudWatchMetrics;
  if (!Array.isArray(directives) || directives.length !== 1) {
    fail("CloudWatchMetrics must contain one directive");
  }
  const directive = directives[0];
  exactKeys(directive, ["Namespace", "Dimensions", "Metrics"], "metric directive");
  if (directive.Namespace !== NAMESPACE) fail(`namespace must be ${NAMESPACE}`);
  if (
    !Array.isArray(directive.Dimensions) ||
    directive.Dimensions.length !== 1 ||
    !Array.isArray(directive.Dimensions[0]) ||
    directive.Dimensions[0].length !== 1 ||
    directive.Dimensions[0][0] !== "stage"
  ) {
    fail("dimensions must be exactly [[stage]]");
  }
  if (!Array.isArray(directive.Metrics) || directive.Metrics.length !== 1) {
    fail("metric directive must contain one metric");
  }
  const metric = directive.Metrics[0];
  exactKeys(metric, ["Name", "Unit"], "metric");
  if (metric.Name !== METRIC || metric.Unit !== "Count") {
    fail(`${METRIC} must use Count`);
  }

  return record;
}

export function extractSamplerEventFromDockerLogs(input) {
  const bytes = Buffer.isBuffer(input) ? input : Buffer.from(input);
  const events = [];
  let start = 0;
  for (let index = 0; index < bytes.length; index += 1) {
    if (bytes[index] !== 0x0a) continue;
    const event = bytes.subarray(start, index + 1);
    if (event.includes(Buffer.from(`"${METRIC}"`))) events.push(event);
    start = index + 1;
  }
  if (start < bytes.length) {
    const event = bytes.subarray(start);
    if (event.includes(Buffer.from(`"${METRIC}"`))) events.push(event);
  }
  if (events.length !== 1) {
    fail(`expected exactly one ${METRIC} event, found ${events.length}`);
  }

  const event = events[0];
  if (event.at(-1) !== 0x0a || event.at(-2) === 0x0d) {
    fail("non-TTY Docker output must end with LF and no preceding CR");
  }
  return event;
}

function main() {
  const dockerStream = process.argv.slice(2).includes("--docker-stream");
  const input = readFileSync(0);
  const event = dockerStream ? extractSamplerEventFromDockerLogs(input) : input;
  const record = validateSamplerEvent(event);
  process.stdout.write(
    `validated ${METRIC} stage=${record.stage} bytes=${event.length}${
      dockerStream ? " framing=LF" : ""
    }\n`,
  );
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
