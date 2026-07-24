#!/usr/bin/env node

import { appendFileSync, readFileSync } from "node:fs";

const fixturePath = process.env.AWS_FIXTURE_FILE;
const callLog = process.env.AWS_CALL_LOG;

if (!fixturePath || !callLog) {
  process.stderr.write("fake aws requires AWS_FIXTURE_FILE and AWS_CALL_LOG\n");
  process.exit(2);
}

const args = process.argv.slice(2);
appendFileSync(callLog, `${JSON.stringify({ args })}\n`);

const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
const key = args.slice(0, 2).join(" ");
const response = fixture.responses[key];

if (!response) {
  process.stderr.write(`unexpected fake aws command: ${key}\n`);
  process.exit(2);
}

if (response.stdout !== undefined) {
  process.stdout.write(
    typeof response.stdout === "string" ? response.stdout : JSON.stringify(response.stdout),
  );
}
process.exit(response.status ?? 0);
