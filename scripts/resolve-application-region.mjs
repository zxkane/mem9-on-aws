#!/usr/bin/env node

import { resolveApplicationRegion } from "./lib/application-region.mjs";

let configPath;
for (let index = 2; index < process.argv.length; index += 1) {
  const argument = process.argv[index];
  if (argument === "--config" && process.argv[index + 1]) {
    configPath = process.argv[++index];
    continue;
  }
  console.error(`Unknown or incomplete option: ${argument}`);
  process.exit(2);
}

try {
  console.log(await resolveApplicationRegion({ configPath }));
} catch (error) {
  console.error(error?.message ?? error);
  process.exit(1);
}
