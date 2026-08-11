import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const DEFAULT_CONFIG_PATH = fileURLToPath(
  new URL("../../sst.config.ts", import.meta.url),
);
const AWS_REGION_PATTERN = /^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$/u;
let importSequence = 0;
let configImportTail = Promise.resolve();

async function importWithConfigShim(configUrl) {
  let releaseImport;
  const precedingImport = configImportTail;
  configImportTail = new Promise((resolvePromise) => {
    releaseImport = resolvePromise;
  });
  await precedingImport;

  const priorConfig = globalThis.$config;
  globalThis.$config = (config) => config;
  try {
    return await import(configUrl.href);
  } finally {
    if (priorConfig === undefined) delete globalThis.$config;
    else globalThis.$config = priorConfig;
    releaseImport();
  }
}

/**
 * Resolve the application plane's region from the SST AWS provider.
 *
 * `$config` is an SST compile-time global. Supplying an identity shim lets Node
 * evaluate app() without running the resource-producing run() function.
 */
export async function resolveApplicationRegion({
  configPath = DEFAULT_CONFIG_PATH,
} = {}) {
  const configUrl = pathToFileURL(resolve(configPath));
  configUrl.searchParams.set("application-region-read", String(++importSequence));

  const configModule = await importWithConfigShim(configUrl);

  const app = configModule.default?.app;
  if (typeof app !== "function") {
    throw new Error("sst.config.ts must expose an app() function");
  }
  const region = app({ stage: "application-region-resolution" })?.providers
    ?.aws?.region;
  if (typeof region !== "string" || !AWS_REGION_PATTERN.test(region)) {
    throw new Error("sst.config.ts AWS provider region is missing or malformed");
  }
  return region;
}
