export const CONTROL_ZERO_FINDINGS_POLICY: Readonly<Record<string, unknown>>;
export const CONTROL_ZERO_FINDINGS_POLICY_HASH: string;
export const CONTROL_ZERO_FINDINGS_POLICY_SOURCE: string;
export function ecrScanTimestampMs(value: unknown): number;
export function assertNonrootControlScanPolicy(contract: unknown, sourceContext: unknown): Promise<Readonly<Record<string, unknown>>>;
export function normalizeNonrootControlScanPages(pages: unknown, image: unknown, options: {observedMs: number; now: number}): Readonly<{
  rawPages: readonly string[];
  findings: readonly Readonly<Record<string, unknown>>[];
  scanCompletedMs: number;
}>;
export function verifyNonrootControlScan(scan: unknown, options: {
  image: unknown;
  contract: unknown;
  sourceContext: unknown;
  resolveJson(reference: unknown): Promise<unknown>;
  resolveBytes(reference: unknown): Promise<Uint8Array>;
  now?: number;
}): Promise<Readonly<{policyHash: string; rawPagesHash: string; findingsHash: string; expiresMs: number}>>;
