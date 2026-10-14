import type {LocalReadCharge} from './production-nonroot-budget-transport.mjs';
export {CONTROL_ZERO_FINDINGS_POLICY,CONTROL_ZERO_FINDINGS_POLICY_HASH,CONTROL_ZERO_FINDINGS_POLICY_SOURCE,verifyNonrootControlScan} from './production-nonroot-control-scan-policy.mjs';

/** Uses the existing paid reader. A nonterminal scan page holds without
 * requesting a next page that is absent from the funded CONTROL profile.
 * scan.rawPages resolves to complete decoded response JSON strings so ECR
 * fractional epoch seconds remain intact in the integer-only proof archive. */
export function collectNonrootControlScan(input: {
  contract: unknown;
  sourceContext: unknown;
  graph: unknown;
  archive: unknown;
  budgetedReads: {
    readJson(service: 'ecr', action: 'DescribeImageScanFindings', input: Record<string, unknown>): Promise<Record<string, unknown>>;
    reserveLocal(charge: LocalReadCharge): unknown;
  };
  maximumExpiresMs: number;
}, options?: {clock?: () => number; signal?: AbortSignal}): Promise<Readonly<{
  scan: Readonly<Record<string, unknown>>;
  archive: unknown;
  archiveAdditions: readonly (Readonly<Record<string, unknown>> & {bytes: Uint8Array})[];
}>>;
