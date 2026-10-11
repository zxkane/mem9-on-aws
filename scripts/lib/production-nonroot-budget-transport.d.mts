export interface LocalReadCharge {
  ecrRequests: number;
  logicalBytes: number;
  httpBodyBytes: number;
  uncompressedBytes: number;
  processedEntries: number;
}
export interface NonrootReadReservation {
  caps: {requestBytes: number; responseBytes: number; overshootBytes?: number};
  finalGuard(): void;
  charge(bytes: number): void;
  complete(response: Record<string, unknown>, responseHash: string): Promise<unknown>;
  unknown(): Promise<unknown>;
}
export interface NonrootMetadataReads {
  beforeRead(action: string, request: Record<string, unknown>): Promise<NonrootReadReservation>;
  reserveLocal(charge: LocalReadCharge): unknown;
  finish(): Promise<unknown>;
}
export interface NonrootReadClient {
  send(command: unknown, options?: {abortSignal?: AbortSignal}): Promise<Record<string, unknown>>;
}
export function assertNonrootMetadataReads(value: unknown): NonrootMetadataReads;
export function createNonrootBudgetedReads(options: {
  region: string;
  env: Record<string, string | undefined>;
  metadataReads: NonrootMetadataReads;
  requestHandler?: {handle(request: unknown, options?: unknown): Promise<unknown>; destroy(): void};
}): {
  clients: Readonly<Record<'sts'|'ssm'|'s3'|'ecs'|'iam', NonrootReadClient>>;
  readEcr(operation: 'batch-get-image'|'describe-image-scan-findings', input: {repositoryName: string; imageDigest: string; nextToken?: string}, scope: {account: string}): Promise<Record<string, unknown>>;
  readJson(service: 'ecr'|'kms', action: string, input: Record<string, unknown>): Promise<Record<string, unknown>>;
  readBlob(input: {repositoryName: string; layerDigest: string}, options: {account: string; size: number; consume(stream: AsyncIterable<Uint8Array>): Promise<unknown>; signal?: AbortSignal}): Promise<{repositoryName: string; layerDigest: string; size: number}>;
  controlMetadata(scope: {account: string; region: string}): {artifact(route: Record<string, unknown>): Promise<unknown>; key(route: Record<string, unknown>): Promise<string>};
  reserveLocal(charge: LocalReadCharge): unknown;
  close(): void;
};
