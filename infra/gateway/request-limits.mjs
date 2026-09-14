// Server responses must complete before the proxy and Lambda deadlines.
export const RECALL_TIMEOUT_MS = 20_000;
export const RECALL_RESPONSE_RESERVE_MS = 2_000;
export const PROXY_TIMEOUT_MS = 25_000;
export const LAMBDA_RESPONSE_RESERVE_MS = 1_000;
