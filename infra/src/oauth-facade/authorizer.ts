/**
 * Compliance-only allow-all shim. Real authentication remains the facade
 * handler's `/mcp` bearer check; discovery, `/oauth/*`, and `/register` must
 * remain anonymously reachable.
 */
export async function handler(): Promise<{ isAuthorized: true }> {
  return { isAuthorized: true };
}
