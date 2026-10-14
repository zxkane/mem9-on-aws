export const RUNTIME_SECRET_CACHE_MS: number;
export type RuntimeSecretSlot = 'identity' | 'tenant' | 'transport' | 'oauth' | 'webhook';
export interface RuntimeSecretClient { send(command: any, options?: any): Promise<any> }
export function createRuntimeSecretReader(options?: {
  env?: Record<string, string | undefined>; ssm?: RuntimeSecretClient;
  secretsManager?: RuntimeSecretClient; now?: () => number;
}): (slot: RuntimeSecretSlot) => Promise<string>;
