export const SERVICE_CONTAINERS: readonly string[];
export function serviceNonrootHash(value: unknown): string;
export function hardenServiceContainer<T extends Record<string, unknown>>(value: T): T;
export function hardenServiceRegistration<T extends {containerDefinitions: Record<string, unknown>[]}>(value: T): T;
export function registrationInput(value: unknown): Record<string, unknown>;
