export const MAINTENANCE_NODE_ENTRYPOINT: readonly string[];
export function hardenMaintenanceContainer<T extends Record<string,unknown>>(container:T):T;
export function assertHardenedMaintenanceContainer(container:unknown):void;
export function assertMaintenanceProcess(status:string,uid:number|undefined,gid:number|undefined):void;
export function requireMaintenanceProcess():Promise<void>;
