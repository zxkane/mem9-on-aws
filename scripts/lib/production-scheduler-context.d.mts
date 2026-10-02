export const SCHEDULER_CONTEXT_ENVIRONMENT:ReadonlyArray<Readonly<{name:string;value:string}>>;
export function productionRecurringEnvironment<T>(generation:T,admission:T):Array<{name:string;value:T|string}>;
export function readProductionSchedulerContext(environment:unknown,expected:{scheduleArn:string;generation:string;admission:string}):{
  scheduleArn:string;scheduledMs:number;executionId:string;attempt:1;
};
