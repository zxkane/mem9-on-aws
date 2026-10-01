export function productionArtifactAdmission(seed:string,sourceTag:string,image:string):string;
export function validateProductionBackendBinding(value:unknown,clusterArn?:string):{taskArn:string;taskDefinitionArn:string;containers:Array<{name:string;imageDigest:string}>};
export function bindProductionBackend(expected:unknown,observed:unknown,clusterArn:string,allowInitial?:boolean):ReturnType<typeof validateProductionBackendBinding>;
