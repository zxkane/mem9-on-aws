import {observerDiscoveryName,observerWorkerCloneRegistration} from '../scripts/lib/production-nonroot-observer-topology.mjs';
declare const $util:typeof import('@pulumi/pulumi');
const CASES=['successful-handover','prefix-start-failure','sidecar-readiness-failure','post-liveness-regression','nonterminal-timeout'] as const;
export interface ObserverTopology {
  owner:string; operation:string; stage:string;
  namespaceId:Input<string>; namespaceName:string; namespaceArn:Input<string>;
  cases:Array<{caseName:string;discovery:{namespaceId:Input<string>;namespaceName:string;serviceId:Output<string>;serviceArn:Output<string>;serviceName:string};privateOrigin:string}>;
}
export function observerTopologyResources(namespace:{id:Input<string>;arn:Input<string>},raw=process.env.MEM9_PREVIEW_OBSERVER_TOPOLOGY):ObserverTopology|undefined {
  if(raw===undefined)return;
  if(!/^pr-[1-9][0-9]*$/.test($app.stage)||typeof raw!=='string'||Buffer.byteLength(raw)>1024)throw Error('ObserverTopologySelection');
  const value=JSON.parse(raw);
  if(!value||Object.keys(value).sort().join()!=='operation,owner'||!['owner','operation'].every(k=>typeof value[k]==='string'&&/^[a-f0-9]{32}$/.test(value[k])))throw Error('ObserverTopologySelection');
  const stage=$app.stage,namespaceName=`mem9-${stage}.local`,{owner,operation}=value;
  const awsAny=aws as any;
  const tags={Project:'mem9-on-aws',Stage:stage,ManagedBy:'sst','observer-owner':owner,'observer-operation':operation};
  const cases=CASES.map((caseName,index)=>{
    const name=observerDiscoveryName({stage,owner,operation,caseName});
    const service=new awsAny.servicediscovery.Service(`ObserverDiscovery${index+1}`,{
      name,namespaceId:namespace.id,dnsConfig:{namespaceId:namespace.id,routingPolicy:'MULTIVALUE',dnsRecords:[{type:'A',ttl:10}]},tags:{...tags,'observer-case':caseName},
    });
    return {caseName,discovery:{namespaceId:namespace.id,namespaceName,serviceId:service.id,serviceArn:service.arn,serviceName:name},privateOrigin:`http://${name}.${namespaceName}:8080`};
  });
  return {owner,operation,stage,namespaceId:namespace.id,namespaceName,namespaceArn:namespace.arn,cases};
}
/** Called only AFTER both original nonroot task transforms. Clone all input
 * fields; family, tags and the existing base URL are the only differences. */
export function observerWorkerTemplate(kind:'planner'|'executor',args:Record<string,any>,topology:ObserverTopology){
  const selected=topology.cases.find(c=>c.caseName==='successful-handover')!;
  const family=`mem9-observer-template-${topology.owner}-${topology.operation}-${kind}`;
  const tags=$util.all([args.tags??{}]).apply(([original])=>({...original,'observer-owner':topology.owner,'observer-operation':topology.operation,'observer-case':'successful-handover'}));
  const containerDefinitions=$util.all([args.containerDefinitions]).apply(([raw])=>{
    const original={containerDefinitions:JSON.parse(raw)};
    return JSON.stringify(observerWorkerCloneRegistration(original,{family,tags:[],privateOrigin:selected.privateOrigin}).containerDefinitions);
  });
  return new aws.ecs.TaskDefinition(`Observer${kind==='planner'?'Planner':'Executor'}Template`,{...args,family,tags,containerDefinitions});
}
export function publishObserverTopology(topology:ObserverTopology,generation:Input<string>,workers:Record<string,Input<string>>){
  if(Object.keys(workers).sort().join()!=='executor,planner')throw Error('ObserverTopologyWorkerCoverage');
  return new aws.ssm.Parameter('ObserverTopology',{
    name:`/mem9-on-aws/${topology.stage}/consolidation-preview/observer-topology`,type:'String',
    value:$jsonStringify({version:1,kind:'observer-topology-stack-output',authority:false,owner:topology.owner,operation:topology.operation,stage:topology.stage,generation,
      namespace:{id:topology.namespaceId,arn:topology.namespaceArn,name:topology.namespaceName},cases:topology.cases,workerTaskDefinitionArns:workers}).apply(raw=>{if(Buffer.byteLength(raw)>4096)throw Error("ObserverTopologyMetadataBound");return raw;}),
    tags:{Project:'mem9-on-aws',Stage:topology.stage,ManagedBy:'sst','observer-owner':topology.owner,'observer-operation':topology.operation},
  });
}
