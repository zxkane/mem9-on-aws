/** Pure original observer topology bindings. No provisioning or authority. */
import {canonical,exact,hash,need,same} from './production-nonroot-engineering-json.mjs';
export const OBSERVER_TOPOLOGY_CASES=Object.freeze(['successful-handover','prefix-start-failure','sidecar-readiness-failure','post-liveness-regression','nonterminal-timeout']);
const hex=(s,n)=>typeof s==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(s);
export function observerDiscoveryName(scope){
 exact(scope,['stage','owner','operation','caseName']);
 need(/^pr-[1-9][0-9]*$/.test(scope.stage)&&hex(scope.owner,32)&&hex(scope.operation,32)&&OBSERVER_TOPOLOGY_CASES.includes(scope.caseName),'ObserverTopologyScope');
 // Hash the complete tuple, never truncated owner/operation prefixes.
 return 'mnemo-'+scope.caseName+'-'+hash(scope).slice(0,24);
}
export function inspectObserverDiscovery(value,scope){
 exact(value,['namespaceId','namespaceName','serviceId','serviceArn','serviceName']);
 const name=observerDiscoveryName({stage:scope.stage,owner:scope.owner,operation:scope.operation,caseName:scope.caseName});
 need(/^ns-[A-Za-z0-9]+$/.test(value.namespaceId)&&value.namespaceName==='mem9-'+scope.stage+'.local'&&/^srv-[A-Za-z0-9]+$/.test(value.serviceId),'ObserverDiscoveryNamespace');
 need(/^\d{12}$/.test(scope.account)&&/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(scope.region)&&value.serviceArn==='arn:aws:servicediscovery:'+scope.region+':'+scope.account+':service/'+value.serviceId&&value.serviceName===name,'ObserverDiscoveryIdentity');
 return value;
}
export function observerDiscoveryOrigin(value,scope){
 inspectObserverDiscovery(value,scope);return 'http://'+value.serviceName+'.'+value.namespaceName+':8080';
}
export function inspectObserverTopologyPlan(plan){
 need(plan.version===3&&plan.geometry.topology===1&&plan.geometry.control,'ObserverTopologyVersion');
 const services=new Set(),names=new Set(),namespace=new Set();
 for(const c of plan.cases){
  inspectObserverDiscovery(c.discovery,{...plan.scope,owner:plan.owner,operation:plan.operation,stage:c.stage,caseName:c.name});
  services.add(c.discovery.serviceArn);names.add(c.discovery.serviceName);namespace.add(c.discovery.namespaceId+'\n'+c.discovery.namespaceName);
 }
 need(services.size===5&&names.size===5&&namespace.size===1&&plan.scope.discoveryServiceArns.length===5&&new Set(plan.scope.discoveryServiceArns).size===5&&plan.scope.discoveryServiceArns.every(a=>services.has(a)),'ObserverTopologyCoverage');
}
export function verifyObserverDiscoveryService(response,binding){
 const service=response?.Service;
 need(service&&service.Id===binding.serviceId&&service.Arn===binding.serviceArn&&service.Name===binding.serviceName,'ObserverDiscoveryReadback');
 need((service.NamespaceId??service.DnsConfig?.NamespaceId)===binding.namespaceId&&(!service.NamespaceId||service.NamespaceId===binding.namespaceId)&&(!service.DnsConfig?.NamespaceId||service.DnsConfig.NamespaceId===binding.namespaceId),'ObserverDiscoveryReadbackNamespace');
 need(service.DnsConfig?.RoutingPolicy==='MULTIVALUE','ObserverDiscoveryRouting');
 same(service.DnsConfig.DnsRecords,[{Type:'A',TTL:10}],'ObserverDiscoveryDnsRecords');
}
export function observerInstancesEmpty(response){
 need(Array.isArray(response?.Instances)&&response.Instances.length<=1&&(response.NextToken===undefined||typeof response.NextToken==='string'&&response.NextToken.length>0&&response.NextToken.length<=4096),'ObserverDiscoveryInstances');
 return response.Instances.length===0&&response.NextToken===undefined;
}
export function verifyObserverEmptyInstances(response){need(observerInstancesEmpty(response),'ObserverDiscoveryNotEmpty');}
export function verifyObserverServiceRegistry(service,binding){
 same(service?.serviceRegistries,[{registryArn:binding.serviceArn}],'ObserverServiceRegistryChanged');
}
const metadata=['taskDefinitionArn','revision','status','requiresAttributes','compatibilities','registeredAt','registeredBy','deregisteredAt','deleteRequestedAt'];
export function observerWorkerCloneRegistration(original,{family,tags,privateOrigin}){
 canonical(original);canonical({family,tags,privateOrigin});
 need(typeof family==='string'&&/^[A-Za-z0-9_-]{1,255}$/.test(family)&&Array.isArray(tags),'ObserverCloneIdentity');
 const definition=structuredClone(Object.fromEntries(Object.entries(original).filter(([k])=>!metadata.includes(k))));
 need(definition.containerDefinitions?.length===1,'ObserverCloneContainers');
 const app=definition.containerDefinitions[0],env=app.environment;
 need(Array.isArray(env)&&env.filter(e=>e.name==='MEM9_BASE_URL').length===1,'ObserverCloneEndpoint');
 const url=new URL(privateOrigin);need(url.origin===privateOrigin&&url.protocol==='http:'&&url.port==='8080'&&!url.username&&!url.password,'ObserverCloneOrigin');
 definition.family=family;definition.tags=structuredClone(tags);
 app.environment=env.map(e=>e.name==='MEM9_BASE_URL'?{...e,value:privateOrigin}:e);
 return definition;
}
export function verifyObserverWorkerClone(original,expected,observed,selection){
 same(expected,observerWorkerCloneRegistration(original,selection),'ObserverCloneUnlistedChange');
 const actual=Object.fromEntries(Object.entries(observed.taskDefinition??{}).filter(([k])=>!metadata.includes(k)));
 if(observed.tags!==undefined)actual.tags=observed.tags;
 same(actual,expected,'ObserverCloneReadback');return actual;
}
