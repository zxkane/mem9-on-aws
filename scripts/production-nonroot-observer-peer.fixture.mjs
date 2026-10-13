import {OBSERVER_RUNTIME_SLOTS,observerZeroCounter,observerBytesHash as sha} from './lib/production-nonroot-observer-delivery.mjs';
import {describeObserverProviderFinalization} from './lib/production-nonroot-observer-finalization-work.mjs';
import {observerDiscoveryName} from './lib/production-nonroot-observer-topology.mjs';
import {deriveObserverPeerInventory} from './lib/production-nonroot-observer-peer-inventory.mjs';
export function completeDelivery(){
 const account='123456789012',region='ap-northeast-1',stage='pr-7',owner=sha('owner').slice(0,32),operation=sha('operation').slice(0,32),caseName='post-liveness-regression';
 const registry=JSON.stringify({issuer:'https://identity.example.com/issuer',audience:'original-read-audience',human:Array.from({length:16},(_,i)=>sha('registered-human-'+i)),m2m:Array.from({length:16},(_,i)=>sha('registered-read-machine-'+i))});
 const credentialBindings=Object.fromEntries(['clientId','clientSecret','tenantKey','identitySigningKeys','transportSigningKeys'].map(name=>{
  const store=['tenantKey','identitySigningKeys'].includes(name)?'secretsmanager':'ssm';
  return [name,{store,arn:`arn:aws:${store}:${region}:${account}:`+(store==='ssm'?`parameter/mem9-on-aws/${stage}/original-observer-registered-client/${name}`:`secret:mem9-on-aws-${stage}-${name}-original-protected-runtime-secret-AbCd12`),region,version:store==='ssm'?127:sha(name).slice(0,32),sha256:sha('original-value-commitment-'+name),bytesLength:name==='clientId'?48:4096,endpoint:`https://${store}.${region}.amazonaws.com`}];
 }));
 for(const [name,b]of Object.entries(credentialBindings)){b.valueType=b.store==='ssm'?(name==='clientId'?'String':'SecureString'):'SecretString';b.kms=b.valueType==='String'?null:{keyArn:'arn:aws:kms:'+region+':'+account+':key/00000000-0000-4000-8000-000000000001',viaService:b.store+'.'+region+'.amazonaws.com',contextKey:b.store==='ssm'?'PARAMETER_ARN':'SecretARN',contextValue:b.arn};}
 const slots=OBSERVER_RUNTIME_SLOTS.map(id=>{const kind=['source/registry','credential-adapter','context','output','runtime-finalization'].includes(id)?'local':'http',requestBytes=kind==='http'?65536:0,responseBytes=kind==='http'?1048576:0;return {id,kind,requestBytes,responseBytes,counter:{...observerZeroCounter(),logicalBytes:16777216,httpBodyBytes:requestBytes+responseBytes}};});
 slots.find(s=>s.id==='runtime-finalization').counter.logicalBytes=describeObserverProviderFinalization({allocation:{slots}}).logicalBytes;
 const charge=observerZeroCounter();for(const s of slots)for(const k of Object.keys(charge))charge[k]+=s.counter[k];
 return {version:1,kind:'fixed-observer-control-delivery',owner,operation,stage,caseName,sampleIndex:1023,captureId:sha('capture').slice(0,32),sourceTree:sha('source').slice(0,40),manifestSha256:sha('guard-manifest'),inputHash:sha('bound-input'),account,region,clusterArn:`arn:aws:ecs:${region}:${account}:cluster/mem9-on-aws-${stage}-Cluster-original-bound-network-LongId01`,taskDefinitionArn:`arn:aws:ecs:${region}:${account}:task-definition/mem9-on-aws-${stage}-fixed-original-control-route-purpose:127`,taskDefinitionHash:sha('definition'),taskRoleArn:`arn:aws:iam::${account}:role/mem9-on-aws/${stage}/original-observer-control-registered-read-runtime`,containerName:'consolidation-worker',controlImage:{rootDigest:'sha256:'+sha('root'),arm64Digest:'sha256:'+sha('arm'),configDigest:'sha256:'+sha('config')},startedMs:1900000000000,deadlineMs:1900000100000,allocation:{id:caseName+'/control-runtime/1023',quoteHash:sha('quote'),charge,slots},route:{privateOrigin:`http://mnemo.mem9-${stage}.local:8080`,gatewayUrl:'https://original-bound-gateway.gateway.example.com/mcp',jobId:'00000000-0000-4000-8000-000000000001',identityHash:sha('principal'),issuer:'https://identity.example.com/issuer',audience:'original-read-audience',transportIssuer:'gateway-target',tokenEndpoint:'https://identity.example.com/oauth2/token',jwksUri:'https://identity.example.com/issuer/.well-known/jwks.json',registryHash:sha(registry)},credentialBindings,registry};
}
const expectedIp="10.0.0.11";
export function peerInputs(delivery){
 const geometry={listPages:2,taskLimit:20,rawPageBytes:1048576},clusterArn=delivery.clusterArn,serviceName='synthetic-service',serviceArn=`arn:aws:ecs:${delivery.region}:${delivery.account}:service/${clusterArn.split('/').at(-1)}/${serviceName}`;
 const casePlan={clusterArn,serviceName,serviceArn,startedMs:delivery.startedMs,deadlineMs:delivery.deadlineMs},prefix=delivery.caseName+'/sample/'+delivery.sampleIndex;
 const task={taskArn:`arn:aws:ecs:${delivery.region}:${delivery.account}:task/${clusterArn.split('/').at(-1)}/${'b'.repeat(32)}`,taskDefinitionArn:delivery.taskDefinitionArn,clusterArn,group:'service:'+serviceName,lastStatus:'RUNNING',containers:[{name:'mnemo-server',networkInterfaces:[{privateIpv4Address:expectedIp}]}]};
 const values=[['/service','DescribeServices',{cluster:clusterArn,services:[serviceArn]},{services:[{serviceArn,clusterArn,serviceName}],failures:[]}],['/list/RUNNING/0','ListTasks',{cluster:clusterArn,serviceName,desiredStatus:'RUNNING',maxResults:100},{taskArns:[task.taskArn]}],['/list/STOPPED/0','ListTasks',{cluster:clusterArn,serviceName,desiredStatus:'STOPPED',maxResults:100},{taskArns:[]}],['/tasks/0','DescribeTasks',{cluster:clusterArn,tasks:[task.taskArn]},{tasks:[task],failures:[]}]];
 const originals=values.map(([id,action,input,value],i)=>({id:prefix+id,action,input,value,responseHash:sha(JSON.stringify(value)),responseBytes:Buffer.byteLength(JSON.stringify(value)),startedMs:delivery.startedMs+100+i*2,completedMs:delivery.startedMs+101+i*2}));
 return {delivery,geometry,casePlan,originals};
}
function peerFixture(delivery){return deriveObserverPeerInventory(peerInputs(delivery));}

export function peerDelivery(version=3){
 const d=completeDelivery(),now=Date.now();d.startedMs=now-1000;d.deadlineMs=now+120000;
 d.version=version;d.discovery={namespaceId:'ns-synthetic',namespaceName:'mem9-'+d.stage+'.local',serviceId:'srv-synthetic',serviceArn:`arn:aws:servicediscovery:${d.region}:${d.account}:service/srv-synthetic`,serviceName:observerDiscoveryName({stage:d.stage,owner:d.owner,operation:d.operation,caseName:d.caseName})};
 d.route.privateOrigin='http://'+d.discovery.serviceName+'.'+d.discovery.namespaceName+':8080';
 if(version===3)d.peerInventory=peerFixture(d);return d;
}
