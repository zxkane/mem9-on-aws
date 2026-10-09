import {describe,it,expect} from 'vitest';
import {deflateRawSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {dataLaunchPolicy,controlLaunchPolicy,validateNonrootEnvironment,resolveCarrierRunTaskRequest,verifyCarrierRunTaskBinding,assertCarrierRunTaskDispatch,verifyTargetIdentityRecheck} from './lib/production-nonroot-launch.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';

const h=c=>c.repeat(64),d=c=>'sha256:'+h(c),account='123456789012',region='ap-northeast-1';
const img={rootDigest:d('a'),arm64Digest:d('b'),configDigest:d('c')};
const image={account,region,repositoryName:'mem9-on-aws/preview/bootstrap',...img};
const ref={bytesHash:h('a'),canonicalHash:h('b'),bytesLength:2};
const cluster='arn:aws:ecs:'+region+':'+account+':cluster/mem9-on-aws-prod-example';
const td='arn:aws:ecs:'+region+':'+account+':task-definition/mem9-on-aws-prod-example-ControlMem9Bootstrap:7';
const role='arn:aws:iam::'+account+':role/mem9-on-aws-prod-control';
const owner='a'.repeat(32),id='b'.repeat(32),now=1800000000000;
const envInput=()=>({imageEnvironment:['PATH=/usr/local/bin:/usr/bin:/bin'],taskEnvironment:[],secrets:[],overrides:{},files:[],expectedCa:[]});
function fixture(){
 const body=Buffer.from(JSON.stringify({invocation:id}));
 const overrides={containerOverrides:[{name:'ControlMem9Bootstrap',environment:[{name:'MEM9_SUPERSESSION_ROOT_INPUT',value:deflateRawSync(body).toString('base64')},{name:'MEM9_SUPERSESSION_ROOT_HASH',value:createHash('sha256').update(body).digest('hex')},{name:'MEM9_SUPERSESSION_ROOT_CODE_HASH',value:h('c')}]}]};
 const gate={version:1,kind:'prelaunch-environment-gate',image:img,registrationBodyHash:h('b'),overrideHash:hash(overrides),imageEnvironment:ref,taskEnvironment:ref,secretNamesAndReferences:ref,overrideEnvironment:ref,caBindings:[],forbiddenNamesHash:h('c'),loaderFileEvidence:ref,checkedMs:now-20,result:'pass'};
 const contract={version:1,kind:'carrier-runtask-contract',cluster,count:1,launchType:'FARGATE',platformVersion:'1.4.0',networkConfiguration:{awsvpcConfiguration:{subnets:['subnet-0123456789abcdef0','subnet-1123456789abcdef0'],securityGroups:['sg-0123456789abcdef0'],assignPublicIp:'DISABLED'}},enableExecuteCommand:false,enableECSManagedTags:false,propagateTags:'NONE',tags:[{key:'mem9-supersession-owner',value:owner}],taskDefinitionSource:'exact-carrier-registration-readback',clientTokenSource:'permit-invocation',startedByRule:'root-prefix-invocation-first-29',overridesSource:'exact-carrier-overrides'};
 const plan={version:1,kind:'standalone-preaudit-launch-plan',owner,account,region,carrierBuildHash:h('d'),carrierImage:image,legacyClosureProofHash:h('a'),guardImportsHash:h('b'),environmentPolicyHash:h('c'),existingControlBinding:ref,registrationBody:ref,containerName:'ControlMem9Bootstrap',entryPoint:['/bin/setpriv','--no-new-privs','--','/usr/local/bin/node','/carrier/guard-first.mjs','audit-original-root'],command:[],taskRoleArn:role,executionRoleArn:role+'-execution',network:ref,secretNamesAndReferences:ref,logDestination:ref,environmentGate:gate,maxRuntimeMs:140000,cleanupReserveMs:30000,runTaskContract:contract,carrierPlatform:{version:1,kind:'actual-runtime-platform',taskArn:'arn:aws:ecs:'+region+':'+account+':task/mem9-on-aws-pr-1-test/'+'c'.repeat(32),taskDefinitionArn:'arn:aws:ecs:'+region+':'+account+':task-definition/mem9-on-aws-pr-1-test-audit:1',launchType:'FARGATE',platformVersion:'1.4.0',platformFamily:'Linux',cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX',rawTask:ref,rawDefinition:ref,independentHealthProbe:ref,observedMs:now-1000}};
 const readback={version:1,kind:'exact-carrier-registration-readback',taskDefinitionArn:td,carrierImage:image,requestedRegistrationBodyHash:ref.canonicalHash,rawDefinition:ref,rawDefinitionHash:ref.canonicalHash,observedMs:now-30};
 const presence={version:1,kind:'same-carrier-registry-presence',carrierBuildHash:plan.carrierBuildHash,image,rootManifest:{sha256:h('a'),bytesLength:1},arm64Manifest:{sha256:h('b'),bytesLength:1},config:{sha256:h('c'),bytesLength:1},blobAvailability:ref,registryObservation:ref,observedMs:now-10,expiresMs:now+100000};
 const permissions={version:1,kind:'existing-permissions-preflight',account,applicationRegion:region,iamRegion:'us-west-2',...Object.fromEntries(['caller','actorBindings','identityPolicies','boundaries','trustAndResourcePolicies','organizationAndEndpointControls','actionMatrix','positiveNegativeTests','analyzerScannerReview'].map(k=>[k,ref])),carrierRunTaskContractHash:hash(contract),observedMs:now-100,result:'pass'};
 const invocation={invocation:id,runOverrides:overrides};
 const request=resolveCarrierRunTaskRequest(plan,readback,invocation);
 const expected={planHash:hash(plan),readbackHash:hash(readback),environmentGateHash:hash(gate),carrierPresenceHash:hash(presence),permissionsHash:hash(permissions),carrierBuildHash:plan.carrierBuildHash,requestHash:hash(request),callerArn:'arn:aws:sts::'+account+':assumed-role/reviewed-operator/session',deadlineMs:now+900000,reviewExpiresMs:now+1000000};
 const binding={version:1,kind:'permit-bound-carrier-runtask',request,requestHash:hash(request),launchPlanHash:hash(plan),runTaskContractHash:hash(contract),registrationReadbackHash:hash(readback),environmentGateHash:hash(gate),carrierPresenceHash:hash(presence),authorization:{permissionsDossierHash:hash(permissions),requestHash:hash(request),callerArn:expected.callerArn,action:'ecs:RunTask',taskDefinitionArn:td,clusterArn:cluster,taskRoleArn:role,executionRoleArn:role+'-execution',decision:'allowed'}};
 return {plan,readback,invocation,request,binding,context:{plan,readback,environmentGate:gate,carrierPresence:presence,permissions,invocation,expected,now}};
}

describe('exact nonroot launch transforms',()=>{
 it.each(['mnemo-server','qwen3-embed','llm-proxy','planner','executor'])('hardens %s preserving unrelated fields and caller input',component=>{
  const worker=['planner','executor'].includes(component);const name=worker?'Mem9Consolidation'+(component==='planner'?'Planner':'Executor'):component;
  const original={name,image:'example.com/image@'+d('a'),linuxParameters:{initProcessEnabled:true},environment:[{name:'UNCHANGED',value:'yes'}],...(worker?{entryPoint:['node'],command:['/app/scripts/consolidation-worker.mjs']}:{})};const saved=structuredClone(original);
  const got=dataLaunchPolicy(component,original);expect(original).toEqual(saved);expect(got.user).toBe('1000:1000');expect(got.linuxParameters).toEqual({initProcessEnabled:true,capabilities:{drop:['ALL']}});expect(got.entryPoint.slice(0,3)).toEqual([component==='mnemo-server'?'/bin/setpriv':'/usr/bin/setpriv','--no-new-privs','--']);expect(got.environment).toEqual(original.environment);expect(dataLaunchPolicy(component,got)).toEqual(got);
 });
 it('wraps each existing health launch without altering timing or application argv',()=>{
  const before={name:'mnemo-server',healthCheck:{command:['CMD-SHELL','wget -q -O /dev/null http://localhost:8080/healthz || exit 1'],interval:30,startPeriod:300}};
  const got=dataLaunchPolicy('mnemo-server',before);expect(got.healthCheck).toEqual({...before.healthCheck,command:['CMD','/bin/setpriv','--no-new-privs','--','/bin/sh','-c',before.healthCheck.command[1]]});
  const q=dataLaunchPolicy('qwen3-embed',{healthCheck:{command:['CMD','node','/app/healthcheck.mjs','http://localhost:8081/health'],timeout:5}});expect(q.healthCheck.command).toEqual(['CMD','/usr/bin/setpriv','--no-new-privs','--','node','/app/healthcheck.mjs','http://localhost:8081/health']);
 });
 it('pins CONTROL/carrier Node absolutely and preserves existing init settings',()=>{
  const c=controlLaunchPolicy('audit-original-root',{linuxParameters:{initProcessEnabled:true},environment:[{name:'PATH',value:'/shadow'}]});expect(c.entryPoint).toEqual(['/bin/setpriv','--no-new-privs','--','/usr/local/bin/node','/carrier/guard-first.mjs','audit-original-root']);expect(c.linuxParameters.initProcessEnabled).toBe(true);expect(c.command).toEqual([]);
 });
 it('requires independently supplied image-specific named-node mapping for Mem9PostFixture',()=>{
  const original={name:'Mem9PostFixture',user:'node',image:'example.com/bootstrap@'+d('a'),readonlyRootFilesystem:true};
  const namedUserIdentity={image:original.image,username:'node',uid:1000,gid:1000,passwdSha256:h('b')};
  expect(()=>controlLaunchPolicy('post-runtime-fixture',original)).toThrow();
  const got=controlLaunchPolicy('post-runtime-fixture',original,{namedUserIdentity});expect(got.user).toBe('1000:1000');expect(got.readonlyRootFilesystem).toBe(true);
  for(const change of [p=>p.uid=0,p=>p.gid=0,p=>p.image='example.com/other@'+d('b'),p=>p.passwdSha256='missing']){const p=structuredClone(namedUserIdentity);change(p);expect(()=>controlLaunchPolicy('post-runtime-fixture',original,{namedUserIdentity:p})).toThrow();}
 });
 it('allows only the five reviewed fixture purposes on the existing isolated post-runtime container',()=>{
  for(const suffix of ['pause','setup','verify-planned','verify-executed','verify-repeated']){
   const c=controlLaunchPolicy('preview-fixture-'+suffix,{name:'Mem9PostFixture',user:'1000:1000'});
   expect(c.entryPoint.at(-1)).toBe('preview-fixture-'+suffix);expect(c.command).toEqual([]);
  }
  for(const purpose of ['bootstrap-admin-probe','bootstrap-runtime-bootstrap','consolidation-control'])
   expect(()=>controlLaunchPolicy(purpose,{name:'Mem9PostFixture',user:'1000:1000'})).toThrow();
 });
 it.each([{entryPoint:['sh','-c','arbitrary']},{command:['different']},{privileged:true},{linuxParameters:{capabilities:{add:['SYS_PTRACE']}}},{user:'1000:0'}])('rejects unreviewed original launch changes',original=>{expect(()=>dataLaunchPolicy('llm-proxy',original)).toThrow();});
 it('rejects unknown purpose, altered health and a replay command on the planner',()=>{expect(()=>controlLaunchPolicy('arbitrary')).toThrow();expect(()=>dataLaunchPolicy('mnemo-server',{healthCheck:{command:['CMD-SHELL','echo hello']}})).toThrow();expect(()=>dataLaunchPolicy('planner',{entryPoint:['node'],command:['/app/scripts/consolidation-canary-replay.mjs']})).toThrow();});
});
describe('prelaunch environment rejection',()=>{
 it('accepts an inert environment without producing approval',()=>{expect(validateNonrootEnvironment(envInput())).not.toHaveProperty('authorized');});
 for(const name of ['NODE_OPTIONS','NODE_PATH','LD_PRELOAD','LD_AUDIT','LD_LIBRARY_PATH','NODE_TLS_REJECT_UNAUTHORIZED','OPENSSL_CONF','BASH_ENV'])for(const surface of ['image','task','secret','override'])it('rejects '+name+' on '+surface,()=>{const i=envInput();if(surface==='image')i.imageEnvironment.push(name+'=');if(surface==='task')i.taskEnvironment.push({name,value:''});if(surface==='secret')i.secrets.push({name,valueFrom:'arn:aws:ssm:'+region+':'+account+':parameter/example'});if(surface==='override')i.overrides={containerOverrides:[{name:'ControlMem9Bootstrap',environment:[{name,value:''}]}]};expect(()=>validateNonrootEnvironment(i)).toThrow();});
 it('requires actual immutable CA file and parent metadata matching an independent expected digest',()=>{
  const i=envInput();i.imageEnvironment.push('NODE_EXTRA_CA_CERTS=/app/global-bundle.pem');i.expectedCa=[{path:'/app/global-bundle.pem',sha256:h('a')}];i.files=[{path:'/',type:'directory',mode:493,uid:0,gid:0},{path:'/app',type:'directory',mode:493,uid:0,gid:0},{path:'/app/global-bundle.pem',type:'file',mode:420,uid:0,gid:0,sha256:h('a')}];expect(()=>validateNonrootEnvironment(i)).not.toThrow();i.files[1].mode=511;expect(()=>validateNonrootEnvironment(i)).toThrow();
 });
});
describe('whole carrier request binding',()=>{
 it('resolves after registration and checks immutable independent bindings',()=>{const f=fixture();expect(verifyCarrierRunTaskBinding(f.binding,f.context)).toEqual(f.binding);expect(assertCarrierRunTaskDispatch(f.request,f.binding,f.context)).toBeUndefined();expect(f.request.taskDefinition).toBe(td);expect(f.request.platformVersion).toBe('1.4.0');expect(()=>verifyCarrierRunTaskBinding(f.binding)).toThrow();});
 it.each(['cluster','taskDefinition','count','launchType','platformVersion','networkConfiguration','enableExecuteCommand','enableECSManagedTags','propagateTags','tags','clientToken','startedBy','overrides'])('rejects changed %s even after attacker recomputes self hashes',key=>{const f=fixture(),b=structuredClone(f.binding);b.request[key]=key==='count'?2:key==='enableExecuteCommand'?true:'changed';b.requestHash=hash(b.request);b.authorization.requestHash=b.requestHash;expect(()=>verifyCarrierRunTaskBinding(b,f.context)).toThrow();expect(()=>assertCarrierRunTaskDispatch(b.request,f.binding,f.context)).toThrow();});
 it('rejects mutation after an await, stale evidence, missing pins and wrong context',async()=>{const f=fixture(),request=structuredClone(f.request);await Promise.resolve();request.networkConfiguration.awsvpcConfiguration.subnets.reverse();expect(()=>assertCarrierRunTaskDispatch(request,f.binding,f.context)).toThrow();for(const change of [c=>delete c.expected,c=>c.now+=400000,c=>c.expected.deadlineMs=c.now+170000,c=>c.invocation.invocation='c'.repeat(32),c=>c.permissions.result='fail']){const c=structuredClone(f.context);change(c);expect(()=>verifyCarrierRunTaskBinding(f.binding,c)).toThrow();}});
});

function identityFixture(){
 const names=['llm-proxy','mnemo-server','qwen3-embed'],descriptorHash=h('c'),registrationHash=h('d'),launchContractHash=h('a');
 const target={account,region,clusterArn:cluster,serviceName:'Mem9Server',serviceDeploymentId:'deployment-1',taskArn:'arn:aws:ecs:'+region+':'+account+':task/mem9-on-aws-prod-example/'+'a'.repeat(32),taskDefinitionArn:td,registrationHash,containers:names.map(name=>({name,runtimeId:'runtime-'+name,image:img,launchContractHash}))};
 const process=(pid,entry)=>({pid,ppid:1,startTimeTicks:pid+100,executablePath:'/usr/local/bin/node',executableDigest:d('a'),entrypointIdentityHash:entry,uid:[1000,1000,1000,1000],gid:[1000,1000,1000,1000],groups:[1000],capInh:'0000000000000000',capPrm:'0000000000000000',capEff:'0000000000000000',capBnd:'0000000000000000',capAmb:'0000000000000000',noNewPrivs:1});
 const runtime=(name,after=false)=>({version:2,kind:'application-process-identity',phase:'target',taskKey:'backend',account,region,taskArn:target.taskArn,taskDefinitionArn:td,containerName:name,runtimeId:'runtime-'+name,image:img,registrationHash,launchContractHash,sourceBindingHash:h('b'),artifactBinding:{kind:'data',descriptorHash,launchContractHash},collectorCodeHash:h('d'),sessionBinding:ref,startedMs:now-(after?20000:100000),completedMs:now-(after?10000:60000),application:[process(7,h('d')),process(after?21:20,h('e'))],trustedLaunch:[],managed:[],samples:ref,coverage:ref,result:'pass'});
 const pre={version:1,kind:'target-before-root-audit',descriptorHash,parameterVersion:2,deploymentSourceHash:h('b'),target,identity:names.map(n=>runtime(n)),routing:{version:1,kind:'target-private-routing',targetBindingHash:hash(target),probeSource:ref,routeObservations:ref,targetAttribution:ref,dependencyChecks:ref,startedMs:now-90000,completedMs:now-60000,result:'pass'},platform:fixture().plan.carrierPlatform,rawObservations:ref,startedMs:now-100000,completedMs:now-60000};
 const healthCommands=Object.fromEntries(names.map(n=>[n,['CMD','/usr/bin/setpriv','--no-new-privs','--','node','/app/healthcheck.mjs','http://localhost/health']]));
 const post={version:1,kind:'typed-post-audit-target-identities',preTargetHash:hash(pre),targetBindingHash:hash(target),registrationHash,identities:names.map(n=>runtime(n,true)),mainProcesses:names.map(containerName=>({containerName,preMain:process(7,h('d')),postMain:process(7,h('d'))})),healthCoverage:names.map(containerName=>({containerName,runtimeId:'runtime-'+containerName,image:img,registrationHash,launchContractHash,healthCommandHash:hash(healthCommands[containerName]),processes:[process(21,h('e'))],startedMs:now-20000,completedMs:now-10000})),startedMs:now-20000,completedMs:now-10000};
 return structuredClone({pre,post,context:{now,auditStartedMs:now-50000,auditCompletedMs:now-30000,healthCommands,mainEntrypointIdentityHashes:Object.fromEntries(names.map(n=>[n,h('d')]))}});
}
describe('pure same-target post-audit identity join',()=>{
 it('joins actual typed identities and independent health samples for all three containers',()=>{const f=identityFixture();expect(verifyTargetIdentityRecheck(f.post,f.pre,f.context)).toEqual(f.post);});
 it.each([
  f=>f.post.identities[0].runtimeId='replacement',f=>f.post.identities[0].registrationHash=h('f'),f=>f.post.identities[0].image.configDigest=d('f'),f=>f.post.identities.pop(),f=>f.post.healthCoverage[0].processes=[],f=>f.post.healthCoverage[0].healthCommandHash=h('f'),f=>f.post.identities[0].application[0].noNewPrivs=0,f=>f.post.startedMs=f.context.auditCompletedMs-1,f=>f.context.auditStartedMs=f.pre.completedMs-1,
  f=>{f.post.mainProcesses[0].postMain.pid=9;f.post.identities[0].application[0].pid=9;},
  f=>{const p=f.post.identities[0].application[1];f.post.mainProcesses[0].preMain=structuredClone(p);f.post.mainProcesses[0].postMain=structuredClone(p);},
 ])('rejects stale, changed, missing or misclassified process evidence',change=>{const f=identityFixture();change(f);expect(()=>verifyTargetIdentityRecheck(f.post,f.pre,f.context)).toThrow();});
});
