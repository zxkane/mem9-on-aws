/**
 * Pure launch construction and cross-record comparisons. Nothing here issues an
 * authorization or performs IO. In particular, a self-hashed JSON "allowed"
 * claim is insufficient: binding checks require independently authenticated pins
 * supplied by the owning adapter and a fresh explicit clock.
 */
import {createHash} from 'node:crypto';
import {inflateRawSync} from 'node:zlib';
import {
  copyNonrootJson, parseNonrootJson, nonrootHash as hash, inspectNonrootRecord,
  inspectCarrierRunTaskRequest, inspectEnvironmentGate, inspectRuntimeIdentity,
  inspectTargetIdentityRecheck, CONTROL_NODE, NONROOT_DATA_COMPONENTS,
} from './production-nonroot-contracts.mjs';

const need=(ok,code='NonrootLaunchInvalid')=>{if(!ok)throw Error(code);};
const same=(a,b,code='NonrootBindingMismatch')=>need(hash(a)===hash(b),code);
const record=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const exact=(v,keys)=>need(record(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k)));
const positive=v=>Number.isSafeInteger(v)&&v>0;
const h64=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const mutable=v=>structuredClone(copyNonrootJson(v));
const imageOnly=v=>({rootDigest:v.rootDigest,arm64Digest:v.arm64Digest,configDigest:v.configDigest});
const current=(at,now)=>need(positive(at)&&positive(now)&&at<=now&&now-at<=300000,'NonrootEvidenceExpired');

const dataSpecs=Object.freeze({
  'mnemo-server':{name:'mnemo-server',entry:['/usr/local/bin/entrypoint.sh'],command:[],prefix:'/bin/setpriv',
    health:['CMD-SHELL','wget -q -O /dev/null http://localhost:8080/healthz || exit 1']},
  'qwen3-embed':{name:'qwen3-embed',entry:['node','server.mjs'],command:[],prefix:'/usr/bin/setpriv',
    health:['CMD','node','/app/healthcheck.mjs','http://localhost:8081/health']},
  'llm-proxy':{name:'llm-proxy',entry:['node','server.mjs'],command:[],prefix:'/usr/bin/setpriv',
    health:['CMD','node','/app/healthcheck.mjs','http://localhost:8082/health']},
  planner:{name:'Mem9ConsolidationPlanner',entry:['node'],command:['/app/scripts/consolidation-worker.mjs'],prefix:'/usr/bin/setpriv'},
  executor:{name:'Mem9ConsolidationExecutor',entry:['node'],command:['/app/scripts/consolidation-worker.mjs'],prefix:'/usr/bin/setpriv'},
});
function harden(original,namedUserIdentity){
  const value=mutable(original);need(record(value));
  if(Object.hasOwn(value,'privileged'))need(value.privileged===false);
  if(value.user==='node'){
    const identity=copyNonrootJson(namedUserIdentity);
    exact(identity,['image','username','uid','gid','passwdSha256']);
    need(identity.image===value.image&&typeof identity.image==='string'&&/@sha256:[a-f0-9]{64}$/.test(identity.image)&&identity.username==='node'&&identity.uid===1000&&identity.gid===1000&&h64(identity.passwdSha256),'NonrootNamedUserIdentity');
  }else{
    need(namedUserIdentity===undefined,'NonrootUnusedUserIdentity');
    if(Object.hasOwn(value,'user'))need(['','0','0:0','root','root:root','1000:1000'].includes(value.user));
  }
  const linux=value.linuxParameters??{};need(record(linux));
  if(linux.capabilities!==undefined){
    need(record(linux.capabilities)&&Object.keys(linux.capabilities).every(k=>['add','drop'].includes(k)));
    if(linux.capabilities.add!==undefined)same(linux.capabilities.add,[]);
    if(linux.capabilities.drop!==undefined)same(linux.capabilities.drop,['ALL']);
  }
  value.user='1000:1000';
  value.linuxParameters={...linux,capabilities:{drop:['ALL']}};
  return value;
}

/** Returns a new immutable complete container definition, preserving unrelated
 * fields. component is a DATA component name, "planner", or "executor".
 * Effective OCI defaults are the reviewed fixed defaults, not inferred from a
 * tag. The proof adapter separately verifies actual image config/PATH evidence. */
export function dataLaunchPolicy(component,original){
  need(Object.hasOwn(dataSpecs,component));
  const spec=dataSpecs[component],value=harden(original);
  if(value.name!==undefined)need(value.name===spec.name);
  const prefix=[spec.prefix,'--no-new-privs','--'],target=[...prefix,...spec.entry];
  if(value.entryPoint!==undefined){
    need(hash(value.entryPoint)===hash(spec.entry)||hash(value.entryPoint)===hash(target));
  }
  const command=value.command??spec.command;
  if(component==='executor'&&hash(command)===hash(['/app/scripts/consolidation-canary-replay.mjs'])){
    // Existing explicit replay variant only; the Node prefix remains identical.
  }else same(command,spec.command);
  value.entryPoint=target;
  if(value.command!==undefined||spec.command.length)value.command=command;
  if(value.healthCheck!==undefined){
    need(record(value.healthCheck)&&spec.health);
    const before=spec.health;
    const after=before[0]==='CMD-SHELL'
      ?['CMD',...prefix,'/bin/sh','-c',before[1]]
      :['CMD',...prefix,...before.slice(1)];
    need(hash(value.healthCheck.command)===hash(before)||hash(value.healthCheck.command)===hash(after));
    value.healthCheck={...value.healthCheck,command:after};
  }
  return copyNonrootJson(value);
}
const controlNames=Object.freeze({
  'bootstrap-runtime-verify':'Mem9Bootstrap','consolidation-control':'ControlMem9Bootstrap',
  'consolidation-promote':'PromoteMem9Bootstrap','denied-provision':'ProdMem9Bootstrap',
  'denied-transition':'TransitionMem9Bootstrap','audit-original-root':'ControlMem9Bootstrap',
  'bootstrap-runtime-bootstrap':'Mem9Bootstrap','bootstrap-admin-probe':'Mem9Bootstrap',
  'bootstrap-admin-probe-cleanup':'Mem9Bootstrap','preview-fixture-setup':'Mem9Bootstrap',
  'preview-fixture-pause':'Mem9Bootstrap','preview-fixture-verify-planned':'Mem9Bootstrap',
  'preview-fixture-verify-executed':'Mem9Bootstrap','preview-fixture-verify-repeated':'Mem9Bootstrap',
  'post-runtime-fixture':'Mem9PostFixture','canary-fixture':'Mem9CanaryFixture',
  'bootstrap-schema-seed':'Mem9Bootstrap',
});
/** CONTROL replacement is an explicit purpose mapping. This does not admit the
 * operation (including denied purposes). No PATH lookup selects the Node binary. */
export function controlLaunchPolicy(purpose,original={},options={}){
  need(Object.hasOwn(controlNames,purpose));
  const o=copyNonrootJson(options);need(record(o)&&Object.keys(o).every(k=>k==='namedUserIdentity'));
  // Mapping must come from the caller's authenticated image/passwd evidence.
  // A name or a self-asserted mapping is not evidence of image provenance.
  const value=harden(original,o.namedUserIdentity);
  if(value.name!==undefined)need(value.name===controlNames[purpose]||value.name==='Mem9PostFixture'&&
    ['preview-fixture-setup','preview-fixture-pause','preview-fixture-verify-planned','preview-fixture-verify-executed','preview-fixture-verify-repeated'].includes(purpose));
  const script=purpose==='audit-original-root'?'/carrier/guard-first.mjs':'/bootstrap/nonroot-dispatch.mjs';
  value.entryPoint=['/bin/setpriv','--no-new-privs','--',CONTROL_NODE,script,purpose];
  value.command=[];
  return copyNonrootJson(value);
}

export const NONROOT_FORBIDDEN_ENVIRONMENT=Object.freeze([
  'NODE_OPTIONS','NODE_PATH','NODE_REPL_EXTERNAL_MODULE','NODE_V8_COVERAGE','NODE_ICU_DATA',
  'NODE_TLS_REJECT_UNAUTHORIZED','OPENSSL_CONF','OPENSSL_MODULES','BASH_ENV','ENV',
  'GCONV_PATH','LOCPATH','GLIBC_TUNABLES',
]);
const forbidden=name=>name.startsWith('LD_')||NONROOT_FORBIDDEN_ENVIRONMENT.includes(name);
function envRows(rows,secret=false){
  need(Array.isArray(rows));const names=new Set();
  for(const row of rows){
    exact(row,secret?['name','valueFrom']:['name','value']);
    need(typeof row.name==='string'&&/^[A-Za-z_][A-Za-z0-9_]*$/.test(row.name)&&!names.has(row.name)&&!forbidden(row.name));
    names.add(row.name);
    const value=row[secret?'valueFrom':'value'];need(typeof value==='string'&&!value.includes('\0'));
    if(secret)need(/^arn:aws:(ssm|secretsmanager):[a-z0-9-]+:\d{12}:(parameter\/|secret:)/.test(value)&&row.name!=='NODE_EXTRA_CA_CERTS');
  }
  return names;
}
/** Input metadata/CA expectations must be extracted from authenticated image and
 * task evidence by the caller. This only checks their content and commitments;
 * it does not claim that an arbitrary "files" array is a verified filesystem. */
export function validateNonrootEnvironment(input){
  const v=copyNonrootJson(input);
  exact(v,['imageEnvironment','taskEnvironment','secrets','overrides','files','expectedCa']);
  need(Array.isArray(v.imageEnvironment));
  const image=v.imageEnvironment.map(value=>{
    need(typeof value==='string'&&value.includes('='));const i=value.indexOf('=');
    return {name:value.slice(0,i),value:value.slice(i+1)};
  });
  envRows(image);envRows(v.taskEnvironment);const secretNames=envRows(v.secrets,true);
  need(record(v.overrides)&&Object.keys(v.overrides).every(k=>k==='containerOverrides'));
  const override=[];
  if(v.overrides.containerOverrides!==undefined){
    need(Array.isArray(v.overrides.containerOverrides)&&v.overrides.containerOverrides.length<=1);
    for(const c of v.overrides.containerOverrides){
      exact(c,['name','environment']);need(c.name==='ControlMem9Bootstrap');envRows(c.environment);override.push(...c.environment);
    }
  }
  for(const row of [...image,...v.taskEnvironment,...override])need(!secretNames.has(row.name),'NonrootPlaintextSecretCollision');
  const files=new Map();need(Array.isArray(v.files)&&Array.isArray(v.expectedCa));
  for(const f of v.files){
    need(record(f)&&!files.has(f.path));
    exact(f,f.type==='file'?['path','type','mode','uid','gid','sha256']:['path','type','mode','uid','gid']);
    need(typeof f.path==='string'&&f.path.startsWith('/')&&!f.path.split('/').includes('..')&&['file','directory'].includes(f.type));
    need(Number.isSafeInteger(f.mode)&&f.mode>=0&&f.mode<=4095&&Number.isSafeInteger(f.uid)&&Number.isSafeInteger(f.gid));
    if(f.type==='file')need(h64(f.sha256));
    files.set(f.path,f);
  }
  need(!files.has('/etc/ld.so.preload'),'NonrootLoaderPreloadFile');
  const caValues=[...image,...v.taskEnvironment,...override].filter(r=>r.name==='NODE_EXTRA_CA_CERTS').map(r=>r.value);
  for(const value of caValues){
    need(['/app/global-bundle.pem','/bootstrap/global-bundle.pem'].includes(value),'NonrootCaPath');
    const expected=v.expectedCa.filter(f=>{exact(f,['path','sha256']);return f.path===value;});
    need(expected.length===1&&h64(expected[0].sha256));
    const f=files.get(value);need(f?.type==='file'&&f.sha256===expected[0].sha256);
    for(const path of ['/',value.slice(0,value.lastIndexOf('/')),value]){
      const entry=files.get(path);need(entry&&entry.uid===0&&entry.gid===0&&(entry.mode&0o022)===0&&(entry.mode&0o6000)===0);
      need(path===value?entry.type==='file'&&(entry.mode&0o444)!==0:entry.type==='directory'&&(entry.mode&0o111)!==0);
    }
  }
  // Do not echo environment values or infer permission from a success flag.
  return copyNonrootJson({
    imageEnvironmentHash:hash(v.imageEnvironment),taskEnvironmentHash:hash(v.taskEnvironment),
    secretNamesAndReferencesHash:hash(v.secrets),overrideHash:hash(v.overrides),
    caBindingsHash:hash(v.expectedCa),forbiddenNamesHash:hash({names:NONROOT_FORBIDDEN_ENVIRONMENT,prefix:'LD_'}),
  });
}

function checkedInvocation(value){
  const v=copyNonrootJson(value);exact(v,['invocation','runOverrides']);
  need(typeof v.invocation==='string'&&/^[a-f0-9]{32}$/.test(v.invocation));
  const overrides=inspectNonrootRecord('CarrierRunOverridesV1',v.runOverrides);
  const rows=overrides.containerOverrides[0].environment;
  let bytes,text,decoded;
  try{
    const compressed=Buffer.from(rows[0].value,'base64');
    need(compressed.toString('base64')===rows[0].value);
    bytes=inflateRawSync(compressed,{maxOutputLength:32768});
    text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
    decoded=parseNonrootJson(text,{maxBytes:32768});
  }catch{need(false,'NonrootAuditInputInvalid');}
  // Validate inert JSON including duplicate keys through the public parser.
  // The actual old-root/certificate schema is checked by the owning proof layer.
  need(record(decoded)&&decoded.invocation===v.invocation&&digest(bytes)===rows[1].value,'NonrootAuditInputBinding');
  return {invocation:v.invocation,runOverrides:overrides};
}
/** Builds non-authorizing request data only. The returned exact body still needs
 * authenticated permission/evidence binding before any dispatch. */
export function resolveCarrierRunTaskRequest(planValue,readbackValue,invocationValue){
  const plan=inspectNonrootRecord('PreauditLaunchPlanV1',planValue);
  const readback=inspectNonrootRecord('CarrierRegistrationReadbackV1',readbackValue);
  const invocation=checkedInvocation(invocationValue),c=plan.runTaskContract;
  same(plan.carrierImage,readback.carrierImage);
  need(readback.requestedRegistrationBodyHash===plan.registrationBody.canonicalHash);
  need(plan.environmentGate.registrationBodyHash===plan.registrationBody.canonicalHash);
  same(plan.environmentGate.image,imageOnly(plan.carrierImage));
  const prefix='arn:aws:ecs:'+plan.region+':'+plan.account+':';
  need(c.cluster.startsWith(prefix+'cluster/mem9-on-aws-prod-'));
  need(readback.taskDefinitionArn.startsWith(prefix+'task-definition/'+c.cluster.split('/').at(-1)+'-ControlMem9Bootstrap:'));
  for(const arn of [plan.taskRoleArn,plan.executionRoleArn])need(arn.startsWith('arn:aws:iam::'+plan.account+':role/'));
  const request={};
  for(const k of ['cluster','count','launchType','platformVersion','networkConfiguration','enableExecuteCommand','enableECSManagedTags','propagateTags','tags'])request[k]=c[k];
  Object.assign(request,{taskDefinition:readback.taskDefinitionArn,clientToken:invocation.invocation,
    startedBy:'root-'+invocation.invocation.slice(0,29),overrides:invocation.runOverrides});
  return inspectCarrierRunTaskRequest(request);
}

/** context.expected contains INDEPENDENT authenticated commitments from the
 * owner/admission adapter, never pins computed from the untrusted binding here.
 * All context members are inert data, not validation/authorization callbacks. */
export function verifyCarrierRunTaskBinding(value,context){
  const c=copyNonrootJson(context);
  exact(c,['plan','readback','environmentGate','carrierPresence','permissions','invocation','expected','now']);
  exact(c.expected,['planHash','readbackHash','environmentGateHash','carrierPresenceHash','permissionsHash','carrierBuildHash','requestHash','callerArn','deadlineMs','reviewExpiresMs']);
  const b=inspectNonrootRecord('CarrierRunTaskBindingV1',value),p=inspectNonrootRecord('PreauditLaunchPlanV1',c.plan);
  const r=inspectNonrootRecord('CarrierRegistrationReadbackV1',c.readback),e=inspectEnvironmentGate(c.environmentGate);
  const present=inspectNonrootRecord('CarrierRegistryPresenceV1',c.carrierPresence),permissions=inspectNonrootRecord('PermissionsDossierV1',c.permissions);
  for(const [field,input] of [['planHash',p],['readbackHash',r],['environmentGateHash',e],['carrierPresenceHash',present],['permissionsHash',permissions]]){
    need(h64(c.expected[field])&&hash(input)===c.expected[field],'NonrootIndependentPinMismatch');
  }
  need(h64(c.expected.requestHash)&&b.requestHash===c.expected.requestHash&&c.expected.carrierBuildHash===p.carrierBuildHash,'NonrootIndependentPinMismatch');
  same(b.request,resolveCarrierRunTaskRequest(p,r,c.invocation));
  need(b.launchPlanHash===c.expected.planHash&&b.runTaskContractHash===hash(p.runTaskContract)&&b.registrationReadbackHash===c.expected.readbackHash&&b.environmentGateHash===c.expected.environmentGateHash&&b.carrierPresenceHash===c.expected.carrierPresenceHash);
  need(permissions.carrierRunTaskContractHash===b.runTaskContractHash&&permissions.account===p.account&&permissions.applicationRegion===p.region);
  need(b.authorization.permissionsDossierHash===c.expected.permissionsHash&&b.authorization.callerArn===c.expected.callerArn&&b.authorization.taskRoleArn===p.taskRoleArn&&b.authorization.executionRoleArn===p.executionRoleArn);
  need(b.authorization.callerArn.startsWith('arn:aws:')&&b.authorization.callerArn.split(':')[4]===p.account);
  need(e.registrationBodyHash===r.requestedRegistrationBodyHash&&e.overrideHash===hash(b.request.overrides));
  same(e.image,imageOnly(p.carrierImage));same(present.image,p.carrierImage);
  need(present.carrierBuildHash===p.carrierBuildHash);
  for(const at of [r.observedMs,e.checkedMs,present.observedMs,permissions.observedMs])current(at,c.now);
  need(r.observedMs<=e.checkedMs&&c.now<present.expiresMs,'NonrootEvidenceExpired');
  need(positive(c.expected.deadlineMs)&&positive(c.expected.reviewExpiresMs)&&c.expected.deadlineMs<=c.expected.reviewExpiresMs);
  need(c.now+p.maxRuntimeMs+p.cleanupReserveMs<Math.min(c.expected.deadlineMs,c.expected.reviewExpiresMs),'NonrootEvidenceExpired');
  return b;
}
/** Call again AFTER awaits, at the owning adapter's final API boundary. */
export function assertCarrierRunTaskDispatch(request,binding,context){
  const checked=verifyCarrierRunTaskBinding(binding,context);
  same(inspectCarrierRunTaskRequest(request),checked.request,'NonrootDispatchChanged');
}

/** Pure three-container/PID/health/time join. Reference byte authentication and
 * routing/SQL audit verification remain the evidence adapter's responsibility. */
export function verifyTargetIdentityRecheck(value,preValue,context){
  const c=copyNonrootJson(context);
  exact(c,['auditStartedMs','auditCompletedMs','now','healthCommands','mainEntrypointIdentityHashes']);
  exact(c.healthCommands,NONROOT_DATA_COMPONENTS);exact(c.mainEntrypointIdentityHashes,NONROOT_DATA_COMPONENTS);
  const post=inspectTargetIdentityRecheck(value),pre=inspectNonrootRecord('TargetPreReadinessV1',preValue),target=pre.target;
  need(post.preTargetHash===hash(pre)&&post.targetBindingHash===hash(target)&&post.registrationHash===target.registrationHash,'NonrootTargetBinding');
  need(positive(c.now)&&positive(c.auditStartedMs)&&positive(c.auditCompletedMs)&&pre.completedMs<=c.auditStartedMs&&c.auditStartedMs<=c.auditCompletedMs&&c.auditCompletedMs<=post.startedMs&&post.completedMs<=c.now,'NonrootTargetWindow');
  const starts=[pre.startedMs,pre.routing.startedMs,...pre.identity.map(i=>i.startedMs)];
  need(post.completedMs-Math.min(...starts)<=300000,'NonrootTargetWindow');
  for(const name of NONROOT_DATA_COMPONENTS){
    const before=pre.identity.find(i=>i.containerName===name),after=post.identities.find(i=>i.containerName===name);
    const bound=target.containers.find(i=>i.name===name),main=post.mainProcesses.find(i=>i.containerName===name),health=post.healthCoverage.find(i=>i.containerName===name);
    for(const identity of [before,after]){
      inspectRuntimeIdentity(identity);
      need(identity.phase==='target'&&identity.taskKey==='backend'&&identity.taskArn===target.taskArn&&identity.taskDefinitionArn===target.taskDefinitionArn&&identity.runtimeId===bound.runtimeId&&identity.account===target.account&&identity.region===target.region&&identity.registrationHash===target.registrationHash&&identity.launchContractHash===bound.launchContractHash,'NonrootTargetBinding');
      same(identity.image,bound.image);need(identity.artifactBinding.kind==='data'&&identity.artifactBinding.descriptorHash===pre.descriptorHash);
    }
    same(before.artifactBinding,after.artifactBinding);need(before.sourceBindingHash===after.sourceBindingHash);
    need(before.startedMs>=pre.startedMs&&before.completedMs<=pre.completedMs&&after.startedMs>=post.startedMs&&after.completedMs<=post.completedMs,'NonrootTargetWindow');
    const entry=c.mainEntrypointIdentityHashes[name];need(h64(entry));
    const beforeMain=before.application.filter(p=>p.entrypointIdentityHash===entry),afterMain=after.application.filter(p=>p.entrypointIdentityHash===entry);
    need(beforeMain.length===1&&afterMain.length===1,'NonrootMainIdentity');
    same(main.preMain,beforeMain[0]);same(main.postMain,afterMain[0]);
    for(const k of ['pid','startTimeTicks','executableDigest','entrypointIdentityHash'])need(main.preMain[k]===main.postMain[k],'NonrootMainIdentity');
    need(health.runtimeId===bound.runtimeId&&health.registrationHash===target.registrationHash&&health.launchContractHash===bound.launchContractHash&&health.healthCommandHash===hash(c.healthCommands[name]),'NonrootHealthBinding');same(health.image,bound.image);
    need(health.startedMs>=post.startedMs&&health.completedMs<=post.completedMs,'NonrootTargetWindow');
    for(const proc of health.processes)need(proc.pid!==main.postMain.pid&&after.application.some(p=>hash(p)===hash(proc)),'NonrootHealthCoverage');
  }
  return post;
}
