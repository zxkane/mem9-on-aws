import {Buffer} from 'node:buffer';

const fail=code=>{throw Error(code);};
const required=['Pid','PPid','Uid','Gid','Groups','CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs'];

/** Inspect the application process itself. ECS Exec's diagnostic process is
 * never evidence for this guard. PID 1 may be a separate trusted init. */
export function inspectGuardIdentity(raw,pid){
 if(typeof raw!=='string'||Buffer.byteLength(raw)>65536||!Number.isSafeInteger(pid)||pid<1)fail('NonrootIdentity');
 const fields=new Map();
 for(const line of raw.split('\n')){
  const at=line.indexOf(':');if(at<0)continue;const name=line.slice(0,at);
  if(!required.includes(name))continue;
  if(fields.has(name))fail('NonrootIdentity');fields.set(name,line.slice(at+1).trim());
 }
 if(required.some(name=>!fields.has(name)))fail('NonrootIdentity');
 const integer=value=>/^(?:0|[1-9][0-9]*)$/.test(value)&&Number.isSafeInteger(Number(value))?Number(value):fail('NonrootIdentity');
 const ids=name=>fields.get(name).split(/\s+/).map(integer);
 const uid=ids('Uid'),gid=ids('Gid'),groups=fields.get('Groups')?ids('Groups'):[];
 if(uid.length!==4||gid.length!==4||[...uid,...gid].some(value=>value!==1000)||
  !(groups.length===0||groups.length===1&&groups[0]===1000)||integer(fields.get('Pid'))!==pid||fields.get('NoNewPrivs')!=='1')fail('NonrootIdentity');
 const capabilities=Object.fromEntries(required.filter(name=>name.startsWith('Cap')).map(name=>{
  const value=fields.get(name);if(value!=='0000000000000000')fail('NonrootIdentity');return [name,value];
 }));
 return Object.freeze({pid,parentPid:integer(fields.get('PPid')),uid:Object.freeze(uid),gid:Object.freeze(gid),groups:Object.freeze(groups),capabilities:Object.freeze(capabilities),noNewPrivs:1});
}

/** Guard inputs use the exact JSON.stringify wire form emitted by the owned
 * launcher/build. Requiring that form also rejects duplicate decoded keys;
 * parsing and silently reserializing arbitrary caller input is not allowed. */
export function parseGuardJson(raw,maxBytes=8192){
 if(typeof raw!=='string'||!Number.isSafeInteger(maxBytes)||maxBytes<1||maxBytes>8388608||Buffer.byteLength(raw)>maxBytes)fail('NonrootInput');
 let value;try{value=JSON.parse(raw);}catch{fail('NonrootInput');}
 if(JSON.stringify(value)!==raw.trim())fail('NonrootInput');
 let count=0;
 const visit=(item,depth)=>{
  if(depth>64||++count>200000)fail('NonrootInput');
  if(typeof item==='number'&&!Number.isSafeInteger(item))fail('NonrootInput');
  if(typeof item==='string'&&(item.includes('\0')||!item.isWellFormed()))fail('NonrootInput');
  if(item&&typeof item==='object')for(const [key,child]of Object.entries(item)){
   if(['__proto__','prototype','constructor'].includes(key)||key.includes('\0')||!key.isWellFormed())fail('NonrootInput');visit(child,depth+1);
  }
 };
 visit(value,0);return value;
}

const base='/bootstrap/operator/scripts/';
const preview=Object.freeze({
 'bootstrap-runtime-bootstrap':['runtime-bootstrap','runtime-bootstrap.mjs'],
 'bootstrap-admin-probe':['runtime-admin-probe','runtime-admin-probe.mjs'],
 'bootstrap-admin-probe-cleanup':['runtime-admin-probe-cleanup','runtime-admin-probe.mjs'],
 'preview-fixture-setup':['consolidation-preview-setup','consolidation-preview-fixture.mjs'],
 'preview-fixture-pause':['consolidation-preview-pause','consolidation-preview-fixture.mjs'],
 'preview-fixture-verify-planned':['consolidation-preview-verify-planned','consolidation-preview-fixture.mjs'],
 'preview-fixture-verify-executed':['consolidation-preview-verify-executed','consolidation-preview-fixture.mjs'],
 'preview-fixture-verify-repeated':['consolidation-preview-verify-repeated','consolidation-preview-fixture.mjs'],
 'post-runtime-fixture':['consolidation-preview-pause','consolidation-preview-fixture.mjs'],
});

/** Call only after identity validation. These are nonsecret routing fields;
 * the selected application retains its own independent operation admission. */
export function resolveGuardPurpose(purpose,env){
 if(typeof purpose!=='string'||!env||typeof env!=='object'||['denied-provision','denied-transition'].includes(purpose))fail('NonrootPurpose');
 const stage=env.MEM9_STAGE,isPreview=/^pr-[1-9][0-9]*$/.test(stage??'');
 if(stage!=='prod'&&!isPreview)fail('NonrootPurpose');
 if(purpose==='continuation-inspection'){
  if(stage!=='prod'||env.MEM9_PRODUCTION_WORKER_OPERATOR!=='control'||
   !['parse-begin','root-audit','capacity-census','publication-audit','publication-probe'].includes(env.MEM9_CONTINUATION_OPERATION))fail('NonrootPurpose');
  return Object.freeze({kind:'module',module:base+'production-continuation-inspection.mjs',operation:env.MEM9_CONTINUATION_OPERATION});
 }
 if(purpose==='bootstrap-runtime-verify'){
  if(env.MEM9_BOOTSTRAP_OPERATION!=='runtime-verify'||env.MEM9_RUNTIME_BOOTSTRAP_VERSION!=='1')fail('NonrootPurpose');
  return Object.freeze({kind:'module',module:base+'runtime-bootstrap.mjs',operation:'runtime-verify'});
 }
 if(purpose==='consolidation-control'||purpose==='consolidation-promote'){
  const operation=purpose==='consolidation-control'?'control':'promotion';
  if(stage!=='prod'||env.MEM9_PRODUCTION_WORKER_OPERATOR!==operation)fail('NonrootPurpose');
  return Object.freeze({kind:'module',module:base+'production-consolidation-operator.mjs',operation});
 }
 if(!isPreview)fail('NonrootPurpose');
 if(purpose==='canary-fixture'){
  const identity=parseGuardJson(env.MEM9_CANARY_FIXTURE_IDENTITY,2048);
  const keys=['stage','runId','runAttempt','commit','sourceTree','coordinatorDigest','schemaDigest','operatorDigest','nonce','deadlineMs'];
  if(!identity||typeof identity!=='object'||Array.isArray(identity)||Object.keys(identity).sort().join()!==keys.sort().join()||identity.stage!==stage||
   !/^[1-9][0-9]*$/.test(identity.runId??'')||!Number.isSafeInteger(identity.runAttempt)||identity.runAttempt<1||
   !['commit','sourceTree'].every(key=>/^[a-f0-9]{40}$/.test(identity[key]??''))||
   !['coordinatorDigest','schemaDigest','operatorDigest'].every(key=>/^[a-f0-9]{64}$/.test(identity[key]??''))||
   !/^[a-f0-9]{32}$/.test(identity.nonce??'')||!Number.isSafeInteger(identity.deadlineMs)||identity.deadlineMs<=Date.now()||identity.deadlineMs>Date.now()+1200000)fail('NonrootPurpose');
  return Object.freeze({kind:'module',module:base+'canary-fixture-runner.mjs',operation:'canary-fixture'});
 }
 if(purpose==='bootstrap-schema-seed'){
  if(env.MEM9_BOOTSTRAP_OPERATION!==undefined||env.MEM9_RUNTIME_BOOTSTRAP_VERSION!==undefined)fail('NonrootPurpose');
  return Object.freeze({kind:'shell',module:'/bootstrap/entrypoint.sh',operation:'schema-seed'});
 }
 const route=Object.hasOwn(preview,purpose)?preview[purpose]:null;
 if(!route||env.MEM9_BOOTSTRAP_OPERATION!==route[0])fail('NonrootPurpose');
 return Object.freeze({kind:'module',module:base+route[1],operation:route[0]});
}
