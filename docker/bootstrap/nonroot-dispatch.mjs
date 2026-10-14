import {readFileSync} from 'node:fs';
import process from 'node:process';
import {createHash} from 'node:crypto';
import {inspectGuardIdentity,parseGuardJson,resolveGuardPurpose} from './nonroot-identity.mjs';
import {readGuardArtifact,inspectGuardManifest,verifyGuardFiles} from './nonroot-files.mjs';

const fail=code=>{throw Error(code);};
const observerInvocations=new WeakMap();let observerEntryUsed=false;
export function requireGuardedObserverInvocation(handle){
 const state=observerInvocations.get(handle);
 if(!state||state.closed||Date.now()<state.startedMs||Date.now()>=state.deadlineMs)fail('NonrootObserverInvocation');
 return state.binding;
}
const forbidden=new Set(['NODE_OPTIONS','NODE_PATH','NODE_REPL_EXTERNAL_MODULE','NODE_V8_COVERAGE','NODE_ICU_DATA',
 'NODE_TLS_REJECT_UNAUTHORIZED','OPENSSL_CONF','OPENSSL_MODULES','BASH_ENV','ENV','GCONV_PATH','LOCPATH','GLIBC_TUNABLES']);

/** This repeat check is defense in depth: the authenticated host launch gate
 * must reject preloading before Node starts, including empty variables. */
function rejectPreloadEnvironment(){
 for(const name of Object.keys(process.env))if(forbidden.has(name)||name.startsWith('LD_'))fail('NonrootEnvironment');
 if(process.env.NODE_EXTRA_CA_CERTS!==undefined&&process.env.NODE_EXTRA_CA_CERTS!=='/bootstrap/global-bundle.pem')fail('NonrootEnvironment');
}

function validateOperation(route){
 if(route.module.endsWith('/production-consolidation-operator.mjs')){
  const request=parseGuardJson(process.env.MEM9_PRODUCTION_CONSOLIDATION_REQUEST,16384);
  const allowed=['plan','baseline','canary','verify-canary','inspect-canary','begin-continuation','resume-plan','pause','status','cleanup-benchmark'];
  if(!request||typeof request!=='object'||Array.isArray(request)||!((route.operation==='promotion'&&request.operation==='promote')||
   route.operation==='control'&&allowed.includes(request.operation))||!/^[a-f0-9]{32}$/.test(request.invocation??'')||
   !Number.isSafeInteger(request.deadline)||request.deadline<=Date.now()||request.deadline>Date.now()+900000)fail('NonrootOperation');
  const keys=['operation','deadline','dailyRows','basisPoints','acceptance','invocation','canaryReportHash','benchmarkRefs','backendBinding','attemptId','parentProofHash','compatibility'];
  if(Object.keys(request).some(key=>!keys.includes(key)))fail('NonrootOperation');
 }
}

export async function guardedControlMain(){
 // The identity check is the first operation that can inspect runtime state.
 // No credential variable or application import is accessed before this gate.
 const identity=inspectGuardIdentity(readFileSync('/proc/self/status','utf8'),process.pid);
 if(process.execPath!=='/usr/local/bin/node'||process.argv.length!==3||process.argv[1]!=='/bootstrap/nonroot-dispatch.mjs')fail('NonrootArguments');
 rejectPreloadEnvironment();
 const purpose=process.argv[2],route=resolveGuardPurpose(purpose,process.env);
 validateOperation(route);
 const manifestFile=readGuardArtifact('/bootstrap/nonroot-manifest.json',8388608);
 const manifest=inspectGuardManifest(manifestFile.bytes.toString('utf8'));
 verifyGuardFiles(manifest,route.module);
 if(route.kind==='observer'){
  if(observerEntryUsed)fail('NonrootObserverOnce');observerEntryUsed=true;
  for(const name of ['production-nonroot-observer-route-probe.mjs','production-nonroot-observer-control-context.mjs','production-nonroot-observer-runtime-provider.mjs','production-nonroot-observer-delivery.mjs'])
   if(!manifest.files.some(row=>row.path==='/bootstrap/operator/scripts/lib/'+name))fail('NonrootObserverSource');
 }
 // Content-free lifecycle evidence precedes application credential use.
 process.stdout.write(JSON.stringify({event:'nonroot_guard',outcome:'passed',purpose,pid:identity.pid,noNewPrivs:1,manifestSha256:manifestFile.sha256})+'\n');
 if(route.kind==='observer'){
  // Fixed imports only, after the actual kernel and complete file gates.
  const codec=await import('/bootstrap/operator/scripts/lib/production-nonroot-observer-delivery.mjs');
  const wire=process.env.MEM9_OBSERVER_CONTROL_DELIVERY,decoded=codec.decodeObserverControlDelivery(wire),delivery=decoded.delivery;
  if(delivery.stage!==process.env.MEM9_STAGE||delivery.manifestSha256!==manifestFile.sha256||decoded.wireSha256!==createHash('sha256').update(wire).digest('hex'))fail('NonrootObserverDelivery');
  const handle=Object.freeze({kind:'guarded-observer-invocation'}),state={closed:false,startedMs:delivery.startedMs,deadlineMs:delivery.deadlineMs,
   binding:Object.freeze({purpose,manifestSha256:manifestFile.sha256,payloadSha256:decoded.wireSha256})};
  observerInvocations.set(handle,state);let context,provider,api,runtime;
  try{
   requireGuardedObserverInvocation(handle);
   runtime=await import('/bootstrap/operator/scripts/lib/production-nonroot-observer-runtime-provider.mjs');requireGuardedObserverInvocation(handle);
   api=await import('/bootstrap/operator/scripts/lib/production-nonroot-observer-control-context.mjs');requireGuardedObserverInvocation(handle);
   provider=await runtime.openObserverRuntimeProvider(delivery,handle);requireGuardedObserverInvocation(handle);runtime.observerRuntimeState(provider);
   context=await api.openObserverControlContext(delivery,handle,provider);api.requireObserverControlContext(context);
   const probe=await import('/bootstrap/operator/scripts/lib/production-nonroot-observer-route-probe.mjs');api.requireObserverControlContext(context);
   const observation=await probe.runObserverRouteProbe(delivery,context);api.requireObserverControlContext(context);
   const output=api.encodeObserverRouteObservation(context,observation);let timer;
   try{
    await new Promise((resolve,reject)=>{
     timer=setTimeout(()=>reject(Error('NonrootObserverOutputDeadline')),Math.max(1,delivery.deadlineMs-Date.now()));
     process.stdout.write(output,error=>error?reject(error):resolve());
    });api.requireObserverControlContext(context);
    api.finishObserverRouteObservation(context,output);
   }finally{clearTimeout(timer);}
  }finally{
   try{if(context)await api.closeObserverControlContext(context);else if(provider)await runtime.closeObserverRuntimeProvider(provider);}
   finally{state.closed=true;}
  }
 }else if(route.kind==='shell'){
  const {spawn}=await import('node:child_process');
  const child=spawn(route.module,[],{stdio:'inherit',env:process.env});
  await new Promise((resolve,reject)=>{child.once('error',()=>reject(Error('NonrootApplication')));child.once('exit',(code,signal)=>{
   if(signal||code!==0)reject(Error('NonrootApplication'));else resolve();
  });});
 }else{
  process.argv=[process.execPath,route.module];
  await import('file://'+route.module);
 }
}

if(process.argv[1]==='/bootstrap/nonroot-dispatch.mjs')guardedControlMain().catch(()=>{
 process.stdout.write('{"event":"nonroot_guard","outcome":"failed","errorClass":"NonrootGuardRejected"}\n');process.exitCode=1;
});
