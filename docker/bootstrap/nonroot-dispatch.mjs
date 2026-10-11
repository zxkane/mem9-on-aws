import {readFileSync} from 'node:fs';
import process from 'node:process';
import {inspectGuardIdentity,parseGuardJson,resolveGuardPurpose} from './nonroot-identity.mjs';
import {readGuardArtifact,inspectGuardManifest,verifyGuardFiles} from './nonroot-files.mjs';

const fail=code=>{throw Error(code);};
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
 // Content-free lifecycle evidence precedes application credential use.
 process.stdout.write(JSON.stringify({event:'nonroot_guard',outcome:'passed',purpose,pid:identity.pid,noNewPrivs:1,manifestSha256:manifestFile.sha256})+'\n');
 if(route.kind==='shell'){
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
