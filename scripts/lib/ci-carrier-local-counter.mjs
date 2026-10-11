/** One original local counter spans startup and the consumer. Durable claims
 * survive failure; neither serialized counters nor another run can resume it. */
import {mkdirSync,openSync,writeSync,fsyncSync,closeSync,lstatSync,fstatSync,realpathSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {inspectCarrierFundingPlan,carrierHash as hash} from './ci-carrier-before-copy.mjs';
import {zero,COUNTERS,sha,freeze} from './ci-smoke-acquisition-format.mjs';
import {parseCiSmokeJson} from './ci-smoke-evidence.mjs';
import {inspectCarrierLocalPolicy,carrierCleanupReservation} from './ci-carrier-local-policy.mjs';
const states=new WeakMap(),claimed=new Set(),need=(v,c)=>{if(!v)throw Error(c);};
const execute=promisify(execFile);
export function carrierLocalNativeRun(env,cwd){
 return async(program,args,{maxBytes,encoding='utf8',timeoutMs=30000,signal}={})=>{
  need(['git','gh'].includes(program)&&Number.isSafeInteger(maxBytes)&&maxBytes>0&&maxBytes<=16777216,'CarrierLocalCommand');
  try{return (await execute(program,args,{env,cwd,maxBuffer:maxBytes,encoding:encoding==='buffer'?null:encoding,timeout:Math.min(timeoutMs,30000),signal,killSignal:'SIGKILL'})).stdout;}
  catch{throw Error('CarrierLocalCommandFailed');}
 };
}
const identity=env=>hash(Object.fromEntries(['RUNNER_TEMP','GITHUB_REPOSITORY','GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_JOB','GITHUB_WORKFLOW_SHA','GITHUB_WORKFLOW_REF','INPUT_GRANT_COMMITMENT','INPUT_CONTEXT_COMMITMENT'].map(k=>[k,env[k]??null])));
export function openCarrierLocalCounter({config,env,now=Date.now}){
 const plan=freeze(inspectCarrierFundingPlan(config.plan)),policy=Object.freeze(inspectCarrierLocalPolicy(plan.template.ciLocalPolicy)),planHash=hash(plan),configHash=hash(config),initial=identity(env);
 need(config.templateHash===plan.templateHash&&config.configHash===plan.configHash&&config.ledgerStartHash===plan.ledgerStartHash&&env.INPUT_GRANT_COMMITMENT===config.grantHash&&env.INPUT_CONTEXT_COMMITMENT===plan.context.sha256,'CarrierLocalBinding');
 need(/^[a-f0-9]{64}$/.test(config.grantHash)&&/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ID??'')&&/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ATTEMPT??''),'CarrierLocalBinding');
 const root=env.RUNNER_TEMP;need(typeof root==='string'&&resolve(root)===root&&realpathSync(root)===root&&lstatSync(root).isDirectory(),'CarrierLocalDirectory');
 const key=hash({planHash,grantHash:config.grantHash}),directory=join(root,'mem9-carrier-local-'+key);
 need(!claimed.has(key),'CarrierLocalClaim');claimed.add(key);
 try{mkdirSync(directory,{mode:0o700});}catch{throw Error('CarrierLocalClaim');}
 const path=join(directory,'journal.jsonl'),fd=openSync(path,'wx',0o600),stat=fstatSync(fd),spent=zero(),records=[];
 const cleanupReserved=carrierCleanupReservation(plan.template);need(cleanupReserved<policy.logicalBytes,'CarrierLocalCleanup');
 const abort=new AbortController(),pending=new Set();
 let held=false,closed=false,cleanup=false,cleanupUsed=0,binding,transferred=false,previous=null,recordBytes=0,clock=now(),draining=false,cleanupUnknown=false,drainPromise;
 const checkLocal=()=>{
  need(!closed&&identity(env)===initial,'CarrierLocalBinding');const at=now();need(Number.isSafeInteger(at)&&at>=clock&&at>=plan.issuedMs&&at<plan.deadlineMs,'CarrierLocalDeadline');clock=at;
  const named=lstatSync(path),open=fstatSync(fd);need(named.dev===stat.dev&&named.ino===stat.ino&&open.ino===stat.ino&&named.nlink===1&&(named.mode&511)===0o600,'CarrierLocalJournal');
  if(!cleanup)need(!held&&at<plan.deadlineMs-policy.cleanupMs,'CarrierLocalHeld');
 };
 const reserveLocal=charge=>{
  checkLocal();need(Object.keys(charge).sort().join()===COUNTERS.slice().sort().join()&&charge.ecrRequests===0&&charge.httpBodyBytes===0,'CarrierLocalCharge');
  const limit=cleanup?cleanupReserved-cleanupUsed:policy.logicalBytes-cleanupReserved-spent.logicalBytes;
  if(!Number.isSafeInteger(charge.logicalBytes)||charge.logicalBytes<0||charge.logicalBytes>limit){held=true;throw Error('CarrierLocalLimit');}
  for(const k of COUNTERS)if(!Number.isSafeInteger(charge[k])||charge[k]<0||spent[k]+charge[k]>plan.template.fundedLocal.ci[k]){held=true;throw Error('CarrierLocalLimit');}
  for(const k of COUNTERS)spent[k]+=charge[k];if(cleanup)cleanupUsed+=charge.logicalBytes;
 };
 const record=(type,data)=>{
  need(records.length<policy.maxRecords,'CarrierLocalRecords');reserveLocal({...zero(),logicalBytes:policy.recordChargeBytes});
  const row={sequence:records.length+1,planHash,previousHash:previous,type,data,spent:{...spent}},raw=Buffer.from(JSON.stringify(row)+'\n');need(raw.length<=policy.recordBytes,'CarrierLocalRecordSize');
  let at=0;while(at<raw.length){const n=writeSync(fd,raw,at,raw.length-at);need(n>0,'CarrierLocalJournal');at+=n;}fsyncSync(fd);records.push(row);recordBytes+=raw.length;previous=hash(row);
 };
 const unknownCleanup=()=>{
  if(!cleanupUnknown){cleanupUnknown=true;held=true;cleanup=true;try{record('cleanup',{status:'unknown',pending:pending.size});}catch{}}
  return Object.assign(Error('CarrierLocalCleanupUnknown'),{code:'ECLEANUP',cleanupStatus:'unknown',cleanupConfirmed:false,counterClosed:false,ownershipRetained:true,operationDirectory:directory});
 };
 const handle=Object.freeze({kind:'carrier-original-local-counter'}),state={directory,plan,policy,configHash,env,checkLocal,reserveLocal,record,
  checkNormal(){need(!cleanup,'CarrierLocalHeld');checkLocal();},
  snapshot:()=>({spent:{...spent},normalRemaining:Math.max(0,policy.logicalBytes-cleanupReserved-spent.logicalBytes),cleanupReserved,cleanupUsed,recordBytes,held,closed,pending:pending.size,cleanupUnknown}),
  evidence(){reserveLocal({...zero(),logicalBytes:4*recordBytes});record('checkpoint',{});return {version:1,kind:'carrier-local-evidence',planHash,grantHash:config.grantHash,policyHash:hash(policy),cleanupReserved,cleanupUsed,spent:{...spent},records:structuredClone(records),lastHash:previous};},
  bind(value){checkLocal();need(!binding&&hash(value.config)===configHash&&value.binding.grantHash===config.grantHash&&value.binding.templateHash===plan.templateHash&&value.binding.runId===Number(env.GITHUB_RUN_ID)&&value.binding.runAttempt===Number(env.GITHUB_RUN_ATTEMPT),'CarrierLocalBinding');record('startup',value.binding);binding=hash(value.binding);},
  consume(value){checkLocal();need(!transferred,'CarrierLocalTransfer');need(binding===hash(value.binding)&&hash(value.config)===configHash,'CarrierLocalBinding');record('transfer',value.binding);transferred=true;return state;},
  cleanup(){need(!closed&&!cleanup,'CarrierLocalCleanup');cleanup=true;abort.abort();record('cleanup',{});},
  capture(fn){checkLocal();need(!draining&&!cleanup,'CarrierLocalHeld');const call=Promise.resolve().then(()=>fn(abort.signal));pending.add(call);call.then(()=>pending.delete(call),()=>pending.delete(call));return call;},
  async drain(){
   abort.abort();if(cleanupUnknown)throw unknownCleanup();if(drainPromise)return drainPromise;if(!pending.size)return;
   draining=true;held=true;
   // One bounded drain belongs to this original counter. Repeated callers
   // cannot renew its cleanup window or turn a late settlement into release.
   drainPromise=(async()=>{let timer;try{
    await Promise.race([Promise.allSettled([...pending]),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('CarrierLocalDrainHeld')),Math.max(1,Math.min(policy.cleanupMs,plan.deadlineMs-now())));})]);
    need(pending.size===0,'CarrierLocalDrainHeld');
   }catch{throw unknownCleanup();}finally{clearTimeout(timer);}})();return drainPromise;
  },
  close({complete=false}={}){if(closed)return;if(pending.size||cleanupUnknown)throw unknownCleanup();try{if(!cleanup)cleanup=true;record('closed',{complete:Boolean(complete)});}finally{closed=true;fsyncSync(fd);closeSync(fd);}},
  hold(){held=true;},
 };
 Object.freeze(state);states.set(handle,state);
 try{
  record('claim',{grantHash:config.grantHash,runId:Number(env.GITHUB_RUN_ID),runAttempt:Number(env.GITHUB_RUN_ATTEMPT)});
  reserveLocal({...zero(),logicalBytes:policy.recordChargeBytes});const claim=openSync(join(directory,'claim.json'),'wx',0o600);
  try{writeSync(claim,JSON.stringify({version:1,planHash,grantHash:config.grantHash,configHash,runId:Number(env.GITHUB_RUN_ID),runAttempt:Number(env.GITHUB_RUN_ATTEMPT)}));fsyncSync(claim);}finally{closeSync(claim);}
  // Persist both names before capture, so a restart cannot lose the claim's
  // directory entry after its file contents were flushed.
  for(const name of [directory,root]){const dir=openSync(name,'r');try{fsyncSync(dir);}finally{closeSync(dir);}}
  return handle;
 }catch(e){state.close();throw e;}
}
export function carrierLocalState(handle){const s=states.get(handle);need(s,'CarrierLocalOriginal');return s;}
export const bindCarrierLocalStartup=(handle,value)=>carrierLocalState(handle).bind(value);
export const consumeCarrierLocalCounter=(handle,value)=>carrierLocalState(handle).consume(value);
export const beginCarrierLocalCleanup=handle=>carrierLocalState(handle).cleanup();
export const closeCarrierLocalCounter=(handle,value)=>carrierLocalState(handle).close(value);
export const drainCarrierLocalCounter=handle=>carrierLocalState(handle).drain();

export function carrierLocalHost(handle,host){
 const s=carrierLocalState(handle);need(host?.env===s.env&&typeof host.run==='function','CarrierLocalHost');
 const run=async(program,args,options={})=>{
  s.checkNormal();const maxBytes=options.maxBytes??s.policy.captureBytes;
  need(['git','gh'].includes(program)&&Array.isArray(args)&&args.every(a=>typeof a==='string'&&!a.includes('\0'))&&Number.isSafeInteger(maxBytes)&&maxBytes>0&&maxBytes<=s.policy.captureBytes,'CarrierLocalCommand');
  need(Object.keys(options).every(k=>['maxBytes','timeoutMs','encoding'].includes(k))&&(!options.timeoutMs||Number.isSafeInteger(options.timeoutMs)&&options.timeoutMs>0&&options.timeoutMs<=30000)&&(!options.encoding||['utf8','buffer'].includes(options.encoding)),'CarrierLocalCommand');
  s.reserveLocal({...zero(),logicalBytes:2*s.policy.commandArgumentBytes});need(Buffer.byteLength(JSON.stringify(args))<=s.policy.commandArgumentBytes,'CarrierLocalArguments');
  // execFile bounds stdout and stderr separately. Both are paid before spawn;
  // neither a short response nor a failed command refunds this reservation.
  s.reserveLocal({...zero(),logicalBytes:2*maxBytes});s.record('capture',{program,requestHash:hash(args),maxBytes});
  try{const value=await s.capture(signal=>(host.runBounded??host.run)(program,args,{...options,maxBytes,...(host.runBounded?{signal}:{})}));s.checkNormal();need(typeof value==='string'||value instanceof Uint8Array,'CarrierLocalCapture');const length=Buffer.byteLength(value);need(length<=maxBytes,'CarrierLocalCapture');s.reserveLocal({...zero(),logicalBytes:4*length});s.record('captured',{bytes:length,sha256:sha(value)});return value;}
  catch(e){try{s.record('capture-failed',{});}finally{s.hold();}throw e;}
 };
 const api=async path=>{
  need(typeof path==='string'&&/^[A-Za-z0-9_./?=&%+-]+$/.test(path)&&!path.includes('..')&&!path.startsWith('/'),'CarrierLocalGithubPath');
  const raw=await run('gh',['api','--hostname','github.com','repos/'+s.plan.template.source.repository+'/'+path],{encoding:'buffer'});
  s.reserveLocal({...zero(),logicalBytes:4*Buffer.byteLength(raw)});return parseCiSmokeJson(Buffer.from(raw).toString('utf8'));
 };
 const checkout=async()=>{
  await run('git',['diff','--quiet']);await run('git',['diff','--cached','--quiet']);
  const revision=String(await run('git',['rev-parse','HEAD'])).trim(),tree=String(await run('git',['rev-parse','HEAD^{tree}'])).trim();
  need(revision===s.plan.template.source.candidateRevision&&tree===s.plan.template.source.candidateTree,'CarrierLocalCheckout');return {revision,tree};
 };
 return {env:host.env,run,api,checkout};
}
