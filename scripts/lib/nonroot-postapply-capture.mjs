import {createHash} from 'node:crypto';
import {mkdir,lstat,realpath,open} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {constants} from 'node:fs';
import {smokePrivateRead,smokePrivateWrite} from './ci-smoke-host.mjs';
import {inspectFutureAcquisitionConfig} from './ci-smoke-future-config.mjs';
import {nonrootHash as hash,parseNonrootJson} from './production-nonroot-contracts.mjs';
import {NONROOT_POSTAPPLY_LIMITS as L,NONROOT_POSTAPPLY_FUNCTIONS as FUNCTIONS,NONROOT_POSTAPPLY_SOURCE_PATHS as SOURCE,NONROOT_POSTAPPLY_POLICY_HASH,encodeNonrootPostApplyArtifact,inspectNonrootPostApplyIdentity,projectNonrootPostApplyEnvironment} from './nonroot-postapply.mjs';

const need=(v,c)=>{if(!v)throw Error(c);},sha=b=>createHash('sha256').update(b).digest('hex');
const parse=b=>parseNonrootJson(b.toString('utf8'));
const COUNTERS=['ecrRequests','logicalBytes','httpBodyBytes','uncompressedBytes','processedEntries'];
const counter=v=>{need(v&&Object.keys(v).sort().join()===COUNTERS.toSorted().join()&&COUNTERS.every(k=>Number.isSafeInteger(v[k])&&v[k]>=0),'PostApplyLocalCounters');return v;};
// The existing 96 MiB payment contains both stages. Completion can always
// re-read the original 32 MiB native journal; capture cannot spend its reserve.
const STAGES=Object.freeze({capture:L.captureWorkBytes,complete:L.completionWorkBytes});
function localStage(stage){let used=0;const operations=[];return {stage,get used(){return used;},operations,charge(bytes,purpose){need(Number.isSafeInteger(bytes)&&bytes>=0&&used+bytes<=STAGES[stage],'PostApplyLocalBudget');used+=bytes;operations.push({purpose,bytes});},async read(path,max=65536){const {raw}=await readOwnedFile(path,max,n=>this.charge(n,'read:'+path.split('/').at(-1)),1,true);return raw;},async write(path,value){const raw=Buffer.isBuffer(value)?value:Buffer.from(JSON.stringify(value)+'\n');this.charge(raw.length,'write:'+path.split('/').at(-1));return smokePrivateWrite(path,raw);}};}

async function directory(env,create=false){
 need(typeof env.RUNNER_TEMP==='string'&&resolve(env.RUNNER_TEMP)===env.RUNNER_TEMP&&await realpath(env.RUNNER_TEMP)===env.RUNNER_TEMP,'PostApplyDirectory');
 const path=join(env.RUNNER_TEMP,'mem9-nonroot-deployment');if(create)await mkdir(path,{mode:0o700});
 const s=await lstat(path);need(s.isDirectory()&&!s.isSymbolicLink()&&s.uid===process.getuid()&&(s.mode&511)===448&&await realpath(path)===path,'PostApplyDirectory');return path;
}
export function postApplyIdentity(config,binding){return {repository:binding.source.repository,runId:binding.source.runId,runAttempt:binding.source.runAttempt,jobKey:'deploy-prod',revision:binding.source.mainRevision,tree:binding.source.mainTree,grantSetId:config.startup.grantSetId,descriptorHash:config.startup.descriptorHash,proofHash:config.startup.proofHash};}

/** Called by the successful, native /19 LOCAL replay after charging its fixed
 * capture allocation. No network method, new deadline, refund or retry. */
export async function writePostApplyCaptureAllocation({env,config,binding,scope,localRef,claimRef,localBudget,localUsed,expiresMs}){
 need(config.version===3&&scope.checkpoint==='deploy-prod/19'&&scope.phase==='presst'&&scope.route==='deploy-prod'&&env.GITHUB_JOB==='deploy-prod','PostApplyAllocationScope');
 const dir=await directory(env,true),value={version:1,kind:'prepaid-sst-capture-local',policyHash:NONROOT_POSTAPPLY_POLICY_HASH,source:postApplyIdentity(config,binding),configHash:sha(env.MEM9_CI_ACQUISITION_CONFIG),localRef,claimRef,bindingHash:hash(binding),localBudget:counter(localBudget),localUsed:counter(localUsed),localBytes:L.captureLocalBytes,expiresMs};
 need(STAGES.capture+STAGES.complete===L.captureLocalBytes,'PostApplyLocalBudget');const raw=Buffer.from(JSON.stringify(value)+'\n');need(raw.length<=65536,'PostApplyAllocationSize');await smokePrivateWrite(join(dir,'allocation.json'),raw);return value;
}
async function readPostApplyCaptureAllocation(env,meter){
 need(meter,'PostApplyLocalMeter');
 const config=inspectFutureAcquisitionConfig(parse(Buffer.from(env.MEM9_CI_ACQUISITION_CONFIG??''))),dir=await directory(env),allocationRaw=await meter.read(join(dir,'allocation.json'),65536),a=parse(allocationRaw);
 if(meter.stage==='capture')meter.charge(allocationRaw.length,'original-allocation-write');
 need(a.kind==='prepaid-sst-capture-local'&&a.policyHash===NONROOT_POSTAPPLY_POLICY_HASH&&a.localBytes===L.captureLocalBytes&&a.configHash===sha(env.MEM9_CI_ACQUISITION_CONFIG)&&Date.now()<a.expiresMs,'PostApplyAllocation');
 need(a.source.jobKey===env.GITHUB_JOB&&env.GITHUB_JOB==='deploy-prod'&&a.source.repository===env.GITHUB_REPOSITORY&&a.source.runId===Number(env.GITHUB_RUN_ID)&&a.source.runAttempt===Number(env.GITHUB_RUN_ATTEMPT)&&a.source.revision===env.GITHUB_SHA&&env.GITHUB_WORKFLOW_SHA===env.GITHUB_SHA&&env.GITHUB_EVENT_NAME==='push'&&env.GITHUB_REF==='refs/heads/main'&&a.source.tree===config.startup.source.candidateTree&&a.source.grantSetId===config.startup.grantSetId&&a.source.descriptorHash===config.startup.descriptorHash&&a.source.proofHash===config.startup.proofHash,'PostApplyAllocationIdentity');
 const refs={};for(const [key,ref]of Object.entries({local:a.localRef,claim:a.claimRef})){
  need(typeof ref.path==='string'&&ref.path.startsWith(join(env.RUNNER_TEMP,'mem9-ci-future-acquisitions')+'/')&&ref.path.endsWith(key==='local'?'-local-replay-sst.ndjson':'-local-replay-sst-claim.json'),'PostApplyAllocationReceipt');
  const raw=await meter.read(ref.path,key==='local'?33554432:65536);need(sha(raw)===ref.sha256,'PostApplyAllocationReceipt');refs[key]=raw;
 }
 const claim=parse(refs.claim);need(claim.kind==='ci-future-local-replay'&&claim.scope.checkpoint==='deploy-prod/19'&&claim.scope.phase==='presst'&&claim.scope.route==='deploy-prod'&&claim.expiresMs===a.expiresMs&&claim.ownerRefund===0,'PostApplyAllocationReceipt');
 const prefix=join(env.RUNNER_TEMP,'mem9-ci-future-acquisitions','target-'+hash({bindingHash:a.bindingHash,scope:claim.scope})+'-local-replay-sst');need(a.localRef.path===prefix+'.ndjson'&&a.claimRef.path===prefix+'-claim.json','PostApplyAllocationReceipt');
 const raw=refs.local.toString();need(raw.endsWith('\n'),'PostApplyAllocationDebit');const lines=raw.slice(0,-1).split('\n');need(lines.length>0&&lines.length<=200000,'PostApplyAllocationDebit');
 const budget=counter(a.localBudget),used={...counter(claim.startingLocalUsed)};need(COUNTERS.every(k=>used[k]<=budget[k]),'PostApplyAllocationDebit');let last;
 for(const line of lines){last=counter(parse(Buffer.from(line)));need(last.ecrRequests===0&&last.httpBodyBytes===0,'PostApplyAllocationDebit');for(const k of COUNTERS){used[k]+=last[k];need(Number.isSafeInteger(used[k])&&used[k]<=budget[k],'PostApplyAllocationDebit');}}
 need(hash(used)===hash(counter(a.localUsed))&&last.logicalBytes===L.captureLocalBytes&&COUNTERS.filter(k=>k!=='logicalBytes').every(k=>last[k]===0),'PostApplyAllocationDebit');
 return {dir,allocation:a,config};
}
async function readOwnedFile(path,max,charge,multiple=1,privateFile=false){
 need(await realpath(path)===path,'PostApplyLocalAlias');const fd=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{const before=await fd.stat();need(before.isFile()&&(!privateFile||(before.mode&511)===384)&&before.uid===process.getuid()&&before.nlink===1&&before.size>0&&before.size<=max,'PostApplyLocalBound');charge(multiple*before.size);const raw=Buffer.alloc(before.size);let at=0;while(at<raw.length){const {bytesRead}=await fd.read(raw,at,raw.length-at,at);need(bytesRead>0,'PostApplyLocalChanged');at+=bytesRead;}const after=await fd.stat(),named=await lstat(path);need(raw.length===before.size&&['dev','ino','size','mtimeMs','ctimeMs'].every(k=>before[k]===after[k]&&before[k]===named[k]),'PostApplyLocalChanged');return {raw,mode:before.mode&73?'100755':'100644'};}finally{await fd.close();}
}

/** Runs inside the reviewed SST program once all selected resource Outputs
 * resolve. Only a digest is returned to SST stdout; the artifact stays private. */
export async function captureSstPostApplyOutputs({env,root,work,functions,resources}){
 const meter=localStage('capture');const owned=await directory(env);await meter.write(join(owned,'capture-intent.json'),{version:1,kind:'one-sst-capture',run:env.GITHUB_RUN_ID,attempt:env.GITHUB_RUN_ATTEMPT});
 const {dir,allocation}=await readPostApplyCaptureAllocation(env,meter);need(resolve(root)===root&&resolve(work)===work&&work===join(root,'.sst'),'PostApplySstRoot');
 const charge=n=>meter.charge(n,'source-or-zip');const sourceFiles=[];
 for(const path of SOURCE){const {raw,mode}=await readOwnedFile(join(root,path),1048576,charge,3);sourceFiles.push({path,mode,oid:createHash('sha1').update('blob '+raw.length+'\0').update(raw).digest('hex'),sha256:sha(raw)});}
 for(const name of FUNCTIONS){
  const f=functions[name];need(f&&f.environment&&Object.values(f.environment).every(v=>typeof v==='string'),'PostApplyFunction');
  need(!Object.keys(f.environment).some(k=>['MEM9_API_KEY','MEM9_IDENTITY_SIGNING_KEYS','MEM9_TRANSPORT_SIGNING_KEYS','OAUTH_STATE_HMAC_KEY','SLACK_WEBHOOK_URL','AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN'].includes(k)),'PostApplySecretValue');
  f.environment=projectNonrootPostApplyEnvironment(name,f.environment);
  const {raw}=await readOwnedFile(join(work,'artifacts',name,'code.zip'),L.zipBytes,charge);const digest=sha(raw);need(Buffer.from(f.codeSha256,'base64').toString('hex')===digest&&f.s3Key===`assets/${name}-code-${digest}.zip`,'PostApplyActualLambdaZip');f.zip={sha256:digest,bytes:raw.length};
 }
 const value={version:1,kind:'sst-owned-deployment-capture',policyHash:NONROOT_POSTAPPLY_POLICY_HASH,source:allocation.source,sourceFiles,functions,resources,capturedMs:Date.now()};
 const raw=Buffer.from(JSON.stringify(value));need(raw.length<=L.jsonBytes,'PostApplyOutputSize');charge(raw.length*4);need(Date.now()<allocation.expiresMs,'PostApplyExpired');await meter.write(join(dir,'sst-output.json'),raw);await meter.write(join(dir,'capture-accounting.json'),{version:1,allocationHash:hash(allocation),outputHash:sha(raw),stage:'capture',allocatedBytes:STAGES.capture,operations:meter.operations.slice(),usedBeforeReceipt:meter.used});return sha(raw);
}
/** A successful deploy step calls this after SST exits zero. A partial apply
 * cannot produce this create-only completion, and it cannot renew expiry. */
export async function completeSstPostApplyCapture(env){
 if(!env.MEM9_CI_ACQUISITION_CONFIG)return {phase:'postapply-not-selected'};
 const config=inspectFutureAcquisitionConfig(parse(Buffer.from(env.MEM9_CI_ACQUISITION_CONFIG)));if(config.version!==3)return {phase:'postapply-not-selected'};
 const meter=localStage('complete'),owned=await directory(env);await meter.write(join(owned,'complete-intent.json'),{version:1,kind:'one-sst-completion'});
 const {dir,allocation}=await readPostApplyCaptureAllocation(env,meter),raw=await meter.read(join(dir,'sst-output.json'),L.jsonBytes),value=parse(raw),receipt=parse(await meter.read(join(dir,'capture-accounting.json')));
 need(receipt.version===1&&receipt.allocationHash===hash(allocation)&&receipt.outputHash===sha(raw)&&receipt.stage==='capture'&&receipt.allocatedBytes===STAGES.capture&&Array.isArray(receipt.operations)&&receipt.operations.length<=128&&receipt.operations.every(r=>Number.isSafeInteger(r.bytes)&&r.bytes>=0&&typeof r.purpose==='string')&&receipt.usedBeforeReceipt===receipt.operations.reduce((n,r)=>n+r.bytes,0)&&receipt.usedBeforeReceipt<=STAGES.capture,'PostApplyCaptureAccounting');
 need(hash(value.source)===hash(allocation.source)&&value.policyHash===allocation.policyHash&&Date.now()>=value.capturedMs,'PostApplyCompletion');
 const record={...value,completedMs:Date.now()};meter.charge(L.jsonBytes*4,'completion-codec');const artifact=encodeNonrootPostApplyArtifact(record);need(Date.now()<allocation.expiresMs,'PostApplyExpired');await meter.write(join(dir,'complete-accounting.json'),{version:1,allocationHash:hash(allocation),stage:'complete',allocatedBytes:STAGES.complete,usedBeforeReceipt:meter.used,operations:meter.operations.slice()});await meter.write(join(dir,'completed.json'),artifact);return {phase:'postapply-captured',artifactHash:artifact.sha256};
}
export async function readCompletedPostApplyArtifact({env,binding,config,scope,now=Date.now()}){
 const dir=await directory(env),artifact=parse(await smokePrivateRead(join(dir,'completed.json'),16384));
 const {decodeNonrootPostApplyArtifact}=await import('./nonroot-postapply.mjs');const value=decodeNonrootPostApplyArtifact(artifact);inspectNonrootPostApplyIdentity(value,{binding,config,scope,now});return artifact;
}
