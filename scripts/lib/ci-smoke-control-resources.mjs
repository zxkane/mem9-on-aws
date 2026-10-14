/** Ownership of local CI cache/image resources, never deployment authority.
 * Live allocation handles cannot be restored from JSON. Final cleanup uses
 * immutable creation/completion records and only the original private subtree. */
import {randomBytes} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdir,lstat,realpath,readdir,unlink,rmdir} from 'node:fs/promises';
import {join,resolve,relative} from 'node:path';
import {copyNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {controlImageGraphBinding,imageGraphState} from './production-image-graph.mjs';
import {smokePrivateRead,smokePrivateWrite} from './ci-smoke-host.mjs';
import {sha,parseAcquisitionJson} from './ci-smoke-acquisition-format.mjs';

const execute=promisify(execFile),handles=new WeakMap(),MAX=4194304;
const need=(v,code='CiControlResourceInvalid')=>{if(!v)throw Error(code);};
const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join(),'CiControlResourceFields');
const equal=(a,b,code='CiControlResourceBinding')=>need(hash(a)===hash(b),code);
const hex=(v,n=64)=>typeof v==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(v),digest=v=>typeof v==='string'&&/^sha256:[a-f0-9]{64}$/.test(v);
const positive=n=>Number.isSafeInteger(n)&&n>0;
const completionVersion=c=>c.version===2?!Object.hasOwn(c,'rootExchangeRef'):c.version===3&&c.rootExchangeRef&&Object.keys(c.rootExchangeRef).sort().join()==='path,sha256'&&hex(c.rootExchangeRef.sha256)&&typeof c.claimRef?.path==='string'&&c.rootExchangeRef.path===c.claimRef.path.replace(/-claim\.json$/,'-root-exchange-complete.json');
const loaderNames=stream=>stream?['index.json','oci-layout']:['index.json','oci-layout','image.tar'];
function streamTransport(value,cache,files){
 exact(value,['kind','archiveBytes','blobBytes']);need(value.kind==='oci-tar-stdin','CiControlResourceTransport');
 equal(files.map(f=>f.path.split('/').at(-1)).sort(),loaderNames(true).sort(),'CiControlResourceTransport');
 const blobBytes=cache.files.reduce((n,f)=>n+f.size,0),archiveBytes=[...cache.files,...files].reduce((n,f)=>n+512+Math.ceil(f.size/512)*512,1024);
 need(value.blobBytes===blobBytes&&value.archiveBytes===archiveBytes&&Number.isSafeInteger(archiveBytes),'CiControlResourceTransport');return copyNonrootJson(value);
}
const freeze=v=>{if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;};
const read=async ref=>{exact(ref,['path','sha256']);need(hex(ref.sha256),'CiControlResourceRef');const raw=await smokePrivateRead(ref.path,MAX);need(sha(raw)===ref.sha256,'CiControlResourceHash');return parseAcquisitionJson(raw,MAX);};
const save=async(root,name,value)=>{const path=join(root,name);return {path,sha256:await smokePrivateWrite(path,value)};};
const fileIdentity=s=>({dev:String(s.dev),ino:String(s.ino),size:Number(s.size),uid:Number(s.uid),mode:Number(s.mode)&511,nlink:Number(s.nlink),mtimeNs:String(s.mtimeNs),ctimeNs:String(s.ctimeNs)});
const dirIdentity=s=>({dev:String(s.dev),ino:String(s.ino),uid:Number(s.uid),mode:Number(s.mode)&511});
async function directory(path){need(typeof path==='string'&&resolve(path)===path&&await realpath(path)===path,'CiControlResourcePath');const s=await lstat(path,{bigint:true});need(s.isDirectory()&&!s.isSymbolicLink()&&Number(s.uid)===process.getuid()&&(Number(s.mode)&511)===0o700,'CiControlResourceDirectory');return dirIdentity(s);}
async function file(root,path){need(path.startsWith(root+'/')&&await realpath(path)===path,'CiControlResourcePath');const s=await lstat(path,{bigint:true});need(s.isFile()&&!s.isSymbolicLink()&&Number(s.uid)===process.getuid()&&(Number(s.mode)&511)===0o600&&s.nlink===1n&&s.size<=BigInt(Number.MAX_SAFE_INTEGER),'CiControlResourceFile');return {path:relative(root,path),...fileIdentity(s)};}
async function snapshot(root,dir,names){await directory(dir);equal((await readdir(dir)).sort(),[...names].sort(),'CiControlResourceUnknownFile');const rows=[];for(const name of [...names].sort())rows.push(await file(root,join(dir,name)));return rows;}
function job(env){need(env.GITHUB_ACTIONS==='true'&&typeof env.GITHUB_REPOSITORY==='string'&&/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(env.GITHUB_REPOSITORY)&&hex(env.GITHUB_SHA,40)&&positive(Number(env.GITHUB_RUN_ID))&&positive(Number(env.GITHUB_RUN_ATTEMPT)),'CiControlResourceJob');return {repository:env.GITHUB_REPOSITORY,runId:Number(env.GITHUB_RUN_ID),runAttempt:Number(env.GITHUB_RUN_ATTEMPT),jobKey:env.GITHUB_JOB,revision:env.GITHUB_SHA};}
async function base(env,{create=false}={}){await directoryRoot(env.RUNNER_TEMP);const path=join(env.RUNNER_TEMP,'mem9-control-resources');if(create)try{await mkdir(path,{mode:0o700});}catch(e){if(e.code!=='EEXIST')throw e;}await directory(path);return path;}
async function directoryRoot(path){need(typeof path==='string'&&resolve(path)===path&&await realpath(path)===path,'CiControlResourceRoot');const s=await lstat(path);need(s.isDirectory()&&!s.isSymbolicLink()&&s.uid===process.getuid()&&(s.mode&0o022)===0,'CiControlResourceRoot');}
function expectedRecord(raw){const e=copyNonrootJson(raw);exact(e,['claimRef','scope','bindingHash','sourceReceiptRef','configHash','run','rootDigest','configDigest']);exact(e.scope,['kind','jobKey','route','phase','checkpoint']);exact(e.run,['repository','runId','runAttempt','jobKey','revision']);need(e.scope.kind==='target'&&e.scope.jobKey===e.run.jobKey&&e.scope.route===e.run.jobKey&&['deploy-prod','runtime-cutover-prod'].includes(e.run.jobKey)&&['preupdate','preconfigure','presst','prereadiness'].includes(e.scope.phase)&&typeof e.scope.checkpoint==='string'&&e.scope.checkpoint.startsWith(e.scope.route+'/')&&hex(e.bindingHash)&&hex(e.configHash)&&digest(e.rootDigest)&&digest(e.configDigest),'CiControlResourceBinding');return e;}
function rootFor(env,e){return join(env.RUNNER_TEMP,'mem9-control-resources',hash({bindingHash:e.bindingHash,scope:e.scope}));}
async function validateExpected(env,e,{requireSource=true}={}){equal(job(env),e.run,'CiControlResourceJob');need(typeof env.MEM9_CI_ACQUISITION_CONFIG==='string'&&sha(env.MEM9_CI_ACQUISITION_CONFIG)===e.configHash,'CiControlResourceConfig');const claim=await read(e.claimRef);need(claim.version===1&&claim.kind==='ci-future-acquisition-claim'&&claim.configHash===e.configHash&&hash(claim.binding)===e.bindingHash&&claim.ownerRefund===0,'CiControlResourceClaim');equal(claim.scope,e.scope);equal(claim.sourceReceiptRef,e.sourceReceiptRef);if(requireSource)await read(e.sourceReceiptRef);need(e.claimRef.path===join(env.RUNNER_TEMP,'mem9-ci-future-acquisitions','target-'+hash({bindingHash:e.bindingHash,scope:e.scope})+'-claim.json'),'CiControlResourceClaimPath');return claim;}
async function live(handle){const s=handles.get(handle);need(s&&!s.sealed&&!s.outcome?.outcome?.match(/^(failed|unknown)$/),'CiControlResourceHandle');await validateExpected(s.env,s.allocation.expected);equal(await directory(s.root),s.allocation.rootIdentity);equal(await directory(s.tempRoot),s.allocation.workIdentity);return s;}
async function nativeDocker(args,{directory:cwd}){
 need(args.length===3&&args[0]==='image'&&['inspect','rm'].includes(args[1])&&/^mem9-control-check:[a-f0-9]{32}$/.test(args[2]),'CiControlResourceDockerScope');
 try{const r=await execute('/usr/bin/docker',['--host','unix:///var/run/docker.sock','--config',cwd,...args],{cwd,env:{PATH:'/usr/bin:/bin',HOME:cwd,DOCKER_CONFIG:cwd,LANG:'C',LC_ALL:'C'},encoding:'utf8',timeout:30000,maxBuffer:1048576,killSignal:'SIGKILL'});return {status:0,stdout:r.stdout,stderr:r.stderr};}
 catch(e){if(e.killed||e.signal||e.code==='ERR_CHILD_PROCESS_STDIO_MAXBUFFER')throw Error('CiControlResourceNativeUnknown');if(Number.isInteger(e.code)&&e.code>0&&e.code<=255)return {status:e.code,stdout:e.stdout??'',stderr:e.stderr??''};throw Error('CiControlResourceNativeUnknown');}
}
async function inspect(docker,a,loaderDirectory){const r=await docker(['image','inspect',a.tag],{directory:loaderDirectory});need(r&&Number.isInteger(r.status)&&typeof r.stdout==='string'&&typeof r.stderr==='string'&&Buffer.byteLength(r.stdout)+Buffer.byteLength(r.stderr)<=1048576,'CiControlResourceDockerResponse');if(r.status===1&&r.stderr.trim().endsWith('No such image: '+a.tag))return null;need(r.status===0,'CiControlResourceDockerInspect');const rows=parseAcquisitionJson(Buffer.from(r.stdout),1048576);need(Array.isArray(rows)&&rows.length===1,'CiControlResourceDockerImage');const i=rows[0],e=a.expected;need(i.Os==='linux'&&i.Architecture==='arm64'&&Array.isArray(i.RepoTags)&&i.RepoTags.includes(a.tag),'CiControlResourceDockerImage');need(i.Id===e.rootDigest&&i.Descriptor?.digest===e.rootDigest||i.Id===e.configDigest&&i.RepoDigests?.some(d=>typeof d==='string'&&d.endsWith('@'+e.rootDigest)),'CiControlResourceDockerImage');return {imageId:i.Id,rootDigest:e.rootDigest,configDigest:e.configDigest,tag:a.tag};}

export async function allocateCiSmokeControlResources({env,expected},seams={}){
 exact(seams,Object.keys(seams));need(Object.keys(seams).every(k=>['docker','now'].includes(k)),'CiControlResourceSeam');const e=expectedRecord(expected),claim=await validateExpected(env,e),now=seams.now??Date.now,createdMs=now();need(positive(createdMs)&&createdMs>=claim.openedMs&&createdMs<claim.expiresMs,'CiControlResourceExpired');
 await base(env,{create:true});const root=rootFor(env,e),tempRoot=join(root,'work');await mkdir(root,{mode:0o700});await mkdir(tempRoot,{mode:0o700});
 const tag='mem9-control-check:'+randomBytes(16).toString('hex'),allocation={version:1,kind:'ci-control-resource-allocation',expected:e,scopeHash:hash({bindingHash:e.bindingHash,scope:e.scope}),root,tempRoot,tag,createdMs,rootIdentity:await directory(root),workIdentity:await directory(tempRoot)};
 const allocationRef=await save(root,'allocation.json',allocation),handle=Object.freeze({kind:'ci-control-resource-allocation'});
 handles.set(handle,{env,root,tempRoot,allocation,allocationRef,now,docker:seams.docker??nativeDocker,sealed:false});return Object.freeze({handle,root,tempRoot,tag});
}
/** Only a live allocator handle can select the cache subtree and Docker tag.
 * Returning these identifiers supplies no deployment or reader authority. */
export async function inspectAllocatedControlResources(handle){
 const s=await live(handle),a=s.allocation;
 return copyNonrootJson({tempRoot:a.tempRoot,tag:a.tag,rootDigest:a.expected.rootDigest,configDigest:a.expected.configDigest});
}
export async function registerControlCache(handle,{graph,cacheDirectory,startedMs,completedMs}){
 const s=await live(handle);need(!s.cache,'CiControlResourceCacheDuplicate');const b=controlImageGraphBinding(graph),state=imageGraphState(graph),e=s.allocation.expected;
 need(state.side==='control'&&b.repositoryName==='mem9-on-aws/bootstrap'&&b.rootDigest===e.rootDigest&&b.configDigest===e.configDigest,'CiControlResourceGraph');
 const rel=relative(s.tempRoot,cacheDirectory);need(/^mem9-control-download-[A-Za-z0-9]{6}\/blobs$/.test(rel),'CiControlResourceCachePath');need(positive(startedMs)&&startedMs>=s.allocation.createdMs&&completedMs>=startedMs&&completedMs<=s.now(),'CiControlResourceTime');
 const nodes=graph.inventory.nodes;need(nodes.length>0&&nodes.length<=2176&&new Set(nodes.map(n=>n.digest)).size===nodes.length,'CiControlResourceInventory');const files=await snapshot(s.root,cacheDirectory,nodes.map(n=>n.digest.slice(7)));
 for(const row of files){const node=nodes.find(n=>n.digest.slice(7)===row.path.split('/').at(-1));need(node&&row.size===node.size,'CiControlResourceInventory');}
 const downloadDirectory=resolve(cacheDirectory,'..');s.cache={directory:cacheDirectory,downloadDirectory,inventory:copyNonrootJson(graph.inventory),inventoryHash:hash(graph.inventory),rootDigest:e.rootDigest,files,downloadIdentity:await directory(downloadDirectory),cacheIdentity:await directory(cacheDirectory),startedMs,completedMs};
 equal(await readdir(downloadDirectory),['blobs'],'CiControlResourceUnknownFile');await save(s.root,'cache.json',s.cache);
}
export async function beginControlImageLoad(handle,{loaderDirectory,transport}){
 const s=await live(handle);need(s.cache&&!s.intent&&!s.loadPending,'CiControlResourceLoadOrder');s.loadPending=true;need(/^mem9-control-docker-[A-Za-z0-9]{6}$/.test(relative(s.tempRoot,loaderDirectory)),'CiControlResourceLoaderPath');
 const streaming=transport!==undefined,files=await snapshot(s.root,loaderDirectory,loaderNames(streaming)),maximum=s.cache.files.reduce((n,f)=>n+f.size,0)+s.cache.files.length*1536+32768;
 if(streaming)transport=streamTransport(transport,s.cache,files);
 need(files.every(f=>f.size<=(f.path.endsWith('/image.tar')?maximum:1048576)),'CiControlResourceLoaderSize');need(!await inspect(s.docker,s.allocation,loaderDirectory),'CiControlResourceTagExists');
 s.intent={version:streaming?2:1,kind:'ci-control-load-intent',allocationRef:s.allocationRef,loaderDirectory,loaderIdentity:await directory(loaderDirectory),files,tag:s.allocation.tag,startedMs:s.now(),...(streaming?{transport}:{})};s.intentRef=await save(s.root,'load-intent.json',s.intent);s.loadPending=false;
}
export async function recordControlImageLoad(handle,{outcome,completedMs}){
 const s=await live(handle);need(s.intent&&!s.outcome&&['loaded','failed','unknown'].includes(outcome)&&positive(completedMs)&&completedMs>=s.intent.startedMs&&completedMs<=s.now(),'CiControlResourceLoadOutcome');
 // Set sticky state before another asynchronous inspection can run.
 s.outcome={outcome};let image=null;
 if(outcome==='loaded'){try{image=await inspect(s.docker,s.allocation,s.intent.loaderDirectory);need(image,'CiControlResourceLoadMissing');}catch(e){s.outcome={outcome:'unknown'};await save(s.root,'load-outcome.json',{version:1,kind:'ci-control-load-outcome',outcome:'unknown',allocationRef:s.allocationRef,intentRef:s.intentRef,completedMs,image:null});throw e;}}
 const value={version:1,kind:'ci-control-load-outcome',outcome,allocationRef:s.allocationRef,intentRef:s.intentRef,completedMs,image};s.outcome=value;await save(s.root,'load-outcome.json',value);return Object.freeze({outcome});
}
async function checkFiles(root,record){
 equal(await directory(record.cache.downloadDirectory),record.cache.downloadIdentity);equal(await directory(record.cache.directory),record.cache.cacheIdentity);equal(await readdir(record.cache.downloadDirectory),['blobs'],'CiControlResourceUnknownFile');
 equal(await snapshot(root,record.cache.directory,record.cache.files.map(f=>f.path.split('/').at(-1))),record.cache.files,'CiControlResourceFileChanged');equal(await directory(record.docker.loaderDirectory),record.docker.loaderIdentity);
 equal(await snapshot(root,record.docker.loaderDirectory,loaderNames(record.version===2)),record.docker.files,'CiControlResourceFileChanged');
 equal((await readdir(join(root,'work'))).sort(),[record.cache.downloadDirectory.split('/').at(-1),record.docker.loaderDirectory.split('/').at(-1)].sort(),'CiControlResourceUnknownFile');
}
export async function sealControlResources(handle,{bundleRef}){
 const s=await live(handle);need(s.cache&&s.outcome?.kind==='ci-control-load-outcome'&&s.outcome.outcome==='loaded'&&s.outcome.image,'CiControlResourceIncomplete');const bundle=await read(bundleRef);equal(bundle.controlCache,{directory:s.cache.directory,inventory:s.cache.inventory},'CiControlResourceBundle');
 const e=s.allocation.expected,record={version:s.intent.version,kind:'ci-smoke-control-resources',allocationRef:s.allocationRef,claimRef:e.claimRef,scope:e.scope,bindingHash:e.bindingHash,sourceReceiptRef:e.sourceReceiptRef,configHash:e.configHash,run:e.run,bundleRef,
  cache:s.cache,docker:{...s.outcome.image,loaderDirectory:s.intent.loaderDirectory,loaderIdentity:s.intent.loaderIdentity,files:s.intent.files,startedMs:s.intent.startedMs,completedMs:s.outcome.completedMs,...(s.intent.version===2?{transport:s.intent.transport}:{})},createdMs:s.allocation.createdMs,sealedMs:s.now()};
 await checkFiles(s.root,record);need(await inspect(s.docker,s.allocation,s.intent.loaderDirectory),'CiControlResourceLoadMissing');const ref=await save(s.root,'resources.json',record);s.sealed=true;return ref;
}
async function inspectReceipt({env,resourceReceiptRef,expected,completionRef,requireBundle=true},{cleaned=false}={}){
 const r=await read(resourceReceiptRef);exact(r,['version','kind','allocationRef','claimRef','scope','bindingHash','sourceReceiptRef','configHash','run','bundleRef','cache','docker','createdMs','sealedMs']);need([1,2].includes(r.version)&&r.kind==='ci-smoke-control-resources','CiControlResourceReceipt');
 const a=await read(r.allocationRef);exact(a,['version','kind','expected','scopeHash','root','tempRoot','tag','createdMs','rootIdentity','workIdentity']);need(a.version===1&&a.kind==='ci-control-resource-allocation','CiControlResourceAllocation');const e=expectedRecord(a.expected),root=rootFor(env,e);
 need(resourceReceiptRef.path===join(root,'resources.json')&&r.allocationRef.path===join(root,'allocation.json')&&a.root===root&&a.tempRoot===join(root,'work')&&a.scopeHash===hash({bindingHash:e.bindingHash,scope:e.scope})&&/^mem9-control-check:[a-f0-9]{32}$/.test(a.tag),'CiControlResourcePath');
 const rootNames=await readdir(root),required=['allocation.json','cache.json','load-intent.json','load-outcome.json','resources.json',...(cleaned?['completion.json','cleanup-intent.json','cleanup-complete.json']:['work'])];need(required.every(n=>rootNames.includes(n))&&rootNames.every(n=>required.includes(n)||n==='completion.json'),'CiControlResourceUnknownFile');
 await validateExpected(env,e,{requireSource:!cleaned});equal(await directory(root),a.rootIdentity);equal(r.claimRef,e.claimRef);equal(r.scope,e.scope);equal(r.sourceReceiptRef,e.sourceReceiptRef);equal(r.run,e.run);need(r.bindingHash===e.bindingHash&&r.configHash===e.configHash&&r.createdMs===a.createdMs&&r.sealedMs>=r.createdMs,'CiControlResourceBinding');
 exact(r.cache,['directory','downloadDirectory','inventory','inventoryHash','rootDigest','files','downloadIdentity','cacheIdentity','startedMs','completedMs']);exact(r.docker,['imageId','rootDigest','configDigest','tag','loaderDirectory','loaderIdentity','files','startedMs','completedMs',...(r.version===2?['transport']:[])]);
 if(r.version===2)streamTransport(r.docker.transport,r.cache,r.docker.files);
 need(r.cache.inventoryHash===hash(r.cache.inventory)&&r.cache.rootDigest===e.rootDigest&&r.docker.rootDigest===e.rootDigest&&r.docker.configDigest===e.configDigest&&r.docker.tag===a.tag&&[e.rootDigest,e.configDigest].includes(r.docker.imageId),'CiControlResourceImage');
 need(/^mem9-control-download-[A-Za-z0-9]{6}\/blobs$/.test(relative(a.tempRoot,r.cache.directory))&&r.cache.downloadDirectory===resolve(r.cache.directory,'..')&&/^mem9-control-docker-[A-Za-z0-9]{6}$/.test(relative(a.tempRoot,r.docker.loaderDirectory)),'CiControlResourcePath');
 const local=async name=>parseAcquisitionJson(await smokePrivateRead(join(root,name),MAX),MAX),cache=await local('cache.json'),intent=await local('load-intent.json'),outcome=await local('load-outcome.json');
 equal(cache,r.cache,'CiControlResourceCacheChanged');exact(intent,['version','kind','allocationRef','loaderDirectory','loaderIdentity','files','tag','startedMs',...(r.version===2?['transport']:[])]);need(intent.version===r.version&&intent.kind==='ci-control-load-intent','CiControlResourceLoadHeld');equal(intent.allocationRef,r.allocationRef);
 for(const k of ['loaderDirectory','loaderIdentity','files','tag','startedMs',...(r.version===2?['transport']:[])])equal(intent[k],r.docker[k],'CiControlResourceLoadChanged');
 exact(outcome,['version','kind','outcome','allocationRef','intentRef','completedMs','image']);need(outcome.version===1&&outcome.kind==='ci-control-load-outcome'&&outcome.outcome==='loaded'&&outcome.completedMs===r.docker.completedMs,'CiControlResourceLoadHeld');equal(outcome.allocationRef,r.allocationRef);equal(outcome.intentRef,{path:join(root,'load-intent.json'),sha256:sha(await smokePrivateRead(join(root,'load-intent.json'),MAX))});equal(outcome.image,Object.fromEntries(['imageId','rootDigest','configDigest','tag'].map(k=>[k,r.docker[k]])));
 need(r.cache.startedMs>=r.createdMs&&r.cache.completedMs>=r.cache.startedMs&&r.docker.startedMs>=r.cache.completedMs&&r.docker.completedMs>=r.docker.startedMs&&r.sealedMs>=r.docker.completedMs,'CiControlResourceTime');
 const inventory=r.cache.inventory,nodes=inventory.nodes;need(inventory.kind==='readonly-control-image-graph'&&inventory.roots?.length===1&&inventory.roots[0].component==='bootstrap'&&inventory.roots[0].repositoryName==='mem9-on-aws/bootstrap'&&inventory.roots[0].root.digest===e.rootDigest,'CiControlResourceInventory');
 need(Array.isArray(nodes)&&nodes.length>0&&nodes.length<=2176&&nodes.every(n=>digest(n.digest)&&Number.isSafeInteger(n.size)&&n.size>=0)&&nodes.some(n=>n.digest===e.configDigest)&&r.cache.files.length===nodes.length&&new Set(nodes.map(n=>n.digest)).size===nodes.length,'CiControlResourceInventory');
 equal(r.cache.files.map(f=>[f.path,f.size]).sort(),nodes.map(n=>[relative(root,join(r.cache.directory,n.digest.slice(7))),n.size]).sort(),'CiControlResourceInventory');
 if(expected){const {bundleRef,controlCache,...binding}=expected;equal(binding,e,'CiControlResourceExpected');equal(bundleRef,r.bundleRef);equal(controlCache,{directory:r.cache.directory,inventory:r.cache.inventory});}
 if(requireBundle){const b=await read(r.bundleRef);equal(b.controlCache,{directory:r.cache.directory,inventory:r.cache.inventory},'CiControlResourceBundle');}
 if(completionRef){const link=await local('completion.json');exact(link,['version','kind','resourceReceiptRef','completionRef','linkedMs']);need(link.version===1&&link.kind==='ci-control-completion-link','CiControlResourceCompletion');equal(link.resourceReceiptRef,resourceReceiptRef);equal(link.completionRef,completionRef);const c=await read(completionRef);need(completionVersion(c)&&c.kind==='ci-future-acquisition-complete'&&c.ownerRefund===0&&c.completedMs>=r.sealedMs&&link.linkedMs>=c.completedMs&&completionRef.path===r.claimRef.path.replace(/-claim\.json$/,'-complete.json'),'CiControlResourceCompletion');equal(c.resourceReceiptRef,resourceReceiptRef);equal(c.claimRef,r.claimRef);equal(c.bundleRef,r.bundleRef);}
 if(!cleaned)await checkFiles(root,r);return {record:r,allocation:a,root};
}
export async function verifyControlResources(input){return (await inspectReceipt(input)).record;}
export async function linkControlResourceCompletion({env,resourceReceiptRef,completionRef}){
 const {record:r,root}=await inspectReceipt({env,resourceReceiptRef}),c=await read(completionRef);need(completionVersion(c)&&c.kind==='ci-future-acquisition-complete'&&c.ownerRefund===0&&c.completedMs>=r.sealedMs,'CiControlResourceCompletion');equal(c.resourceReceiptRef,resourceReceiptRef);equal(c.claimRef,r.claimRef);equal(c.bundleRef,r.bundleRef);need(completionRef.path===r.claimRef.path.replace(/-claim\.json$/,'-complete.json'),'CiControlResourceCompletion');
 return save(root,'completion.json',{version:1,kind:'ci-control-completion-link',resourceReceiptRef,completionRef,linkedMs:Date.now()});
}
const metadataNames=['allocation.json','cache.json','load-intent.json','load-outcome.json','resources.json','completion.json'];
/** Explicit final job cleanup only. A failed/unknown/unsealed load is retained;
 * this function cannot recreate authority or retry an uncertain deletion. */
export async function cleanupCiSmokeControlResources({env},seams={}){
 need(Object.keys(seams).every(k=>k==='docker'),'CiControlResourceSeam');let parent;try{parent=await base(env);}catch(e){if(e.code==='ENOENT')return {phase:'ci-control-resources-absent',cleaned:[]};throw e;}
 const own=job(env),cleaned=[],held=[],docker=seams.docker??nativeDocker;
 for(const name of await readdir(parent)){
  if(!hex(name)){held.push(name);continue;}const root=join(parent,name);
  try{
   await directory(root);const allocationRaw=await smokePrivateRead(join(root,'allocation.json'),MAX),allocation=parseAcquisitionJson(allocationRaw,MAX);
   const run=allocation.expected?.run;if(!run||run.repository!==own.repository||run.runId!==own.runId||run.runAttempt!==own.runAttempt||run.jobKey!==own.jobKey)continue;
   need(run.revision===own.revision,'CiControlResourceJob');
   const names=await readdir(root);if(names.includes('cleanup-complete.json')){
    // Source/bundle files may already have been disposed. Authenticate the
    // immutable completion chain; a marker alone never proves cleanup.
    const local=async name=>parseAcquisitionJson(await smokePrivateRead(join(root,name),MAX),MAX),link=await local('completion.json');
    const {record:r,allocation:a}=await inspectReceipt({env,resourceReceiptRef:link.resourceReceiptRef,completionRef:link.completionRef,requireBundle:false},{cleaned:true}),intent=await local('cleanup-intent.json'),done=await local('cleanup-complete.json');
    exact(intent,['version','kind','resourceReceiptRef','completionRef','tag','startedMs']);exact(done,['version','kind','resourceReceiptRef','completionRef','completedMs']);
    need(intent.version===1&&intent.kind==='ci-control-cleanup-intent'&&done.version===1&&done.kind==='ci-control-cleanup-complete','CiControlResourceCleanupChanged');
    for(const v of [intent,done]){equal(v.resourceReceiptRef,link.resourceReceiptRef);equal(v.completionRef,link.completionRef);}
    need(intent.tag===a.tag&&positive(intent.startedMs)&&intent.startedMs>=r.sealedMs&&intent.startedMs>=link.linkedMs&&positive(done.completedMs)&&done.completedMs>=intent.startedMs,'CiControlResourceCleanupChanged');continue;
   }
   need(!names.includes('cleanup-intent.json')&&!names.includes('cleanup-held.json'),'CiControlResourceCleanupUnknown');need(names.length===metadataNames.length+1&&names.every(n=>[...metadataNames,'work'].includes(n)),'CiControlResourceIncomplete');
   const link=parseAcquisitionJson(await smokePrivateRead(join(root,'completion.json'),MAX),MAX);exact(link,['version','kind','resourceReceiptRef','completionRef','linkedMs']);need(link.version===1&&link.kind==='ci-control-completion-link','CiControlResourceCompletion');
   const {record:r,allocation:a}=await inspectReceipt({env,resourceReceiptRef:link.resourceReceiptRef,requireBundle:false}),completion=await read(link.completionRef);
   need(completionVersion(completion)&&completion.kind==='ci-future-acquisition-complete'&&completion.ownerRefund===0,'CiControlResourceCompletion');equal(completion.resourceReceiptRef,link.resourceReceiptRef);equal(completion.claimRef,r.claimRef);equal(completion.bundleRef,r.bundleRef);need(link.completionRef.path===r.claimRef.path.replace(/-claim\.json$/,'-complete.json'),'CiControlResourceCompletion');
   const image=await inspect(docker,a,r.docker.loaderDirectory);if(image)need(image.imageId===r.docker.imageId,'CiControlResourceDockerImage');
   await save(root,'cleanup-intent.json',{version:1,kind:'ci-control-cleanup-intent',resourceReceiptRef:link.resourceReceiptRef,completionRef:link.completionRef,tag:a.tag,startedMs:Date.now()});
   if(image){const out=await docker(['image','rm',a.tag],{directory:r.docker.loaderDirectory});need(out.status===0&&!await inspect(docker,a,r.docker.loaderDirectory),'CiControlResourceCleanupUnknown');}
   await checkFiles(root,r);
   // Exact unlink/rmdir only: never rm -r, wildcards, a caller path or image ID.
   for(const row of [...r.cache.files,...r.docker.files]){equal(await file(root,join(root,row.path)),row,'CiControlResourceFileChanged');await unlink(join(root,row.path));}
   await rmdir(r.cache.directory);await rmdir(r.cache.downloadDirectory);await rmdir(r.docker.loaderDirectory);await rmdir(join(root,'work'));
   await save(root,'cleanup-complete.json',{version:1,kind:'ci-control-cleanup-complete',resourceReceiptRef:link.resourceReceiptRef,completionRef:link.completionRef,completedMs:Date.now()});cleaned.push(name);
  }catch{held.push(name);}
 }
 if(held.length)throw Object.assign(Error('CiControlResourceCleanupHeld'),{heldRoots:held,cleaned});return {phase:'ci-control-resources-cleaned',cleaned};
}
