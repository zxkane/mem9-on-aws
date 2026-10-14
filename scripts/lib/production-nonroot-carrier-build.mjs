import {carrierNativeBuildAdmissionBytes} from './ci-carrier-stage-admission.mjs';
/** Fixed offline R9 build. Input/output handles prove local bytes only; this
 * function cannot issue a CI record, grant, registry operation or root permit. */
import {execFile,spawn} from 'node:child_process';
import {promisify} from 'node:util';
import {createHash,randomBytes} from 'node:crypto';
import {open,mkdir,writeFile,lstat,realpath,readdir,readFile,rm} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,resolve} from 'node:path';
import {inspectMaterializedCarrierContext,consumeCarrierBuildContext,verifyMaterializedCarrierContext} from './ci-carrier-context.mjs';
import {controlImageGraphBinding,imageGraphState,IMAGE_MEDIA,validateImageDescriptor,imageDescriptorDataLocalBytes,createPrepaidControlCacheBudget,readCollectedControlImageCache} from './production-image-graph.mjs';
import {inspectImageFilesystem,inspectImageFilesystemEvidence,inspectImageFilesystemFile,inspectImageFilesystemEntries,assertImageFilesystemUncompressedLimit,assertImageFilesystemEntryLimit} from './production-image-filesystem.mjs';
import {parseAcquisitionJson,hash,freeze} from './ci-smoke-acquisition-format.mjs';
import {CARRIER_BUILD_SUPERVISOR_SOURCE} from './production-nonroot-carrier-build-supervisor.mjs';
import {consumeCarrierRuntimeMaterial,inspectCarrierRuntimeMaterial} from './ci-carrier-derived.mjs';
import {IMAGE_TRANSITION_LIMITS as L} from './production-image-transition.mjs';

const execute=promisify(execFile),builds=new WeakMap(),failures=new WeakMap(),need=(v,c='CarrierBuildInvalid')=>{if(!v){const e=Error(c);failures.set(e,c);throw e;}};
const sha=b=>createHash('sha256').update(b).digest('hex'),zero=()=>({ecrRequests:0,httpBodyBytes:0,logicalBytes:0,uncompressedBytes:0,processedEntries:0});
const indexes=new Set([IMAGE_MEDIA.index,IMAGE_MEDIA.dockerIndex]),manifests=new Set([...indexes,IMAGE_MEDIA.manifest,IMAGE_MEDIA.dockerManifest]);
const parse=(b,cap=1048576)=>parseAcquisitionJson(b,cap);
const padded=n=>Math.ceil(n/512)*512;
const held=(directory,proof)=>Object.assign(Error('CarrierBuildOutcomeHeld'),{code:'ECLEANUP',operationDirectory:directory,processStopped:Boolean(proof),...(proof?{termination:proof}:{})});
const imageName=base=>base.account+'.dkr.ecr.'+base.region+'.amazonaws.com/'+base.repositoryName+'@'+base.rootDigest;
const verificationCodes=new Set(['ControlCacheAcquisitionMismatch','ControlCacheDeadline','ControlCacheBudgetOptions','ControlImageBinding','ControlImageConfigBinding','ControlImageScope','ImageRootIndexRequired','ImageUncompressedLimit','ImageFilesystemEntryLimit','ImageDescriptorFields','ImageDescriptorInvalid','ImageManifestFields','ImageManifestSchema','ImageAttestationSubject','ImageArm64Selection','ImageBlobDigest','ImageBlobSize','ImageGraphInvalid','ImageJsonSize','ImageJsonValue','ImageJsonNumber','ImageRuntimeConfig','ImageEmptyConfig','NonrootContractInvalid','NonrootControlCacheFile','NonrootControlCacheGraphChanged','NonrootControlCacheInventory']);

/** Last matching source-policy rule wins. No remote resolver, frontend,
 * registry credentials or daemon registry cache can substitute the OCI input. */
export function carrierBuildSourcePolicy(base,{derived=false}={}){return freeze({rules:[
 {action:'DENY',selector:{identifier:'*'}},
 ...['local://dockerfile','local://context',...(derived?['local://carrier_runtime']:[]),'oci-layout://'+imageName(base)].map(identifier=>({action:'ALLOW',selector:{identifier}})),
]});}

class TarCursor{
 constructor(stream,cap,charge,check){this.iterator=stream[Symbol.asyncIterator]();this.buffer=Buffer.alloc(0);this.at=0;this.count=0;this.cap=cap;this.charge=charge;this.check=check;this.digest=createHash('sha256');}
 async ready(){while(this.at===this.buffer.length){this.check();const n=await this.iterator.next();if(n.done)return false;need(n.value instanceof Uint8Array&&n.value.length<=8388608,'CarrierOciChunk');this.buffer=Buffer.from(n.value);this.at=0;this.count+=this.buffer.length;need(this.count<=this.cap,'CarrierOciArchiveSize');this.charge(this.buffer.length);this.digest.update(this.buffer);if(this.buffer.length)return true;}return true;}
 async *chunks(n){while(n){need(await this.ready(),'CarrierOciTruncated');const k=Math.min(n,this.buffer.length-this.at);yield this.buffer.subarray(this.at,this.at+k);this.at+=k;n-=k;}}
 async read(n){need(n<=1048576,'CarrierOciBuffer');const all=[];for await(const b of this.chunks(n))all.push(Buffer.from(b));return Buffer.concat(all,n);}
 async skip(n){for await(const b of this.chunks(n))need(b.every(c=>c===0),'CarrierOciPadding');}
 async close(){await this.iterator.return?.();}
}
const tarText=b=>{const at=b.indexOf(0);return new TextDecoder('utf-8',{fatal:true}).decode(at<0?b:b.subarray(0,at));};
function tarNumber(b){const text=tarText(b).trim();need(/^[0-7]+$/.test(text),'CarrierOciTarNumber');const n=parseInt(text,8);need(Number.isSafeInteger(n)&&n>=0,'CarrierOciTarNumber');return n;}
async function collectOutput(stream,{directory,bounds,charge,check}){
 const maxNodes=bounds.manifestNodes+bounds.blobNodes,maxArchive=bounds.compressedBytes+maxNodes*1536+1048576+4096;
 const cursor=new TarCursor(stream,maxArchive,charge,check),files=new Map(),seen=new Set();let contentBytes=0;
 try{
  while(true){
   const h=await cursor.read(512);if(h.every(c=>c===0)){need((await cursor.read(512)).every(c=>c===0),'CarrierOciTarEnd');while(await cursor.ready()){await cursor.skip(cursor.buffer.length-cursor.at);}break;}
   let sum=0;for(let i=0;i<512;i++)sum+=i>=148&&i<156?32:h[i];need(sum===tarNumber(h.subarray(148,156)),'CarrierOciTarChecksum');
   need(['ustar','ustar '].includes(tarText(h.subarray(257,263)))&&tarText(h.subarray(345,500))==='','CarrierOciTarFormat');
   const name=tarText(h.subarray(0,100)),type=String.fromCharCode(h[156]||48),size=tarNumber(h.subarray(124,136));
   need(!seen.has(name)&&seen.size<=maxNodes+4,'CarrierOciDuplicate');seen.add(name);
   if(type==='5'){need(['blobs/','blobs/sha256/'].includes(name)&&size===0,'CarrierOciDirectory');continue;}
   need(type==='0'&&/^(?:blobs\/sha256\/[a-f0-9]{64}|index\.json|oci-layout)$/.test(name),'CarrierOciMember');
   need(size>0&&(name.startsWith('blobs/')?size<=bounds.compressedBytes:size<=1048576),'CarrierOciFileSize');
   contentBytes+=size;need(contentBytes<=bounds.compressedBytes+1048576,'CarrierOciContentSize');charge(size);
   const fd=await open(join(directory,name),constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600),digest=createHash('sha256');
   try{for await(const b of cursor.chunks(size)){check();digest.update(b);let offset=0;while(offset<b.length){const r=await fd.write(b,offset,b.length-offset);need(r.bytesWritten>0,'CarrierOciWrite');offset+=r.bytesWritten;}}await fd.sync();}finally{await fd.close();}
   const actual=digest.digest('hex');if(name.startsWith('blobs/'))need(actual===name.slice(13),'CarrierOciBlobHash');files.set(name,{sha256:actual,bytesLength:size});await cursor.skip(padded(size)-size);
  }
  need(files.has('index.json')&&files.has('oci-layout'),'CarrierOciMetadata');return {files,archiveBytes:cursor.count,archiveHash:cursor.digest.digest('hex')};
 }finally{await cursor.close();}
}

function buildProcess({directory,inputHash,deadlineMs,signal,collect}){
 return new Promise((resolve,reject)=>{
  let child,closed=false,collected=false,done=false,problem=false,status,termSignal,output,ackBytes=0,logBytes=0,timer;
  const ack=[],logs=[],logHash=createHash('sha256');let cancelled=false;
  const stop=()=>{problem=true;if(!cancelled&&child?.stdio[4]){cancelled=true;child.stdio[4].end('X');}};
  const finish=()=>{
   if(done||!closed||!collected)return;done=true;clearTimeout(timer);signal?.removeEventListener('abort',stop);child?.stdio[4]?.end();let proof;
   try{if(status===0&&!termSignal){const p=parse(Buffer.concat(ack),4096);
    need(Object.keys(p).sort().join()==='cleanupComplete,killedDescendants,kind,leaderEnded,leaderPid,reaped,reason,signal,status,supervisorPid,version'&&p.version===1&&p.kind==='carrier-offline-build-subreaper-echild'&&p.cleanupComplete===true&&p.supervisorPid===child.pid&&p.leaderEnded===true&&Number.isInteger(p.leaderPid)&&p.leaderPid>1&&Number.isInteger(p.reaped)&&p.reaped>=1&&Number.isInteger(p.killedDescendants)&&p.killedDescendants>=0&&p.killedDescendants<p.reaped,'CarrierBuildTermination');
    need([null,'DockerStdinCancelled','DockerStdinTimeout','DockerDescendantSurvived','DockerSupervisionFault'].includes(p.reason)&&(p.status===null)!==(p.signal===null)&&(p.status===null||Number.isInteger(p.status)&&p.status>=0&&p.status<=255)&&(p.signal===null||/^SIG[A-Z0-9]+$/.test(p.signal)),'CarrierBuildTermination');proof=freeze(p);
   }}catch{problem=true;}
   const digest=logHash.digest('hex'),rawLog=Buffer.concat(logs);
   writeFile(join(directory,'build.log'),rawLog,{mode:0o600,flag:'wx'}).then(()=>{
    if(problem||!proof||proof.reason!==null||proof.status!==0||proof.signal!==null){const error=held(directory,proof);error.diagnostics=Object.freeze({logBytes,logHash:digest});reject(error);}
    else resolve({output,termination:proof,logs:rawLog,logBytes,logHash:digest});
   },()=>reject(held(directory,proof)));
  };
  try{
   signal?.throwIfAborted();need(Date.now()+30000<deadlineMs,'CarrierBuildDeadline');
   child=spawn('/usr/bin/python3',['-I','-B','-c',CARRIER_BUILD_SUPERVISOR_SOURCE,String(process.pid),directory,inputHash],{cwd:directory,env:{PATH:'/usr/bin:/bin',HOME:directory,LANG:'C',LC_ALL:'C'},detached:true,stdio:['ignore','pipe','pipe','pipe','pipe']});
   child.stderr.on('data',b=>{logBytes+=b.length;logHash.update(b);if(logBytes>1048576)stop();else logs.push(Buffer.from(b));});
   child.stdio[3].on('data',b=>{ackBytes+=b.length;if(ackBytes>4096)stop();else ack.push(Buffer.from(b));});child.stdio[4].on('error',()=>{});child.on('error',stop);
   child.on('close',(code,sig)=>{closed=true;status=code;termSignal=sig;finish();});
   timer=setTimeout(stop,Math.min(120000,deadlineMs-Date.now()-30000));signal?.addEventListener('abort',stop,{once:true});if(signal?.aborted)stop();
   collect(child.stdout).then(v=>{output=v;collected=true;finish();},()=>{collected=true;stop();child.stdout.destroy();finish();});
  }catch{closed=!child;collected=true;stop();finish();}
 });
}

function nativeFile(fs,path,pin){
 const f=inspectImageFilesystemFile(fs,path);need(f.sha256===pin&&f.uid===0&&f.gid===0&&(f.mode&0o111)!==0&&(f.mode&0o7022)===0&&f.privilegeAttributes.length===0,'CarrierNativeBaseFile');
 for(const p of [...f.parents,...f.symlinkChain])need(p.uid===0&&p.gid===0&&(p.type==='symlink'||(p.mode&0o7022)===0)&&p.privilegeAttributes.length===0,'CarrierNativeBaseParent');return f;
}
function assertBuiltClosure(filesystem,context,derived){
 const entries=inspectImageFilesystemEntries(filesystem),byPath=new Map(entries.map(r=>['/'+r.path,r]));
 const runtime=derived?.runtimeManifest??context.runtimeManifest,pins=derived?.nativePins??context.nativePins;
 const rows=runtime.files,expected=new Set([...rows.map(r=>r.path),'/carrier/manifest.json']);
 for(const e of entries)if(e.type!=='directory'&&(e.path.startsWith('bootstrap/operator/')||e.path.startsWith('carrier/')))need(expected.has('/'+e.path),'CarrierBuiltExtraMember');
 for(const row of rows){const e=byPath.get(row.path);need(e&&e.type===row.type&&e.mode===row.mode&&e.uid===0&&e.gid===0&&!Object.keys(e.pax??{}).some(k=>k.startsWith('SCHILY.xattr.')),'CarrierBuiltMember');
  if(row.type==='file')need(e.content.sha256===row.sha256&&e.content.size===row.bytes,'CarrierBuiltFileHash');else need(e.link===row.target,'CarrierBuiltLink');
 }
 const manifest=(derived?derived.record.files:context.manifest.files).find(r=>r.path==='rootfs/carrier/manifest.json'),actual=inspectImageFilesystemFile(filesystem,'/carrier/manifest.json');
 need(actual.sha256===manifest.sha256&&actual.size===manifest.bytesLength&&actual.mode===0o444&&actual.uid===0&&actual.gid===0,'CarrierBuiltRuntimeManifest');
 nativeFile(filesystem,'/usr/local/bin/node',pins.nodeSha256);nativeFile(filesystem,'/bin/setpriv',pins.setprivSha256);
 for(const p of ['/carrier','/bootstrap/operator']){const e=byPath.get(p);need(e?.type==='directory'&&e.mode===0o555&&e.uid===0&&e.gid===0,'CarrierBuiltDirectory');}
}

export async function buildCarrierOffline({context:handle,baseGraph,baseFilesystem,metadataReads,tempRoot,signal,derived:derivedHandle}){
 const context=inspectMaterializedCarrierContext(handle),plan=context.plan,t=plan.template,baseBinding=controlImageGraphBinding(baseGraph),state=imageGraphState(baseGraph);
 assertImageFilesystemUncompressedLimit(baseFilesystem,t.bounds.uncompressedBytes);assertImageFilesystemEntryLimit(baseFilesystem,t.bounds.processedEntries);
 const derivedBindings={context:handle,baseGraph,baseFilesystem,metadataReads};
 need(context.manifest.version===2?derivedHandle!==undefined:derivedHandle===undefined,'CarrierDerivedRequired');
 const derived=derivedHandle?await consumeCarrierRuntimeMaterial(derivedHandle,derivedBindings):null,pins=derived?.nativePins??context.nativePins;
 const {graphHash,...base}=baseBinding;need(hash(base)===hash(t.base)&&inspectImageFilesystemEvidence(baseFilesystem).graphHash===graphHash,'CarrierBuildBaseBinding');
 need(state.budget.kind==='prepaid-local-control-cache'&&typeof metadataReads?.reserveLocal==='function'&&(!t.ciLocalPolicy||typeof metadataReads.assertLocalStage==='function'),'CarrierBuildBudget');
 need(process.platform==='linux'&&process.arch==='arm64','CarrierBuildNativeArm64');
 need(resolve(tempRoot)===tempRoot&&await realpath(tempRoot)===tempRoot&&context.directory.startsWith(tempRoot+'/'),'CarrierBuildDirectory');
 nativeFile(baseFilesystem,'/usr/local/bin/node',pins.nodeSha256);nativeFile(baseFilesystem,'/bin/setpriv',pins.setprivSha256);
 const check=()=>{signal?.throwIfAborted();need(Date.now()<plan.deadlineMs,'CarrierBuildExpired');metadataReads.reserveLocal(zero());};
 const charge=n=>{check();metadataReads.reserveLocal({...zero(),logicalBytes:n});};check();
 const directory=join(tempRoot,'mem9-carrier-build-'+randomBytes(16).toString('hex'));await mkdir(directory,{mode:0o700});
 for(const path of ['base','base/blobs','base/blobs/sha256','docker-config','output','output/blobs','output/blobs/sha256'])await mkdir(join(directory,path),{mode:0o700});
 const env={PATH:'/usr/bin:/bin',HOME:directory,DOCKER_CONFIG:join(directory,'docker-config'),LANG:'C',LC_ALL:'C'};let attempted=false,verified,termination,stage='native-prerequisites';
 try{
  const info=await execute('/usr/bin/docker',['--host','unix:///var/run/docker.sock','--config',env.DOCKER_CONFIG,'info','--format','{{json .}}'],{env,cwd:directory,timeout:10000,maxBuffer:1048576,encoding:'buffer'});
  charge(info.stdout.length+info.stderr.length);const identity=parse(info.stdout);need(['arm64','aarch64'].includes(identity.Architecture)&&identity.OSType==='linux','CarrierBuildNativeDaemon');
  await consumeCarrierBuildContext(handle);stage='base-materialization';
  const save=async(path,bytes)=>{charge(bytes.length);await writeFile(join(directory,path),bytes,{flag:'wx',mode:0o600});};
  for(const d of baseGraph.inventory.nodes){
   check();charge(d.size);const fd=await open(join(directory,'base/blobs/sha256',d.digest.slice(7)),constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);let count=0;
   try{for await(const b of state.store.open(d)){check();count+=b.length;need(count<=d.size,'CarrierBuildBaseSize');let offset=0;while(offset<b.length){const r=await fd.write(b,offset,b.length-offset);need(r.bytesWritten>0);offset+=r.bytesWritten;}}need(count===d.size,'CarrierBuildBaseSize');await fd.sync();}finally{await fd.close();}
  }
  const policy=Buffer.from(JSON.stringify(carrierBuildSourcePolicy(base,{derived:!!derived}))),root=state.roots[0].root;
  await save('base/index.json',Buffer.from(JSON.stringify({schemaVersion:2,mediaType:IMAGE_MEDIA.index,manifests:[root]})));await save('base/oci-layout',Buffer.from('{"imageLayoutVersion":"1.0.0"}'));await save('source-policy.json',policy);
  const input={version:1,kind:'fixed-offline-carrier-build',baseImage:imageName(base),baseRootDigest:base.rootDigest,contextDirectory:context.directory,...(derived?{derivedDirectory:derived.materialDirectory}:{}),deadlineMs:plan.deadlineMs,dockerfileHash:t.recipe.dockerfileHash,policyHash:sha(policy)},inputBytes=Buffer.from(JSON.stringify(input));await save('build-input.json',inputBytes);
  // Native build internals have no caller-defined meter. Charge their full
  // declared bound before dispatch: base unpack/write and result traversal,
  // plus context read/write. This is conservative prepaid work, not observed
  // bytes or a refund if BuildKit reuses local content-addressed bytes.
  const contextBytes=context.manifest.files.reduce((n,r)=>n+r.bytesLength,0)+(derived?derived.record.files.reduce((n,r)=>n+r.bytesLength,0):0),baseBytes=baseGraph.inventory.nodes.reduce((n,d)=>n+d.size,0);
  const nativeBound=2*t.bounds.uncompressedBytes+2*contextBytes+baseBytes+2*1048576;
  need(Number.isSafeInteger(nativeBound),'CarrierBuildLocalBound');metadataReads.assertLocalStage?.('build',carrierNativeBuildAdmissionBytes({nativeBound,contextBytes:context.manifest.files.reduce((n,r)=>n+r.bytesLength,0),derivedBytes:derived?derived.record.files.reduce((n,r)=>n+r.bytesLength,0):0}));charge(nativeBound);await verifyMaterializedCarrierContext(handle);if(derived)await inspectCarrierRuntimeMaterial(derivedHandle,derivedBindings);check();
  attempted=true;stage='build-process';const result=await buildProcess({directory,inputHash:sha(inputBytes),deadlineMs:plan.deadlineMs,signal,collect:stream=>collectOutput(stream,{directory:join(directory,'output'),bounds:t.bounds,charge,check})});termination=result.termination;stage='output-metadata';
  const metadataFile=join(directory,'metadata.json'),stat=await lstat(metadataFile);need(stat.isFile()&&!stat.isSymbolicLink()&&stat.uid===process.getuid()&&stat.nlink===1&&stat.size<=1048576,'CarrierBuildMetadata');charge(stat.size);const metadataRaw=await readFile(metadataFile),metadata=parse(metadataRaw);
  const metadataDigest=metadata['containerimage.digest'];need(/^sha256:[a-f0-9]{64}$/.test(metadataDigest),'CarrierBuildMetadata');
  const metadataInlineCost=imageDescriptorDataLocalBytes(metadata['containerimage.descriptor']);if(metadataInlineCost)charge(metadataInlineCost);
  validateImageDescriptor(metadata['containerimage.descriptor'],'manifest');need(metadata['containerimage.descriptor'].digest===metadataDigest,'CarrierBuildMetadata');
  const read=async(name,cap)=>{const file=result.output.files.get(name);need(file&&file.bytesLength<=cap,'CarrierBuildOutputFile');charge(file.bytesLength);const b=await readFile(join(directory,'output',name));need(b.length===file.bytesLength&&sha(b)===file.sha256,'CarrierBuildOutputChanged');return b;};
  need(parse(await read('oci-layout',1048576)).imageLayoutVersion==='1.0.0','CarrierBuildLayout');
  const index=parse(await read('index.json',1048576));need(index.schemaVersion===2&&index.manifests?.length===1&&index.manifests[0].digest===metadataDigest,'CarrierBuildOutputRoot');
  stage='output-graph';const nodes=new Map(),documents=new Map(),visiting=new Set();let compressedBytes=0,manifestCount=0,blobCount=0;
  const visit=async(d,depth=0)=>{
   need(depth<=32&&!visiting.has(d.digest),'CarrierBuildGraphCycle');const manifest=manifests.has(d.mediaType),inlineCost=imageDescriptorDataLocalBytes(d);if(inlineCost)charge(inlineCost);validateImageDescriptor(d,manifest?'manifest':'blob');const prior=nodes.get(d.digest);
   if(prior){need(prior.size===d.size&&prior.mediaType===d.mediaType,'CarrierBuildGraphConflict');return;}
   const observed=result.output.files.get('blobs/sha256/'+d.digest.slice(7));need(observed?.bytesLength===d.size&&observed.sha256===d.digest.slice(7),'CarrierBuildGraphBlob');
   compressedBytes+=d.size;manifest?manifestCount++:blobCount++;need(compressedBytes<=t.bounds.compressedBytes&&manifestCount<=t.bounds.manifestNodes&&blobCount<=t.bounds.blobNodes,'CarrierBuildGraphBound');
   nodes.set(d.digest,{digest:d.digest,size:d.size,mediaType:d.mediaType});if(!manifest)return;visiting.add(d.digest);
   const doc=parse(await read('blobs/sha256/'+d.digest.slice(7),1048576));documents.set(d.digest,doc);
   need(doc.schemaVersion===2&&doc.mediaType===d.mediaType,'CarrierBuildGraphManifest');
   if(indexes.has(d.mediaType)){need(Array.isArray(doc.manifests),'CarrierBuildGraphManifest');for(const child of doc.manifests)await visit(child,depth+1);}
   else{await visit(doc.config,depth+1);need(Array.isArray(doc.layers),'CarrierBuildGraphManifest');for(const child of doc.layers)await visit(child,depth+1);}
   if(doc.subject)await visit(doc.subject,depth+1);visiting.delete(d.digest);
  };
  await visit(index.manifests[0]);need(result.output.files.size===nodes.size+2,'CarrierBuildUnreferencedOutput');
  const rootDoc=documents.get(metadataDigest),arms=rootDoc?.manifests?.filter(d=>d.platform?.os==='linux'&&d.platform.architecture==='arm64');need(arms?.length===1,'CarrierBuildArm64');
  // The OCI exporter supplies a root descriptor, not necessarily a separate
  // config field. The actual verified arm64 manifest is the config authority.
  const configDigest=documents.get(arms[0].digest)?.config?.digest;
  need(/^sha256:[a-f0-9]{64}$/.test(configDigest)&&(metadata['containerimage.config.digest']===undefined||metadata['containerimage.config.digest']===configDigest),'CarrierBuildMetadata');
  const declared=metadata['containerimage.descriptor'],actual=nodes.get(metadataDigest);need(declared.size===actual.size&&declared.mediaType===actual.mediaType,'CarrierBuildMetadata');
  // Derived builds use the verified core descriptor also available to registry
  // readers. Original export/metadata bytes retain their hash commitments;
  // legacy builds retain their full exporter descriptor and historical hashes.
  const builtBinding={account:t.scope.account,region:t.scope.region,repositoryName:t.scope.repositoryName,root:derived?actual:index.manifests[0],arm64Digest:arms[0].digest,configDigest};
  stage='output-graph-verification';const cacheDirectory=join(directory,'output/blobs/sha256'),budget=createPrepaidControlCacheBudget({uncompressedBytesLimit:t.bounds.uncompressedBytes,processedEntriesLimit:t.bounds.processedEntries,metadataReads,deadlineMs:Math.min(plan.deadlineMs,Date.now()+L.maxBlobTransferMs),signal});
  verified=await readCollectedControlImageCache(builtBinding,{directory:cacheDirectory,nodes:[...nodes.values()],budget,metadataReads});
  stage='output-filesystem';const filesystem=await inspectImageFilesystem(verified.graph,{component:'bootstrap'});stage='output-closure';assertBuiltClosure(filesystem,context,derived);stage='output-config';
  const config=parse(await read('blobs/sha256/'+configDigest.slice(7),1048576));
  need(config.os==='linux'&&config.architecture==='arm64'&&config.config?.User==='1000:1000'&&hash(config.config.Entrypoint)===hash(['/bin/setpriv','--no-new-privs','--','/usr/local/bin/node','/carrier/guard-first.mjs','audit-original-root'])&&hash(config.config.Cmd??[])===hash([])&&!(config.config.OnBuild?.length)&&!Object.keys(config.config.Volumes??{}).length,'CarrierBuiltConfig');
  stage='context-recheck';await verifyMaterializedCarrierContext(handle);if(derived)await inspectCarrierRuntimeMaterial(derivedHandle,derivedBindings);await verified.cache.check();check();
  const outputHandle=Object.freeze({kind:'carrier-offline-build'}),record=freeze({version:derived?2:1,kind:'carrier-offline-build-evidence',authority:false,templateHash:plan.templateHash,contextHash:plan.context.sha256,...(derived?{derivedRecordHash:derived.recordHash}:{}),rootDigest:metadataDigest,arm64Digest:arms[0].digest,configDigest,graphHash:verified.graph.graphHash,filesystemHash:hash(inspectImageFilesystemEvidence(filesystem)),sourcePolicyHash:sha(policy),metadataHash:sha(metadataRaw),logHash:result.logHash,logBytes:result.logBytes,archiveHash:result.output.archiveHash,archiveBytes:result.output.archiveBytes,nativeBuildLogicalReservation:nativeBound,processStopped:true,termination:result.termination});
  builds.set(outputHandle,{directory,cacheDirectory,graph:verified.graph,filesystem,metadata,metadataRaw:metadataRaw.toString('utf8'),log:Buffer.from(result.logs),record,runtimeManifest:derived?.runtimeManifest??context.runtimeManifest,derivedRecord:derived?.record,close:verified.cache.close,closed:false});return outputHandle;
 }catch(error){await verified?.cache.close();if(attempted){if(error.code==='ECLEANUP')throw error;const e=held(directory,termination);e.stage=stage;e.failureCode=failures.get(error)??(verificationCodes.has(error.message)?error.message:'CarrierBuildVerification');throw e;}await rm(directory,{recursive:true,force:true});throw error;}
}
export function inspectCarrierOfflineBuild(handle){const b=builds.get(handle);need(b&&!b.closed,'CarrierBuildHandle');need(sha(b.metadataRaw)===b.record.metadataHash&&sha(b.log)===b.record.logHash&&b.log.length===b.record.logBytes,'CarrierBuildEvidenceChanged');return Object.freeze({directory:b.directory,cacheDirectory:b.cacheDirectory,graph:b.graph,filesystem:b.filesystem,record:b.record,runtimeManifest:b.runtimeManifest,...(b.derivedRecord?{derivedRecord:b.derivedRecord}:{}),metadata:freeze(structuredClone(b.metadata)),metadataRaw:b.metadataRaw,log:Buffer.from(b.log)});}
export async function closeCarrierOfflineBuild(handle){const b=builds.get(handle);need(b&&!b.closed,'CarrierBuildHandle');await b.close();b.closed=true;/* Final owner cleanup retains the output until independent registry readback. */}
