import {createHash} from 'node:crypto';
import {IMAGE_TRANSITION_LIMITS as L,IMAGE_TRANSITION_LIMITS_HASH,IMAGE_TRANSITION_COMPONENTS} from './production-image-transition.mjs';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {inspectImageArchiveBinding} from './production-image-custody.mjs';

export const IMAGE_MEDIA=Object.freeze({index:'application/vnd.oci.image.index.v1+json',dockerIndex:'application/vnd.docker.distribution.manifest.list.v2+json',manifest:'application/vnd.oci.image.manifest.v1+json',dockerManifest:'application/vnd.docker.distribution.manifest.v2+json',config:'application/vnd.oci.image.config.v1+json',dockerConfig:'application/vnd.docker.container.image.v1+json',emptyConfig:'application/vnd.oci.empty.v1+json',attestation:'application/vnd.in-toto+json',tar:'application/vnd.oci.image.layer.v1.tar',gzip:'application/vnd.oci.image.layer.v1.tar+gzip',zstd:'application/vnd.oci.image.layer.v1.tar+zstd',dockerGzip:'application/vnd.docker.image.rootfs.diff.tar.gzip'});
const indexes=new Set([IMAGE_MEDIA.index,IMAGE_MEDIA.dockerIndex]),manifests=new Set([...indexes,IMAGE_MEDIA.manifest,IMAGE_MEDIA.dockerManifest]);
const configs=new Set([IMAGE_MEDIA.config,IMAGE_MEDIA.dockerConfig,IMAGE_MEDIA.emptyConfig]);
export const IMAGE_LAYER_MEDIA=Object.freeze([IMAGE_MEDIA.tar,IMAGE_MEDIA.gzip,IMAGE_MEDIA.zstd,IMAGE_MEDIA.dockerGzip]);
const media=new Set([...manifests,...configs,IMAGE_MEDIA.attestation,...IMAGE_LAYER_MEDIA]);
const contexts=new WeakMap(),copies=new WeakMap(),budgets=new WeakSet();
export const imageDigest=bytes=>'sha256:'+createHash('sha256').update(bytes).digest('hex');
export const imageFailure=code=>{throw Object.assign(Error(code),{code,hold:true});};
const need=(ok,code='ImageGraphInvalid')=>{if(!ok)imageFailure(code);};
const record=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const integer=v=>Number.isSafeInteger(v)&&v>=0;
const hexDigest=v=>typeof v==='string'&&/^sha256:[a-f0-9]{64}$/.test(v);
const freeze=v=>{if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;};
const repo=v=>typeof v==='string'&&v.length<=256&&/^[a-z0-9]+(?:(?:[._-]|\/)[a-z0-9]+)*$/.test(v);
const bytesOf=value=>{need(value instanceof Uint8Array,'ImageByteStreamRequired');need(value.byteLength<=L.maxBufferPerStreamBytes,'ImageStreamBufferLimit');return Buffer.from(value.buffer,value.byteOffset,value.byteLength);};

/** One budget spans source reads, copy, destination reads, scans and virtual FS.
 * No JSON, environment or caller option can replace the reviewed constants. */
export function createImageBudget(options={}){
 need(record(options)&&Object.keys(options).every(k=>['now','startedMs','credentialExpiresMs','signal'].includes(k)),'ImageLimitsOverride');
 const now=options.now??Date.now,startedMs=options.startedMs??now(),expires=options.credentialExpiresMs;
 need(typeof now==='function'&&Number.isSafeInteger(startedMs)&&startedMs<=now()&&Number.isSafeInteger(expires),'ImageBudgetTime');
 const deadlineMs=startedMs+L.maxStageMs;need(expires>=deadlineMs+L.minimumCredentialMarginMs,'ImageCredentialLifetime');
 need(hash(L)===IMAGE_TRANSITION_LIMITS_HASH,'ImageLimitsChanged');
 const seen=new Map(),edges=new Set();let manifestNodes=0,blobNodes=0,uniqueBytes=0,transferredBytes=0,calls=0,uncompressedBytes=0,fsEntries=0,active=0;
 const check=()=>{options.signal?.throwIfAborted();need(now()>=startedMs&&now()<deadlineMs-L.cleanupReserveMs,'ImageStageExpired');need(expires-now()>=L.minimumCredentialMarginMs,'ImageCredentialLifetime');};
 const add=(key,size,isManifest)=>{check();need(integer(size));const prior=seen.get(key);if(prior){need(prior.size===size&&prior.isManifest===isManifest,'ImageDescriptorConflict');return;}
  need(uniqueBytes+size<=L.maxUniqueCompressedGraphBytes,'ImageGraphByteLimit');need(isManifest?manifestNodes+1<=L.maxManifestNodes:blobNodes+1<=L.maxBlobNodes,'ImageGraphNodeLimit');
  seen.set(key,{size,isManifest});uniqueBytes+=size;if(isManifest)manifestNodes++;else blobNodes++;
 };
 const budget={limitsHash:IMAGE_TRANSITION_LIMITS_HASH,startedMs,deadlineMs,now,signal:options.signal,check,
  manifest(d){validateImageDescriptor(d,'manifest');add(d.digest,d.size,true);},
  blob(d){validateImageDescriptor(d,'blob');add(d.digest,d.size,false);},
  edge(key){check();need(typeof key==='string');if(!edges.has(key)){need(edges.size<L.maxEdges,'ImageGraphEdgeLimit');edges.add(key);}},
  transfer(size){check();need(integer(size)&&transferredBytes+size<=L.maxTransferredBytes,'ImageTransferLimit');transferredBytes+=size;},
  call(){check();need(++calls<=L.maxEcrCalls,'ImageCallLimit');},
  uncompressed(size){check();need(integer(size)&&uncompressedBytes+size<=L.maxUncompressedBytes,'ImageUncompressedLimit');uncompressedBytes+=size;},
  entry(){check();need(++fsEntries<=L.maxFsEntries,'ImageFilesystemEntryLimit');},
  enter(){check();need(active<L.maxConcurrency,'ImageConcurrencyLimit');active++;let closed=false;return()=>{if(!closed){closed=true;active--;}};},
  projected({transferBytes,ecrCalls}){check();need(integer(transferBytes)&&integer(ecrCalls)&&transferredBytes+transferBytes<=L.maxTransferredBytes&&calls+ecrCalls<=L.maxEcrCalls,'ImageCopyBudgetUnavailable');},
  usage:()=>({manifestNodes,blobNodes,edges:edges.size,uniqueBytes,transferredBytes,calls,uncompressedBytes,fsEntries,active})};
 budgets.add(budget);return Object.freeze(budget);
}
export function assertImageBudget(budget){need(budgets.has(budget),'ImageBudgetRequired');budget.check();return budget;}
export function validateImageDescriptor(d,kind){
 need(record(d)&&Object.keys(d).every(k=>['mediaType','digest','size','annotations','platform','artifactType'].includes(k)),'ImageDescriptorFields');
 need(hexDigest(d.digest)&&integer(d.size)&&media.has(d.mediaType),'ImageDescriptorInvalid');
 if(kind==='manifest')need(manifests.has(d.mediaType)&&d.size<=L.maxManifestBytes,'ImageManifestLimit');
 if(kind==='blob')need(!manifests.has(d.mediaType)&&d.size<=L.maxBlobBytes,'ImageBlobLimit');
 if(configs.has(d.mediaType))need(d.size<=L.maxConfigBytes,'ImageConfigLimit');
 if(d.mediaType===IMAGE_MEDIA.attestation)need(d.size<=L.maxAttestationPayloadBytes,'ImageAttestationLimit');
 if(d.annotations!==undefined)need(record(d.annotations)&&Object.entries(d.annotations).every(([k,v])=>typeof v==='string'&&Buffer.byteLength(k)<=L.maxPathBytes&&Buffer.byteLength(v)<=L.maxBufferPerStreamBytes),'ImageAnnotations');
 if(d.platform!==undefined)need(record(d.platform)&&typeof d.platform.os==='string'&&typeof d.platform.architecture==='string','ImagePlatform');
 return d;
}

/** Full grammar/duplicate-key validation with projection for large config and
 * attestation predicates. Raw bytes are separately retained and hashed. */
export async function readImageJson(stream,{maxBytes,budget,fields}={}){
 assertImageBudget(budget);need(integer(maxBytes)&&maxBytes<=L.maxAttestationPayloadBytes);
 const iterator=stream[Symbol.asyncIterator](),decoder=new TextDecoder('utf-8',{fatal:true});let text='',offset=0,total=0,ended=false,steps=0;
 const limitAt=Math.min(budget.deadlineMs-L.cleanupReserveMs,budget.now()+L.maxBlobTransferMs);
 const peek=async()=>{if(++steps%4096===0){budget.check();need(budget.now()<limitAt,'ImageJsonTimeout');}
  while(offset===text.length&&!ended){const item=await iterator.next();if(item.done){text=decoder.decode();offset=0;ended=true;}else{const bytes=bytesOf(item.value);total+=bytes.length;need(total<=maxBytes,'ImageJsonSize');text=decoder.decode(bytes,{stream:true});offset=0;}}
  return offset<text.length?text[offset]:null;
 };
 const take=async()=>{const c=await peek();need(c!==null,'ImageJsonTruncated');offset++;return c;};
 const whitespace=async()=>{while([' ','\n','\r','\t'].includes(await peek()))offset++;};
 const string=async keep=>{need(await take()==='"');let raw=keep?'"':'',rawBytes=1,previousHigh=false;
  const append=c=>{if(!keep)return;const n=c.charCodeAt(0);rawBytes+=previousHigh&&n>=0xdc00&&n<=0xdfff?1:Buffer.byteLength(c);previousHigh=n>=0xd800&&n<=0xdbff;need(rawBytes<=L.maxBufferPerStreamBytes,'ImageJsonScalarLimit');raw+=c;};
  while(true){const c=await take();append(c);if(c==='"')break;
   need(c.charCodeAt(0)>=32,'ImageJsonString');if(c==='\\'){const e=await take();append(e);need('"\\/bfnrtu'.includes(e),'ImageJsonEscape');if(e==='u')for(let n=0;n<4;n++){const h=await take();need(/[a-fA-F0-9]/.test(h),'ImageJsonEscape');append(h);}}
  }return keep?JSON.parse(raw):undefined;
 };
 const value=async(depth,keep)=>{need(depth<=L.maxJsonDepth,'ImageJsonDepth');await whitespace();const c=await peek();
  if(c==='"')return string(keep);
  if(c==='{'||c==='['){await take();const object=c==='{',result=keep?(object?{}:[]):undefined,keys=new Set();await whitespace();const end=object?'}':']';if(await peek()===end){await take();return result;}
   while(true){let key;if(object){key=await string(true);need(!keys.has(key),'ImageJsonDuplicateKey');keys.add(key);await whitespace();need(await take()===':','ImageJsonColon');}
    const capture=keep&&(!object||depth!==0||!fields||fields.includes(key)),child=await value(depth+1,capture);
    if(capture){if(object)Object.defineProperty(result,key,{value:child,enumerable:true,writable:true,configurable:true});else result.push(child);}
    await whitespace();const delimiter=await take();if(delimiter===end)break;need(delimiter===',','ImageJsonDelimiter');await whitespace();
   }return result;
  }
  let raw='';while(true){const q=await peek();if(q===null||[' ', '\t','\r','\n',',',']','}'].includes(q))break;raw+=await take();need(raw.length<=L.maxBufferPerStreamBytes,'ImageJsonScalarLimit');}
  need(raw==='null'||raw==='true'||raw==='false'||/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/.test(raw),'ImageJsonValue');const parsed=JSON.parse(raw);need(typeof parsed!=='number'||Number.isFinite(parsed),'ImageJsonNumber');return keep?parsed:undefined;
 };
 try{const result=await value(0,true);await whitespace();need(await peek()===null,'ImageJsonTrailing');return result;}
 finally{await iterator.return?.();}
}
export async function* verifyImageBytes(stream,descriptor,budget,{transfer=false}={}){
 assertImageBudget(budget);if(transfer)budget.transfer(descriptor.size);const h=createHash('sha256');let count=0,complete=false;const until=Math.min(budget.deadlineMs-L.cleanupReserveMs,budget.now()+L.maxBlobTransferMs);
 try{for await(const value of stream){budget.check();need(budget.now()<until,'ImageBlobTimeout');const bytes=bytesOf(value);count+=bytes.length;need(count<=descriptor.size,'ImageBlobSize');h.update(bytes);yield bytes;}
  need(count===descriptor.size&&'sha256:'+h.digest('hex')===descriptor.digest,'ImageBlobDigest');complete=true;
 }finally{if(!complete){stream.destroy?.();await stream.return?.();await stream.cancel?.();}}
}
const oneChunk=bytes=>(async function*(){yield bytes;})();
function validateRoots(roots){
 need(Array.isArray(roots)&&roots.length===L.rootCount&&new Set(roots.map(r=>r.component)).size===L.rootCount,'ImageRoots');
 for(const r of roots){need(record(r)&&Object.keys(r).sort().join()===['component','sourceRepository','destinationRepository','targetTag','root','arm64Digest'].sort().join(),'ImageRootFields');
  need(IMAGE_TRANSITION_COMPONENTS.includes(r.component)&&repo(r.sourceRepository)&&repo(r.destinationRepository)&&r.sourceRepository!==r.destinationRepository&&typeof r.targetTag==='string'&&/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(r.targetTag)&&hexDigest(r.arm64Digest),'ImageRootScope');validateImageDescriptor(r.root,'manifest');need(indexes.has(r.root.mediaType),'ImageRootIndexRequired');}
 need(new Set(roots.map(r=>r.sourceRepository)).size===3&&new Set(roots.map(r=>r.destinationRepository)).size===3,'ImageRepositoryMapping');
}

/** Adapters return decoded manifest bytes or async byte streams; never URLs or
 * approval flags. A context proves validated bytes, not source/caller authority. */
export async function readImageGraph(roots,{readManifest,readBlob,source,store,budget,side='source'}={}){
 validateRoots(roots);assertImageBudget(budget);need(['source','destination'].includes(side));
 readManifest??=source&&(({repositoryName,descriptor})=>source.manifest(repositoryName,descriptor));
 readBlob??=source&&(({repositoryName,descriptor})=>source.blob(repositoryName,descriptor));
 need(typeof readManifest==='function'&&typeof readBlob==='function'&&typeof store?.put==='function'&&typeof store.open==='function','ImageReadAdapter');
 const manifestMap=new Map(),blobs=new Map(),descriptors=new Map(),visiting=new Set(),done=new Set(),origins=new Set(),edges=[],attestations=[],images=new Map(),readbacks=[];
 const register=d=>{const before=descriptors.get(d.digest);if(before)need(before.size===d.size&&before.mediaType===d.mediaType,'ImageDescriptorConflict');else descriptors.set(d.digest,{digest:d.digest,size:d.size,mediaType:d.mediaType});};
 const blob=async(repositoryName,d)=>{validateImageDescriptor(d,'blob');register(d);budget.blob(d);const key=repositoryName+'\0'+d.digest;if(origins.has(key))return;origins.add(key);
  const leave=budget.enter();budget.transfer(d.size);budget.call();try{const input=await readBlob({repositoryName,descriptor:d,signal:budget.signal});let consumed=false;const checked=(async function*(){yield*verifyImageBytes(input,d,budget);consumed=true;})();if(!blobs.has(d.digest)){await store.put(d,checked);need(consumed,'ImageBlobNotConsumed');blobs.set(d.digest,{...descriptors.get(d.digest)});}else for await(const _ of checked){};readbacks.push({repositoryName,...descriptors.get(d.digest)});}finally{leave();}
 };
 const edge=(component,parent,d,kind,index)=>{validateImageDescriptor(d,manifests.has(d.mediaType)?'manifest':'blob');const row={component,parent,child:d.digest,kind,index};budget.edge(hash(row));edges.push(row);};
 const visit=async(root,d,depth)=>{
  need(depth<=L.maxGraphDepth,'ImageGraphDepth');validateImageDescriptor(d,'manifest');register(d);budget.manifest(d);
  const repositoryName=side==='source'?root.sourceRepository:root.destinationRepository,key=repositoryName+'\0'+d.digest;
  need(!visiting.has(key),'ImageGraphCycle');if(done.has(key))return;visiting.add(key);
  const leave=budget.enter();budget.transfer(d.size);budget.call();let bytes;try{bytes=bytesOf(await readManifest({repositoryName,descriptor:d,signal:budget.signal}));need(bytes.length===d.size&&imageDigest(bytes)===d.digest,'ImageManifestDigest');}finally{leave();}
  const document=await readImageJson(oneChunk(bytes),{maxBytes:L.maxManifestBytes,budget});need(record(document)&&document.schemaVersion===2&&document.mediaType===d.mediaType,'ImageManifestSchema');
  readbacks.push({repositoryName,...descriptors.get(d.digest)});
  const allowed=indexes.has(d.mediaType)?['schemaVersion','mediaType','manifests','annotations','subject','artifactType']:['schemaVersion','mediaType','config','layers','annotations','subject','artifactType'];need(Object.keys(document).every(k=>allowed.includes(k)),'ImageManifestFields');
  if(!manifestMap.has(d.digest)){await store.put(d,oneChunk(bytes));manifestMap.set(d.digest,{...descriptors.get(d.digest),document});}
  if(indexes.has(d.mediaType)){
   need(Array.isArray(document.manifests)&&document.manifests.length>0&&document.manifests.length<=L.maxEdges,'ImageIndexChildren');
   const children=new Set();for(const [index,child]of document.manifests.entries()){need(!children.has(child.digest),'ImageDuplicateManifestEdge');children.add(child.digest);edge(root.component,d.digest,child,'manifest',index);await visit(root,child,depth+1);}
   if(d.digest===root.root.digest)need(document.manifests.filter(c=>c.digest===root.arm64Digest&&c.platform?.os==='linux'&&c.platform.architecture==='arm64').length===1,'ImageArm64Selection');
  }else{
   need(Array.isArray(document.layers)&&document.layers.length<=L.maxBlobNodes&&configs.has(document.config?.mediaType),'ImageManifestConfig');
   edge(root.component,d.digest,document.config,'config',0);await blob(repositoryName,document.config);
   const config=await readImageJson(verifyImageBytes(store.open(document.config),document.config,budget),{maxBytes:L.maxConfigBytes,budget,fields:['architecture','os','rootfs']});need(record(config),'ImageConfigSchema');if(document.config.mediaType===IMAGE_MEDIA.emptyConfig)need(Object.keys(config).length===0,'ImageEmptyConfig');
   let payloads=0;for(const [index,layer]of document.layers.entries()){
    need(IMAGE_LAYER_MEDIA.includes(layer.mediaType)||layer.mediaType===IMAGE_MEDIA.attestation,'ImageLayerMedia');edge(root.component,d.digest,layer,'layer',index);await blob(repositoryName,layer);
    if(layer.mediaType===IMAGE_MEDIA.attestation){payloads++;const payload=await readImageJson(verifyImageBytes(store.open(layer),layer,budget),{maxBytes:L.maxAttestationPayloadBytes,budget,fields:['_type','subject','predicateType']});
     need(['https://in-toto.io/Statement/v0.1','https://in-toto.io/Statement/v1'].includes(payload._type)&&Array.isArray(payload.subject)&&payload.subject.length>0&&payload.subject.every(s=>record(s)&&record(s.digest)&&Object.keys(s.digest).length===1&&s.digest.sha256===root.arm64Digest.slice(7)),'ImageAttestationSubject');
     attestations.push({component:root.component,manifestDigest:d.digest,payloadDigest:layer.digest,subjectDigest:root.arm64Digest,predicateType:payload.predicateType});
    }
   }
   if(payloads){need(payloads===document.layers.length,'ImageMixedArtifactLayers');if(d.annotations?.['vnd.docker.reference.digest']!==undefined)need(d.annotations['vnd.docker.reference.digest']===root.arm64Digest,'ImageAttestationSubject');if(d.annotations?.['vnd.docker.reference.type']!==undefined)need(d.annotations['vnd.docker.reference.type']==='attestation-manifest','ImageAttestationType');}
   else{need(config.os==='linux'&&['arm64','amd64'].includes(config.architecture)&&config.rootfs?.type==='layers'&&Array.isArray(config.rootfs.diff_ids)&&config.rootfs.diff_ids.length===document.layers.length&&config.rootfs.diff_ids.every(hexDigest),'ImageRuntimeConfig');}
   if(d.digest===root.arm64Digest){need(!payloads&&config.architecture==='arm64','ImageArm64Config');images.set(root.component,{manifest:descriptors.get(d.digest),config:document.config,layers:document.layers,diffIds:config.rootfs.diff_ids});}
  }
  if(document.subject){need(document.subject.digest===root.arm64Digest,'ImageArtifactSubject');edge(root.component,d.digest,document.subject,'subject',0);await visit(root,document.subject,depth+1);}
  visiting.delete(key);done.add(key);
 };
 for(const root of roots)await visit(root,root.root,0);
 need(images.size===3,'ImageMissingArm64');
 const inventory=freeze({version:1,limitsHash:IMAGE_TRANSITION_LIMITS_HASH,roots:structuredClone(roots),nodes:[...descriptors.values()].sort((a,b)=>a.digest.localeCompare(b.digest)),edges:edges.sort((a,b)=>hash(a).localeCompare(hash(b))),attestations:attestations.sort((a,b)=>hash(a).localeCompare(hash(b)))});
 const graphHash=hash(inventory),handle=Object.freeze({graphHash,inventoryHash:graphHash,limitsHash:IMAGE_TRANSITION_LIMITS_HASH,inventory});contexts.set(handle,{roots:structuredClone(roots),side,store,budget,manifests:manifestMap,blobs,images,readbacks:freeze(readbacks)});return handle;
}
export function imageGraphState(handle){need(contexts.has(handle),'ImageGraphContextRequired');const s=contexts.get(handle);return {roots:freeze(structuredClone(s.roots)),side:s.side,budget:s.budget,
 manifests:new Map([...s.manifests].map(([k,v])=>[k,freeze(structuredClone(v))])),blobs:new Map([...s.blobs].map(([k,v])=>[k,freeze(structuredClone(v))])),images:new Map([...s.images].map(([k,v])=>[k,freeze(structuredClone(v))])),
 readbacks:structuredClone(s.readbacks),store:Object.freeze({open(d){const known=s.blobs.get(d.digest)??s.manifests.get(d.digest);need(known&&known.size===d.size&&known.mediaType===d.mediaType,'ImageCacheDescriptor');return verifyImageBytes(s.store.open(d),d,s.budget);}})};}
export function verifyImageGraphCopies(source,destination,{account,region}={}){
 const a=imageGraphState(source),b=imageGraphState(destination);need(a.side==='source'&&b.side==='destination'&&source.inventoryHash===destination.inventoryHash&&a.budget===b.budget,'ImageDestinationGraphChanged');
 need(typeof account==='string'&&/^\d{12}$/.test(account)&&typeof region==='string'&&/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(region),'ImageGraphScope');a.budget.check();
 const images=Object.fromEntries(a.roots.map(r=>[r.component,{rootDigest:r.root.digest,arm64Digest:r.arm64Digest}]));
 const summary=freeze({version:1,limitsHash:IMAGE_TRANSITION_LIMITS_HASH,account,region,images,contentHash:hash(source.inventory.nodes),destinationContentHash:hash(destination.inventory.nodes),inventoryHash:source.inventoryHash,destinationReadbackHash:hash({inventory:destination.inventory,reads:b.readbacks}),startedMs:a.budget.startedMs,completedMs:a.budget.now()});
 const result=Object.freeze({graphHash:hash(summary),limitsHash:IMAGE_TRANSITION_LIMITS_HASH,summary});copies.set(result,{source,destination,summary,kind:'live-copy-evidence'});return result;
}
export function inspectImageCopyVerification(context){
 need(copies.has(context),'ImageCopyVerificationRequired');const c=copies.get(context);
 if(c.kind==='archived-copy-evidence')return {graphHash:context.graphHash,summary:structuredClone(c.summary),kind:c.kind,inventory:structuredClone(c.inventory),destinationReadback:structuredClone(c.destinationReadback),archiveBinding:structuredClone(c.binding)};
 return {graphHash:context.graphHash,summary:structuredClone(c.summary),kind:c.kind,inventory:structuredClone(c.source.inventory),destinationReadback:{inventory:structuredClone(c.destination.inventory),reads:structuredClone(contexts.get(c.destination).readbacks)}};
}

/** Protected commitments authenticate the already verified inventory. No live
 * graph context or blob access is created here, so this cannot drive uploads. */
export function restoreArchivedImageCopyVerification(binding,value){
 const anchor=inspectImageArchiveBinding(binding),proof=anchor.proof,summary=proof.graph,inventory=proof.graphInventory,readback=proof.destinationReadback;
 need(value&&Object.keys(value).sort().join()===['version','graphHash','summary','inventory','destinationReadback'].sort().join()&&value.version===1,'ImageArchiveGraphShape');
 need(hash(value.summary)===hash(summary)&&value.graphHash===hash(summary)&&hash(value.inventory)===hash(inventory)&&hash(value.destinationReadback)===hash(readback),'ImageArchiveGraphCommitment');
 need(summary.account===anchor.scope.account&&summary.region===anchor.scope.region&&summary.limitsHash===IMAGE_TRANSITION_LIMITS_HASH&&hash(summary.images)===hash(anchor.data.images)&&hash(inventory)===summary.inventoryHash&&hash(readback)===summary.destinationReadbackHash&&hash(readback.inventory)===hash(inventory),'ImageArchiveGraphScope');
 validateRoots(inventory.roots);need(inventory.version===1&&inventory.limitsHash===IMAGE_TRANSITION_LIMITS_HASH&&Array.isArray(inventory.nodes)&&Array.isArray(inventory.edges)&&Array.isArray(inventory.attestations)&&inventory.edges.length<=L.maxEdges,'ImageArchiveInventory');
 const nodes=new Map();let total=0,manifestCount=0,blobCount=0;
 for(const d of inventory.nodes){const isManifest=manifests.has(d.mediaType);validateImageDescriptor(d,isManifest?'manifest':'blob');need(!nodes.has(d.digest),'ImageArchiveDuplicateNode');nodes.set(d.digest,d);total+=d.size;need(Number.isSafeInteger(total)&&total<=L.maxUniqueCompressedGraphBytes,'ImageArchiveByteLimit');if(isManifest)manifestCount++;else blobCount++;}
 need(manifestCount<=L.maxManifestNodes&&blobCount<=L.maxBlobNodes&&hash(inventory.nodes)===summary.contentHash&&summary.contentHash===summary.destinationContentHash,'ImageArchiveGraphContent');
 const edgeKeys=new Set(),byComponent=new Map();
 for(const e of inventory.edges){need(e&&Object.keys(e).sort().join()===['component','parent','child','kind','index'].sort().join()&&IMAGE_TRANSITION_COMPONENTS.includes(e.component)&&nodes.has(e.parent)&&nodes.has(e.child)&&manifests.has(nodes.get(e.parent).mediaType)&&['manifest','config','layer','subject'].includes(e.kind)&&integer(e.index),'ImageArchiveEdge');const key=hash(e);need(!edgeKeys.has(key),'ImageArchiveDuplicateEdge');edgeKeys.add(key);const list=byComponent.get(e.component)??[];list.push(e);byComponent.set(e.component,list);}
 const expectedReads=new Set(),covered=new Set();
 for(const root of inventory.roots){
  need(root.root.digest===anchor.data.images[root.component].rootDigest&&root.arm64Digest===anchor.data.images[root.component].arm64Digest&&root.destinationRepository==='mem9-on-aws/'+root.component,'ImageArchiveTarget');
  const active=new Set(),done=new Set(),edges=byComponent.get(root.component)??[];
  const visit=(digest,depth)=>{need(nodes.has(digest)&&depth<=L.maxGraphDepth&&!active.has(digest),'ImageArchiveClosure');if(done.has(digest))return;active.add(digest);covered.add(digest);expectedReads.add(root.destinationRepository+'\0'+digest);for(const e of edges.filter(e=>e.parent===digest))visit(e.child,depth+(manifests.has(nodes.get(e.child).mediaType)?1:0));active.delete(digest);done.add(digest);};
  visit(root.root.digest,0);need(done.has(root.arm64Digest)&&edges.every(e=>done.has(e.parent)&&done.has(e.child)),'ImageArchiveClosure');
 }
 need(covered.size===nodes.size&&Array.isArray(readback.reads),'ImageArchiveClosure');
 const got=new Set();for(const r of readback.reads){const d=nodes.get(r.digest),key=r.repositoryName+'\0'+r.digest;need(d&&Object.keys(r).sort().join()===['repositoryName','digest','size','mediaType'].sort().join()&&r.size===d.size&&r.mediaType===d.mediaType&&expectedReads.has(key)&&!got.has(key),'ImageArchiveReadback');got.add(key);}
 need(got.size===expectedReads.size,'ImageArchiveReadback');
 for(const a of inventory.attestations)need(a&&IMAGE_TRANSITION_COMPONENTS.includes(a.component)&&nodes.has(a.manifestDigest)&&nodes.get(a.payloadDigest)?.mediaType===IMAGE_MEDIA.attestation&&a.subjectDigest===anchor.data.images[a.component].arm64Digest,'ImageArchiveAttestation');
 const handle=Object.freeze({graphHash:hash(summary),limitsHash:IMAGE_TRANSITION_LIMITS_HASH,summary:freeze(structuredClone(summary))});
 copies.set(handle,{kind:'archived-copy-evidence',summary:handle.summary,inventory:structuredClone(inventory),destinationReadback:structuredClone(readback),binding:{proofHash:anchor.proofHash,dataHash:anchor.dataHash,reviewHash:anchor.reviewHash,scope:anchor.scope}});return handle;
}
