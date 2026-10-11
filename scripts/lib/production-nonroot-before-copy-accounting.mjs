/** Closed COPY-prefix accounting only. These records cannot restore a reader,
 * issue credentials, spend a slot, or authenticate a build/security result. */
import {copyNonrootJson,parseNonrootJson} from './production-nonroot-contracts.mjs';
import {verifyNonrootFenceAcquisitionPayment} from './production-nonroot-fence-accounting.mjs';
import {nonrootAccountingPolicy} from './production-nonroot-budget-revision.mjs';
import {need,exact,same,hash,sha,hex,integer,counter,zero,parseAcquisitionJson} from './ci-smoke-acquisition-format.mjs';
import {compileOriginalIssuersBudget,inspectOriginalIssuerPlan,inspectOriginalIssuerSource,verifyOriginalIssuerJournal,ORIGINAL_ISSUER_LIMITS} from './production-nonroot-original-issuer-accounting.mjs';
import {verifyCarrierBeforeCopyGrant} from './ci-carrier-before-copy.mjs';
import {IMAGE_TRANSITION_LIMITS as L,IMAGE_TRANSITION_LIMITS_HASH} from './production-image-transition.mjs';
import {IMAGE_MEDIA,validateImageDescriptor} from './production-image-graph.mjs';

const manifests=new Set([IMAGE_MEDIA.index,IMAGE_MEDIA.dockerIndex,IMAGE_MEDIA.manifest,IMAGE_MEDIA.dockerManifest]);
const caps={identity:{requestBytes:16384,responseBytes:16384},assume:{requestBytes:16384,responseBytes:262144},manifest:{requestBytes:16384,responseBytes:8388608},url:{requestBytes:16384,responseBytes:65536}};
const unknownBytes=8388608;
const metadataProfiles=[{action:'ImdsV2Token',count:1,requestBytes:0,responseBytes:4096},{action:'ImdsV2Credentials',count:1,requestBytes:0,responseBytes:65536}];
const metadataRequests=[{method:'PUT',host:'169.254.169.254',path:'/latest/api/token',ttlSeconds:60},{method:'GET',host:'169.254.169.254',path:'/latest/meta-data/iam/security-credentials/aws-compliance-role'}];
const positive=n=>integer(n)&&n>0;
const ref=r=>{exact(r,['path','sha256']);need(typeof r.path==='string'&&r.path.startsWith('/')&&r.path.length<=4096&&!r.path.split('/').includes('..')&&hex(r.sha256),'NonrootBeforeCopyRef');};
function document(v,maxBytes=8388608){
 exact(v,['ref','raw']);ref(v.ref);need(typeof v.raw==='string'&&v.raw.length<=4*Math.ceil(maxBytes/3),'NonrootBeforeCopyRaw');
 const raw=Buffer.from(v.raw,'base64');need(raw.length>0&&raw.length<=maxBytes&&raw.toString('base64')===v.raw&&sha(raw)===v.ref.sha256,'NonrootBeforeCopyRaw');
 return parseAcquisitionJson(raw,maxBytes);
}
function legacyPlan(p,original,scope,sourceValue){
 exact(p,['version','kind','binding','bounds','profiles','charge',...(p.version===2?['source']:[])]);need([1,2].includes(p.version)&&p.kind==='legacy-bootstrap-read-plan','NonrootBeforeCopyLegacyPlan');
 const source=inspectOriginalIssuerSource(sourceValue);
 if(p.version===2)same(p.source,source,'NonrootBeforeCopyLegacyIssuerSource');
 else need(source.provider==='static-temporary','NonrootBeforeCopyLegacyIssuerSource');
 exact(original,['revision','sourceTree','binding','imageDigests','platformDigests']);exact(original.imageDigests,['bootstrap']);exact(original.platformDigests,['bootstrap']);
 need(hex(original.revision,40)&&hex(original.sourceTree,40),'NonrootBeforeCopyLegacySource');
 const op=original.binding.operator,td=original.binding.definitions.control,c=td?.containerDefinitions?.[0];
 need(op?.stage==='prod'&&op.account===scope.account&&op.region===scope.region&&td?.status==='ACTIVE'&&td.taskDefinitionArn===op.operators?.control?.taskDefinition&&td.taskDefinitionArn.startsWith(`arn:aws:ecs:${scope.region}:${scope.account}:task-definition/`),'NonrootBeforeCopyLegacyScope');
 need(td.containerDefinitions.length===1&&c.name==='ControlMem9Bootstrap'&&c.image===`${scope.account}.dkr.ecr.${scope.region}.amazonaws.com/mem9-on-aws/bootstrap@${original.imageDigests.bootstrap}`,'NonrootBeforeCopyLegacyImage');
 same(td.runtimePlatform,{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'});
 same(p.binding,{account:scope.account,region:scope.region,repositoryName:'mem9-on-aws/bootstrap',rootDigest:original.imageDigests.bootstrap,arm64Digest:original.platformDigests.bootstrap,revision:original.revision,sourceTree:original.sourceTree,operatorBindingHash:hash(original)},'NonrootBeforeCopyLegacyBinding');
 const b=p.bounds,maxima={manifestNodes:L.maxManifestNodes,blobNodes:L.maxBlobNodes,compressedBytes:L.maxUniqueCompressedGraphBytes,localBytes:L.maxTransferredBytes,uncompressedBytes:L.maxUncompressedBytes,processedEntries:L.maxFsEntries};exact(b,Object.keys(maxima));
 for(const [key,max]of Object.entries(maxima))need(positive(b[key])&&b[key]<=max,'NonrootBeforeCopyLegacyBounds');
 need(b.manifestNodes>=2&&b.localBytes>=b.compressedBytes&&b.uncompressedBytes>=L.maxBufferPerStreamBytes,'NonrootBeforeCopyLegacyBounds');
 if(p.version===2)need(b.localBytes>=ORIGINAL_ISSUER_LIMITS.localBytes+b.compressedBytes,'NonrootBeforeCopyLegacyBounds');
 const profiles=[...(source.provider==='instance-metadata'?metadataProfiles:[]),{action:'GetCallerIdentity',count:2,...caps.identity},{action:'AssumeRole',count:1,...caps.assume},{action:'BatchGetImage',count:b.manifestNodes,...caps.manifest},{action:'GetDownloadUrlForLayer',count:b.blobNodes,...caps.url},{action:'S3BlobGet',count:b.blobNodes,requestBytes:0,totalResponseBytes:b.compressedBytes}];
 same(p.profiles,profiles,'NonrootBeforeCopyLegacyProfiles');
 const wire=profiles.reduce((n,r)=>n+r.count*(r.requestBytes+(r.responseBytes??0))+(r.totalResponseBytes??0),unknownBytes);
 same(p.charge,{ecrRequests:b.manifestNodes+b.blobNodes,logicalBytes:b.localBytes,httpBodyBytes:wire,uncompressedBytes:b.uncompressedBytes,processedEntries:b.processedEntries},'NonrootBeforeCopyLegacyCharge');counter(p.charge);
 return p;
}
function legacyAssume(q,scope,tags){
 exact(q,['RoleArn','RoleSessionName','DurationSeconds','Tags','TransitiveTagKeys','Policy']);
 const resource=`arn:aws:ecr:${scope.region}:${scope.account}:repository/mem9-on-aws/bootstrap`,reads=['ecr:BatchGetImage','ecr:GetDownloadUrlForLayer'];
 const policy={Version:'2012-10-17',Statement:[{Effect:'Allow',Action:reads,Resource:resource},{Effect:'Allow',Action:'sts:GetCallerIdentity',Resource:'*'},{Effect:'Deny',NotAction:[...reads,'sts:GetCallerIdentity'],Resource:'*'},{Effect:'Deny',Action:'ecr:*',NotResource:resource}]};
 need(q.RoleArn===`arn:aws:iam::${scope.account}:role/BedrockTrackedInvoke`&&q.DurationSeconds===3600&&q.Policy===JSON.stringify(policy)&&typeof q.RoleSessionName==='string'&&q.RoleSessionName.startsWith(tags.usage+'-legacy-bootstrap-read-')&&/^[A-Za-z0-9_=,.@-]{1,64}$/.test(q.RoleSessionName),'NonrootBeforeCopyLegacyAssume');
 same(q.Tags,Object.entries(tags).map(([Key,Value])=>({Key,Value})));same(q.TransitiveTagKeys,Object.keys(tags));
}

function legacyAccounting(value,{start,events,carrier,sourceTags,issuerSource}){
 exact(value,['version','readPlan','operatorBinding','download','material','inventory','assumeRequest']);need(value.version===1,'NonrootBeforeCopyLegacyVersion');
 const r=document(value.readPlan),original=document(value.operatorBinding),d=document(value.download),m=document(value.material),inventory=document(value.inventory);
 exact(r,['authority','plan','operatorBindingRef','deadlineMs']);need(r.authority===false&&r.deadlineMs===start.deadlineMs,'NonrootBeforeCopyLegacyClock');same(r.operatorBindingRef,value.operatorBinding.ref);
 const p=legacyPlan(r.plan,original,carrier.template.scope,issuerSource),b=p.binding;
 if(carrier.template.ownerSource)same(carrier.template.ownerSource,issuerSource,'NonrootBeforeCopyLegacyIssuerSource');
 if(issuerSource.provider==='instance-metadata')need(carrier.template.ownerSource,'NonrootBeforeCopyLegacyIssuerSource');
 need(carrier.template.anchors.oldImageEvidenceHash===hash(original),'NonrootBeforeCopyLegacyOrigin');
 exact(d,['version','authority','planHash','operatorBindingRef','binding','inventory','startedMs','completedMs','deadlineMs','credentialCleanup','localUsed']);
 need(d.version===1&&d.authority===false&&d.planHash===hash(p)&&d.deadlineMs===start.deadlineMs&&positive(d.startedMs)&&d.startedMs>=start.deadlineMs-L.maxStageMs&&d.completedMs>=d.startedMs&&d.completedMs<=carrier.issuedMs,'NonrootBeforeCopyLegacyReceipt');same(d.operatorBindingRef,value.operatorBinding.ref);
 exact(d.credentialCleanup,['directory','released']);need(d.credentialCleanup.released===true&&typeof d.credentialCleanup.directory==='string'&&d.credentialCleanup.directory.startsWith('/')&&d.credentialCleanup.directory.length<=4096,'NonrootBeforeCopyLegacyCleanup');
 const old=carrier.template.anchors.oldImage;exact(d.binding,['account','region','repositoryName','root','arm64Digest','configDigest']);
 same({account:d.binding.account,region:d.binding.region,repositoryName:d.binding.repositoryName,rootDigest:d.binding.root.digest,arm64Digest:d.binding.arm64Digest,configDigest:d.binding.configDigest},old,'NonrootBeforeCopyLegacyImage');
 need(old.rootDigest===b.rootDigest&&old.arm64Digest===b.arm64Digest&&b.rootDigest!==b.arm64Digest,'NonrootBeforeCopyLegacyImage');
 const nodes=new Map();need(Array.isArray(d.inventory.nodes)&&d.inventory.nodes.length>0&&d.inventory.nodes.length<=L.maxManifestNodes+L.maxBlobNodes,'NonrootBeforeCopyLegacyInventory');
 let manifestCount=0,blobCount=0,compressed=0;
 for(const n of d.inventory.nodes){exact(n,['digest','size','mediaType']);validateImageDescriptor(n,manifests.has(n.mediaType)?'manifest':'blob');need(!nodes.has(n.digest),'NonrootBeforeCopyLegacyDuplicate');nodes.set(n.digest,n);compressed+=n.size;if(manifests.has(n.mediaType))manifestCount++;else blobCount++;}
 need(manifestCount>=2&&manifestCount<=p.bounds.manifestNodes&&blobCount>0&&blobCount<=p.bounds.blobNodes&&compressed<=p.bounds.compressedBytes,'NonrootBeforeCopyLegacyBounds');
 same(nodes.get(b.rootDigest),d.binding.root);need(manifests.has(nodes.get(b.arm64Digest)?.mediaType)&&nodes.get(d.binding.configDigest)?.mediaType===IMAGE_MEDIA.config,'NonrootBeforeCopyLegacyInventory');
 counter(d.localUsed);need(d.localUsed.ecrRequests===0&&d.localUsed.httpBodyBytes===0&&d.localUsed.logicalBytes>=2*compressed+(p.version===2?ORIGINAL_ISSUER_LIMITS.localBytes:0),'NonrootBeforeCopyLegacyLocal');
 for(const [key,max]of [['logicalBytes','localBytes'],['uncompressedBytes','uncompressedBytes'],['processedEntries','processedEntries']])need(d.localUsed[key]<=p.bounds[max],'NonrootBeforeCopyLegacyLocal');
 exact(m,['version','kind','authority','downloadReceiptRef','sourceBinding','sourceClosure','graphHash','filesystem','operatorRoot','inventoryRef','sourceEntries','destinationEntries','contentHash','completedMs','deadlineMs']);
 need(m.version===1&&m.kind==='legacy-operator-package-material'&&m.authority===false&&m.deadlineMs===start.deadlineMs&&m.completedMs>=d.completedMs&&m.completedMs<=carrier.issuedMs&&m.sourceClosure.sourceTree===b.sourceTree,'NonrootBeforeCopyLegacyPackage');
 same(m.downloadReceiptRef,value.download.ref);same(m.inventoryRef,value.inventory.ref);same(m.sourceBinding,b);exact(inventory,['files']);
 need(Array.isArray(inventory.files)&&inventory.files.length>0&&inventory.files.length<=19996&&m.contentHash===hash(inventory.files)&&Array.isArray(m.sourceEntries)&&m.sourceEntries.length===inventory.files.length&&Array.isArray(m.destinationEntries)&&m.destinationEntries.length===inventory.files.length,'NonrootBeforeCopyLegacyPackage');
 need(m.filesystem.component==='bootstrap'&&m.filesystem.graphHash===m.graphHash&&m.filesystem.rootDigest===b.rootDigest&&m.filesystem.arm64Digest===b.arm64Digest&&m.filesystem.limitsHash===IMAGE_TRANSITION_LIMITS_HASH,'NonrootBeforeCopyLegacyFilesystem');
 const sources=new Map(m.sourceEntries.map(row=>[row.path,row])),destinations=new Map(m.destinationEntries.map(row=>[row.path,row]));need(sources.size===inventory.files.length&&destinations.size===inventory.files.length,'NonrootBeforeCopyLegacyDuplicate');
 const allowedFs=new Map([['legacy-bootstrap',null]]),layers=new Map(),files=new Set();
 for(const file of inventory.files){
  exact(file,['path','type','sha256','bytes','mode',...(file.type==='symlink'?['target']:[])]);
  need(typeof file.path==='string'&&file.path.length<=4096&&!file.path.startsWith('/')&&!file.path.split('/').some(s=>!s||s==='.'||s==='..')&&!/[\x00-\x1f\\]/.test(file.path)&&!files.has(file.path)&&hex(file.sha256)&&integer(file.bytes),'NonrootBeforeCopyLegacyFile');files.add(file.path);
  const src=sources.get('bootstrap/operator/'+file.path),dst=destinations.get(file.path);need(src&&dst&&dst.bytes===file.bytes&&dst.sha256===file.sha256&&dst.mode===file.mode,'NonrootBeforeCopyLegacyFile');
  need(file.type===src.type&&['file','symlink'].includes(file.type),'NonrootBeforeCopyLegacyFile');
  if(file.type==='file'){
   const c=src.content;need(c&&integer(c.layer)&&integer(c.offset)&&c.size===file.bytes&&c.sha256===file.sha256&&nodes.has(c.layerDigest)&&!manifests.has(nodes.get(c.layerDigest).mediaType),'NonrootBeforeCopyLegacyFile');
   const prior=layers.get(c.layer);need(!prior||prior.digest===c.layerDigest,'NonrootBeforeCopyLegacyLayer');layers.set(c.layer,{digest:c.layerDigest,files:(prior?.files??0)+1});
   allowedFs.set('legacy-file-'+hash('/'+src.path),null);
  }else need(file.target===src.link&&file.target===dst.target&&sha(file.target)===file.sha256&&Buffer.byteLength(file.target)===file.bytes,'NonrootBeforeCopyLegacyFile');
 }
 for(const [index,layer]of layers)allowedFs.set('legacy-package-layer-'+index,layer.files);
 legacyAssume(value.assumeRequest,carrier.template.scope,sourceTags);
 const expectedRequests=new Map(),addRequest=(key,action,request,cap,descriptor)=>expectedRequests.set(key,{action:'LegacyBootstrap'+action,requestHash:hash(request),cap,descriptor});
 const issuerKeys=issuerSource.provider==='instance-metadata'?['source-token','source-credentials','identity-source','assume','identity-target']:['identity-source','assume','identity-target'];
 if(issuerSource.provider==='instance-metadata')for(const [i,profile]of metadataProfiles.entries())addRequest(issuerKeys[i],profile.action,metadataRequests[i],{requestBytes:profile.requestBytes,responseBytes:profile.responseBytes});
 addRequest('identity-source','GetCallerIdentity',{},caps.identity);addRequest('assume','AssumeRole',value.assumeRequest,caps.assume);addRequest('identity-target','GetCallerIdentity',{},caps.identity);
 for(const n of nodes.values())if(manifests.has(n.mediaType))addRequest('manifest:'+n.digest,'BatchGetImage',{registryId:b.account,repositoryName:b.repositoryName,imageIds:[{imageDigest:n.digest}]},caps.manifest,n);
 else{addRequest('url:'+n.digest,'GetDownloadUrlForLayer',{registryId:b.account,repositoryName:b.repositoryName,layerDigest:n.digest},caps.url,n);addRequest('blob:'+n.digest,'S3BlobGet',{repositoryName:b.repositoryName,layerDigest:n.digest},{requestBytes:0,responseBytes:n.size},n);}
 const reservations=new Set(),filesystemSequences=new Set(),seenFs=new Set(),done=new Set();let active=null,wire=0,ecr=0,logical=0,uncompressed=0,entries=0,first=null,last=null,sourceLocalSequence=null;
 for(const e of events){const x=e.data;
  need(!active||!['reservation','prepayment'].includes(e.type),'NonrootBeforeCopyLegacyConcurrent');
  if(e.type==='reservation'&&x.action.startsWith('LegacyBootstrap')){
   need(!active&&e.sequence<=carrier.debitSequence,'NonrootBeforeCopyLegacyOrder');let key;
   if(done.size<issuerKeys.length)key=issuerKeys[done.size];
   else key=[...expectedRequests].find(([k,q])=>!done.has(k)&&q.action===x.action&&q.requestHash===x.requestHash)?.[0];
   const q=expectedRequests.get(key);need(q&&x.action===q.action&&x.requestHash===q.requestHash&&!reservations.has(x.id),'NonrootBeforeCopyLegacyRequest');
   if(key.startsWith('manifest:'))need(done.has('identity-target')&&(![...done].some(k=>k.startsWith('manifest:'))?key==='manifest:'+b.rootDigest:true),'NonrootBeforeCopyLegacyOrder');
   if(key.startsWith('url:'))need([...expectedRequests.keys()].filter(k=>k.startsWith('manifest:')).every(k=>done.has(k)),'NonrootBeforeCopyLegacyOrder');
   if(key.startsWith('blob:'))need(done.has('url:'+q.descriptor.digest),'NonrootBeforeCopyLegacyOrder');
   const isEcr=key.startsWith('manifest:')||key.startsWith('url:'),bytes=q.cap.requestBytes+q.cap.responseBytes;
   need(x.bound===bytes+unknownBytes&&x.ecr===isEcr,'NonrootBeforeCopyLegacyCap');
   same(x.reserveDebit,{...zero(),ecrRequests:isEcr?1:0,httpBodyBytes:bytes+(first===null?unknownBytes:0)},'NonrootBeforeCopyLegacyDebit');
   if(first===null&&p.version===2){
    // The native source adapter charges its bounded file/raw/journal envelope
    // once before touching source files. This is its existing conservative
    // LOCAL charge, not an additional debit or a measurement of HTTP bodies.
    const local=events[e.sequence-2];need(local?.type==='logical','NonrootBeforeCopyLegacySourceLocal');
    same(local.data,{purpose:'metadata',bytes:ORIGINAL_ISSUER_LIMITS.localBytes,reserveDebit:{...zero(),logicalBytes:ORIGINAL_ISSUER_LIMITS.localBytes}},'NonrootBeforeCopyLegacySourceLocal');
    logical+=ORIGINAL_ISSUER_LIMITS.localBytes;sourceLocalSequence=local.sequence;
   }
   if(first===null)first=e.sequence;reservations.add(x.id);active={id:x.id,key,q};if(isEcr)ecr++;
  }else if(e.type==='completed'&&active&&x.id===active.id){
   need(integer(x.charged)&&x.charged<=active.q.cap.requestBytes+active.q.cap.responseBytes&&hex(x.responseHash),'NonrootBeforeCopyLegacyResponse');
   if(active.key==='source-token'||active.key==='source-credentials')need(positive(x.charged),'NonrootBeforeCopyLegacyResponse');
   if(active.key.startsWith('blob:'))need(x.charged===active.q.descriptor.size&&x.responseHash===active.q.descriptor.digest.slice(7),'NonrootBeforeCopyLegacyBlob');
   wire+=x.charged;done.add(active.key);active=null;last=e.sequence;
  }else if(e.type==='unknown'&&reservations.has(x.id))need(false,'NonrootBeforeCopyLegacyUnknown');
  else if(e.type==='filesystem'&&(x.phase==='control-before-copy'||x.component.startsWith('legacy-'))){
   need(!active&&done.size===expectedRequests.size&&e.sequence<carrier.debitSequence&&x.phase==='control-before-copy'&&allowedFs.has(x.component)&&!seenFs.has(x.component),'NonrootBeforeCopyLegacyFilesystem');
   if(x.component==='legacy-bootstrap')need(seenFs.size===0&&x.uncompressedBytes===d.localUsed.uncompressedBytes&&x.processedEntries===d.localUsed.processedEntries,'NonrootBeforeCopyLegacyFilesystem');
   else need(seenFs.has('legacy-bootstrap'),'NonrootBeforeCopyLegacyFilesystem');
   if(allowedFs.get(x.component)!==null)need(x.processedEntries===allowedFs.get(x.component),'NonrootBeforeCopyLegacyFilesystem');
   same(x.reserveDebit,{...zero(),uncompressedBytes:x.uncompressedBytes,processedEntries:x.processedEntries},'NonrootBeforeCopyLegacyDebit');
   need(integer(x.uncompressedBytes)&&integer(x.processedEntries),'NonrootBeforeCopyLegacyFilesystem');uncompressed+=x.uncompressedBytes;entries+=x.processedEntries;filesystemSequences.add(e.sequence);seenFs.add(x.component);last=e.sequence;
  }
  if(first!==null&&e.sequence<carrier.debitSequence&&e.type==='logical'&&x.purpose==='metadata'){same(x.reserveDebit,{...zero(),logicalBytes:x.bytes},'NonrootBeforeCopyLegacyDebit');need(integer(x.bytes),'NonrootBeforeCopyLegacyLocal');logical+=x.bytes;}
 }
 need(!active&&done.size===expectedRequests.size&&seenFs.has('legacy-bootstrap')&&[...layers.keys()].every(i=>seenFs.has('legacy-package-layer-'+i)),'NonrootBeforeCopyLegacyIncomplete');
 need(logical>=d.localUsed.logicalBytes&&logical<=p.bounds.localBytes&&wire<=p.charge.httpBodyBytes&&ecr<=p.charge.ecrRequests&&uncompressed<=p.bounds.uncompressedBytes&&entries<=p.bounds.processedEntries,'NonrootBeforeCopyLegacyBounds');
 return {reservations,filesystemSequences,firstSequence:sourceLocalSequence??first,lastSequence:last};
}

/** payments.originalIssuers.journals is exactly the two original {plan,records}
 * journals. Legacy documents use {ref:{path,sha256},raw:<canonical base64 of
 * ORIGINAL file bytes>}; assumeRequest contains no credential or response body.
 * The enclosing replay owns all counter updates and full DATA completion.
 * Returned sets/maps identify accepted ORIGINAL events, never new debits. */
export function verifyNonrootBeforeCopyAccounting(value,{startRaw,events,copyReceipt,expectedFunding,expectedBudgetRevision,expectedBudgetCeiling,expectedFenceAcquisition}){
 const payments=copyNonrootJson(value);exact(payments,['version','originalIssuers','carrierGrant',...(Object.hasOwn(payments,'legacyBootstrap')?['legacyBootstrap']:[]),...(Object.hasOwn(payments,'fenceAcquisition')?['fenceAcquisition']:[])]);need(payments.version===1,'NonrootBeforeCopyVersion');
 need(typeof startRaw==='string'&&startRaw.length<=32768,'NonrootBeforeCopyStart');const raw=Buffer.from(startRaw,'base64');need(raw.toString('base64')===startRaw&&sha(raw)===copyReceipt.combinedPass.ledgerStartHash,'NonrootBeforeCopyStart');
 const start=parseNonrootJson(new TextDecoder('utf-8',{fatal:true}).decode(raw));need(start.mode==='copy','NonrootBeforeCopyStart');
 const policy=nonrootAccountingPolicy(start.budgetRevision,expectedBudgetRevision,expectedBudgetCeiling);
 need(start.version===policy.version,'NonrootBeforeCopyStart');
 const binding=copyReceipt.combinedPass.binding;same(start.binding,binding);need(binding.owner===copyReceipt.owner&&binding.planHash===copyReceipt.planHash&&binding.publicationHash===copyReceipt.publicationHash,'NonrootBeforeCopyBinding');
 need(start.deadlineMs===copyReceipt.summary.startedMs+L.maxStageMs&&Array.isArray(events)&&events.length>0&&events.length<=20000,'NonrootBeforeCopyEvents');
 let previous=null;for(const [i,e]of events.entries()){need(e.sequence===i+1&&e.previousHash===previous,'NonrootBeforeCopyChain');for(const k of Object.keys(binding))need(e[k]===binding[k],'NonrootBeforeCopyBinding');previous=hash(e);}
 const firstData=events.find(e=>e.type==='cache-begin'||e.type==='scan-pool-prepayment'||e.type==='combined-pass-start'||e.type==='reservation'&&['BatchGetImage','GetDownloadUrlForLayer','BatchCheckLayerAvailability','InitiateLayerUpload','PutImage'].includes(e.data.action))?.sequence??events.length+1;
 const prepayments=new Map(),all=events.filter(e=>e.type==='prepayment');
 const add=(planHash,scopeHash,charge)=>{const rows=all.filter(e=>e.data.planHash===planHash);need(rows.length===1,'NonrootBeforeCopyPaymentOnce');const e=rows[0];need(e.sequence<firstData&&!prepayments.has(e.sequence),'NonrootBeforeCopyPaymentOrder');same(e.data,{allocationId:planHash,planHash,scopeHash,charge,reserveDebit:charge},'NonrootBeforeCopyDebit');prepayments.set(e.sequence,charge);return e;};
 exact(payments.originalIssuers,['budget','journals']);const {budget,journals}=payments.originalIssuers;
 const compiled=compileOriginalIssuersBudget({source:budget.source});same(budget,compiled,'NonrootBeforeCopyIssuerBudget');need(Array.isArray(journals)&&journals.length===2,'NonrootBeforeCopyIssuers');
 const issuerEvents=new Map();let sourceTags;
 for(const journal of journals){
  const {plan:p,planHash,scopeHash,charge}=inspectOriginalIssuerPlan(journal.plan),purpose=p.slot.purpose;
  need(!issuerEvents.has(purpose)&&p.ledgerStartHash===sha(raw)&&p.scope.account===copyReceipt.summary.account&&p.scope.region===copyReceipt.summary.region&&p.scope.owner===binding.owner,'NonrootBeforeCopyIssuerBinding');
  same(p.identities,{sourceRoleArn:`arn:aws:iam::${p.scope.account}:role/aws-compliance-role`,targetRoleArn:`arn:aws:iam::${p.scope.account}:role/BedrockTrackedInvoke`},'NonrootBeforeCopyIssuerIdentity');
  const e=add(planHash,scopeHash,charge);verifyOriginalIssuerJournal(journal,{binding,sourceHash:compiled.sourceHash,deadlineMs:start.deadlineMs,debitEventHash:hash(e)});
  need(journal.records.filter(r=>r.kind==='request'||r.kind==='response').every(r=>r.data.atMs>=copyReceipt.summary.startedMs),'NonrootBeforeCopyIssuerTime');
  if(sourceTags)same(sourceTags,p.sourceTags,'NonrootBeforeCopyIssuerSource');else sourceTags=p.sourceTags;issuerEvents.set(purpose,e);
 }
 need(issuerEvents.has('ci-reader')&&issuerEvents.has('copy'),'NonrootBeforeCopyIssuers');
 const g=payments.carrierGrant,p=g.plan;const verified=verifyCarrierBeforeCopyGrant(g,{grantHash:hash(g),templateHash:p.templateHash,configHash:binding.planHash,ledgerStartHash:sha(raw),...(policy.version===2?{budgetRevision:policy.budgetRevision,compiledCeiling:policy.caps}:{})});
 same(p.ledgerBinding,binding);same(g.debit.startRaw,startRaw,'NonrootBeforeCopyCarrierPrefix');
 const n=g.debit.events.length;need(n<=events.length&&n>0,'NonrootBeforeCopyCarrierPrefix');same(g.debit.events,events.slice(0,n),'NonrootBeforeCopyCarrierPrefix');
 const carrierEvent=add(g.planHash,g.debit.events.at(-1).data.scopeHash,verified.budget.total);
 need(carrierEvent.sequence===n&&issuerEvents.get('ci-reader').sequence<n&&n<issuerEvents.get('copy').sequence&&p.template.scope.account===copyReceipt.summary.account&&p.template.scope.region===copyReceipt.summary.region,'NonrootBeforeCopyCarrierBinding');
 if(expectedFunding){const keys=['repository','prNumber','candidateRevision','candidateTree','baseRevision'];same(Object.fromEntries(keys.map(k=>[k,p.template.source[k]])),expectedFunding.source,'NonrootBeforeCopyProofSource');}
 need(Object.hasOwn(payments,'fenceAcquisition')===(expectedFenceAcquisition!==undefined),'NonrootFenceExpected');
 if(expectedFenceAcquisition){
  exact(expectedFenceAcquisition,['budget','ownerAuthorizationHash','parentStartHash']);exact(payments.fenceAcquisition,['version','plan']);need(payments.fenceAcquisition.version===1,'NonrootFencePaymentVersion');
  const rootStart=events.find(r=>r.type==='root-pool-prepayment');
  const checked=verifyNonrootFenceAcquisitionPayment(payments.fenceAcquisition,{expected:{...expectedFenceAcquisition,ledgerBinding:binding,ledgerStartHash:sha(raw),budgetRevision:policy.budgetRevision,deadlineMs:start.deadlineMs},events,carrierSequence:carrierEvent.sequence,rootSequence:rootStart?.sequence});
  add(checked.planHash,checked.scopeHash,checked.charge);
 }
 need(all.length===prepayments.size&&prepayments.size===(expectedFenceAcquisition?4:3),'NonrootBeforeCopyUnknownPayment');
 let legacy={reservations:new Set(),filesystemSequences:new Set()};
 if(payments.legacyBootstrap){legacy=legacyAccounting(payments.legacyBootstrap,{start,events,carrier:{...p,debitSequence:n},sourceTags,issuerSource:compiled.source});need(legacy.firstSequence>issuerEvents.get('ci-reader').sequence&&legacy.lastSequence<n,'NonrootBeforeCopyLegacyOrder');}
 else need(!events.some(e=>e.type==='reservation'&&e.data.action.startsWith('LegacyBootstrap')||e.type==='filesystem'&&(e.data.phase==='control-before-copy'||e.data.component.startsWith('legacy-'))),'NonrootBeforeCopyLegacyRequired');
 return {prepayments,legacyReservations:legacy.reservations,legacyFilesystemSequences:legacy.filesystemSequences};
}
