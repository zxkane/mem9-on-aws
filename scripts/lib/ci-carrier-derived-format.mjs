/** Shared R13 wire format. The producer retains the actual handles; this
 * formatter never restores a live native/graph context from serialized data. */
import {createHash} from 'node:crypto';
import {copyNonrootJson,inspectNonrootRecord,parseNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {inspectCarrierFundingPlan} from './ci-carrier-before-copy.mjs';
import {carrierDockerfile,inspectMaterializedCarrierContext} from './ci-carrier-context.mjs';
import {IMAGE_MEDIA,validateImageDescriptor,controlImageGraphBinding,imageGraphState} from './production-image-graph.mjs';
import {inspectImageFilesystemFile} from './production-image-filesystem.mjs';
import {inspectNonrootControlPrerequisites} from './production-nonroot-control-prerequisites.mjs';
const need=(v,c='CarrierDerivedInvalid')=>{if(!v)throw Error(c);},same=(a,b,c='CarrierDerivedBinding')=>need(hash(a)===hash(b),c);
const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join(),'CarrierDerivedFields');
const sha=b=>createHash('sha256').update(b).digest('hex'),hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const zero=()=>({ecrRequests:0,httpBodyBytes:0,logicalBytes:0,uncompressedBytes:0,processedEntries:0});
export const CARRIER_RUNTIME_MANIFEST_PATH='rootfs/carrier/manifest.json',CARRIER_DERIVED_CA_PATH='rootfs/bootstrap/global-bundle.pem';
const manifests=new Set([IMAGE_MEDIA.index,IMAGE_MEDIA.dockerIndex,IMAGE_MEDIA.manifest,IMAGE_MEDIA.dockerManifest]);
const metadataTypes=new Set([...manifests,IMAGE_MEDIA.config,IMAGE_MEDIA.dockerConfig,IMAGE_MEDIA.emptyConfig,IMAGE_MEDIA.attestation].filter(Boolean));
export function carrierSourceDockerfile(base){inspectNonrootRecord('ControlImageBindingV1',base);return carrierDockerfile(base,{caPresent:true,derived:true});}
export function inspectCarrierSourceManifest(value,planValue){
 const p=inspectCarrierFundingPlan(planValue),m=copyNonrootJson(value);
 exact(m,['version','kind','templateHash','sourceTree','provenance','runtimeSource','files']);
 need(m.version===2&&m.kind==='carrier-build-source-context'&&m.templateHash===p.templateHash&&m.sourceTree===p.template.source.candidateTree&&hash(m)===p.context.manifestHash,'CarrierSourceContextBinding');
 exact(m.runtimeSource,['legacyCodeHash','expandedSourceHash','minifiedSourceHash','dependencyHash','operatorInventoryHash']);need(Object.values(m.runtimeSource).every(hex)&&m.runtimeSource.legacyCodeHash===p.template.anchors.hostCodeHash&&m.runtimeSource.expandedSourceHash===p.template.anchors.hostSourceHash,'CarrierSourceLegacy');
 same(m.provenance,{oldImageHash:hash(p.template.anchors.oldImage),oldImageEvidenceHash:p.template.anchors.oldImageEvidenceHash,hostEvidenceHash:p.template.anchors.hostEvidenceHash,sourceCiHash:p.template.anchors.sourceCiHash,baseEvidenceHash:p.template.anchors.baseEvidenceHash});
 need(Array.isArray(m.files)&&m.files.length>0&&m.files.length<=p.template.bounds.contextFiles&&new Set(m.files.map(f=>f.path)).size===m.files.length,'CarrierSourceMembers');
 for(const file of m.files)need(![CARRIER_RUNTIME_MANIFEST_PATH,CARRIER_DERIVED_CA_PATH].includes(file.path),'CarrierSuppliedDerivedCollision');return m;
}
export function carrierRuntimeManifest(context,plan,native,ca){
 const m=inspectCarrierSourceManifest(context,plan);need(ca.present===true&&ca.sourcePath==='/bootstrap/global-bundle.pem','CarrierDerivedCa');
 const files=m.files.filter(row=>row.path!=='Dockerfile').map(({path,bytesLength,...row})=>({...row,path:path.slice(6),bytes:bytesLength}));
 files.push({path:'/bootstrap/global-bundle.pem',type:'file',mode:0o444,sha256:ca.sha256,bytes:ca.bytesLength});files.sort((a,b)=>a.path.localeCompare(b.path));
 return copyNonrootJson({version:1,...m.runtimeSource,runtime:{nodeSha256:native.nodeRuntime.executableSha256,setprivSha256:native.primitiveEvidence.fileSha256},files,caPath:'/bootstrap/global-bundle.pem'});
}
function decode(row){need(typeof row.bytesBase64==='string','CarrierDerivedEncoding');const b=Buffer.from(row.bytesBase64,'base64');need(b.toString('base64')===row.bytesBase64&&b.length===row.bytesLength&&sha(b)===row.sha256,'CarrierDerivedBytes');return b;}
export function inspectCarrierDerivedMaterial(value,{plan:input,grantHash,contextManifest}={}){
 const p=inspectCarrierFundingPlan(input),d=copyNonrootJson(value);exact(d,['version','kind','templateHash','grantHash','contextHash','baseImage','baseGraphHash','baseMetadata','nativeEvidence','ca','files']);
 need(d.version===1&&d.kind==='carrier-derived-runtime-material'&&d.templateHash===p.templateHash&&hex(grantHash)&&d.grantHash===grantHash&&d.contextHash===p.context.sha256&&hex(d.baseGraphHash),'CarrierDerivedBinding');same(d.baseImage,p.template.base);
 const n=d.nativeEvidence;exact(n,['record','recordRef','nodeRuntime','primitiveEvidence','environment','objects']);inspectNonrootRecord('NodeRuntimeV1',n.nodeRuntime);inspectNonrootRecord('PrimitiveEvidenceV1',n.primitiveEvidence);inspectNonrootRecord('JsonRef',n.recordRef);
 same(n.record.image,d.baseImage);need(n.record.graphHash===d.baseGraphHash&&n.record.sourceTree===p.template.source.candidateTree,'CarrierDerivedNativeBinding');
 need(Array.isArray(n.objects)&&n.objects.length>0&&n.objects.length<=1000,'CarrierDerivedNativeObjects');const objects=new Map();
 for(const row of n.objects){exact(row,['ref','bytesBase64']);const json=Object.hasOwn(row.ref,'canonicalHash');inspectNonrootRecord(json?'JsonRef':'ByteRef',row.ref);const b=Buffer.from(row.bytesBase64,'base64');need(b.toString('base64')===row.bytesBase64&&b.length===row.ref.bytesLength&&sha(b)===(row.ref.bytesHash??row.ref.sha256),'CarrierDerivedNativeObject');if(json)need(hash(parseNonrootJson(b.toString()))===row.ref.canonicalHash,'CarrierDerivedNativeObject');const key=hash(row.ref);need(!objects.has(key),'CarrierDerivedNativeObject');objects.set(key,b);}
 need(objects.has(hash(n.recordRef))&&hash(parseNonrootJson(objects.get(hash(n.recordRef)).toString()))===hash(n.record),'CarrierDerivedNativeRecord');
 const {rootDigest,arm64Digest,configDigest}=d.baseImage;same(n.nodeRuntime.image,{rootDigest,arm64Digest,configDigest});same(n.primitiveEvidence.image,n.nodeRuntime.image);
 need(Array.isArray(d.baseMetadata)&&d.baseMetadata.length>0&&d.baseMetadata.length<=p.template.bounds.manifestNodes+p.template.bounds.blobNodes,'CarrierDerivedBaseMetadata');const meta=new Set();let total=0;
 for(const row of d.baseMetadata){exact(row,['descriptor','bytesBase64']);const v=row.descriptor;need(metadataTypes.has(v.mediaType),'CarrierDerivedLayerInEvidence');validateImageDescriptor(v,manifests.has(v.mediaType)?'manifest':'blob');need(!meta.has(v.digest),'CarrierDerivedBaseMetadata');meta.add(v.digest);const b=Buffer.from(row.bytesBase64,'base64');need(b.toString('base64')===row.bytesBase64&&b.length===v.size&&'sha256:'+sha(b)===v.digest,'CarrierDerivedBaseMetadata');parseNonrootJson(b.toString());total+=b.length;}
 need([rootDigest,arm64Digest,configDigest].every(h=>meta.has(h))&&total<=p.template.bounds.compressedBytes,'CarrierDerivedBaseMetadata');
 exact(d.ca,['present','sourcePath','sha256','bytesLength']);need(d.ca.present===true&&d.ca.sourcePath==='/bootstrap/global-bundle.pem'&&hex(d.ca.sha256)&&Number.isSafeInteger(d.ca.bytesLength)&&d.ca.bytesLength>0&&d.ca.bytesLength<=1048576,'CarrierDerivedCa');
 need(Array.isArray(d.files)&&d.files.length===2,'CarrierDerivedFiles');const names=new Set();
 for(const row of d.files){exact(row,['path','type','mode','sha256','bytesLength','bytesBase64']);need(row.type==='file'&&row.mode===0o444&&hex(row.sha256)&&Number.isSafeInteger(row.bytesLength)&&row.bytesLength>0&&!names.has(row.path)&&[CARRIER_RUNTIME_MANIFEST_PATH,CARRIER_DERIVED_CA_PATH].includes(row.path),'CarrierDerivedFile');decode(row);names.add(row.path);}
 need(names.has(CARRIER_RUNTIME_MANIFEST_PATH)&&names.has(CARRIER_DERIVED_CA_PATH),'CarrierDerivedFiles');const ca=d.files.find(row=>row.path===CARRIER_DERIVED_CA_PATH);need(ca.sha256===d.ca.sha256&&ca.bytesLength===d.ca.bytesLength,'CarrierDerivedCa');
 if(contextManifest!==undefined){const expected=Buffer.from(JSON.stringify(carrierRuntimeManifest(contextManifest,p,n,d.ca))),row=d.files.find(r=>r.path===CARRIER_RUNTIME_MANIFEST_PATH);need(decode(row).equals(expected),'CarrierDerivedManifest');}
 need(Buffer.byteLength(JSON.stringify(d))<=p.template.bounds.resultBytes,'CarrierDerivedResultBytes');return d;
}

/** Serialize the producer's existing real probe; no second probe or download. */
export async function formatCarrierDerivedMaterial({context,grantHash,baseGraph,baseFilesystem,prerequisites,sourceContext,metadataReads}){
 const c=inspectMaterializedCarrierContext(context),p=c.plan,m=inspectCarrierSourceManifest(c.manifest,p),{graphHash,...baseImage}=controlImageGraphBinding(baseGraph);same(baseImage,p.template.base);
 const n=inspectNonrootControlPrerequisites(prerequisites,{controlVerification:{graph:baseGraph,filesystem:baseFilesystem},sourceContext}),charge=bytes=>{need(Date.now()<p.deadlineMs,'CarrierDerivedExpired');metadataReads.reserveLocal({...zero(),logicalBytes:bytes});};
 need(n.environment.caBindings.length===1,'CarrierDerivedCa');const caRef=n.environment.caBindings[0].file,bytes=n.objects.find(o=>hash(o.ref)===hash(caRef))?.bytes;
 need(bytes instanceof Uint8Array,'CarrierDerivedCa');const fact=inspectImageFilesystemFile(baseFilesystem,'/bootstrap/global-bundle.pem');need(fact.sha256===caRef.sha256&&fact.size===caRef.bytesLength,'CarrierDerivedCa');
 const ca={present:true,sourcePath:'/bootstrap/global-bundle.pem',sha256:caRef.sha256,bytesLength:caRef.bytesLength},runtime=carrierRuntimeManifest(m,p,n,ca),file=(path,b)=>{b=Buffer.from(b);charge(b.length);return {path,type:'file',mode:0o444,sha256:sha(b),bytesLength:b.length,bytesBase64:b.toString('base64')};};
 const files=[file(CARRIER_RUNTIME_MANIFEST_PATH,Buffer.from(JSON.stringify(runtime))),file(CARRIER_DERIVED_CA_PATH,bytes)],state=imageGraphState(baseGraph),baseMetadata=[];
 for(const descriptor of baseGraph.inventory.nodes)if(metadataTypes.has(descriptor.mediaType)){charge(descriptor.size);const chunks=[];let total=0;for await(const b of state.store.open(descriptor)){metadataReads.reserveLocal(zero());total+=b.length;need(total<=descriptor.size,'CarrierDerivedBaseMetadata');chunks.push(Buffer.from(b));}need(total===descriptor.size,'CarrierDerivedBaseMetadata');baseMetadata.push({descriptor,bytesBase64:Buffer.concat(chunks,total).toString('base64')});}
 const {objects,...rest}=n,nativeEvidence={...rest,objects:objects.map(o=>({ref:o.ref,bytesBase64:Buffer.from(o.bytes).toString('base64')}))};
 const value={version:1,kind:'carrier-derived-runtime-material',templateHash:p.templateHash,grantHash,contextHash:p.context.sha256,baseImage,baseGraphHash:graphHash,baseMetadata,nativeEvidence,ca,files};charge(Buffer.byteLength(JSON.stringify(value)));return inspectCarrierDerivedMaterial(value,{plan:p,grantHash,contextManifest:m});
}
