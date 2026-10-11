import {createHash} from 'node:crypto';
import {nonrootHash as hash,parseNonrootJson,inspectNonrootRecord,NONROOT_LIMITS} from './production-nonroot-contracts.mjs';
import {validateSupersessionLineage} from './production-data-supersession.mjs';

const contexts=new WeakMap(),MAX_MANIFEST_BYTES=NONROOT_LIMITS.maxProofBytes,MAX_JSON_BYTES=NONROOT_LIMITS.maxProofBytes,MAX_BUFFERED_BYTES=67108864;
const names=new Set(['proof.json','review.json','predecessor.json','legacy-bootstrap-proof.json','source-evidence.json','data-origin.json','copy-adoption.json','artifact-reverification.json','task-plan.json','carrier-build.json','carrier-prerequisite-review.json','preaudit-permit.json','guard-launches.json','overlap-plan.json','permissions.json','availability-rehearsal.json','predeployment-root-audit.json','artifact-security.json','policy-sources.json','protected-inputs.json','design-review.json']);
const purposes=new Set(['protocol','source','image-graph','image-blob','filesystem','scan','vendor','policy','copy-journal','recovery','root-audit','runtime-identity','task-definition','iam-boundary','preview','build','lineage','carrier','availability']);
const authorityPurposes=new Set(['protocol','policy','root-audit','runtime-identity','task-definition','iam-boundary','lineage','carrier','availability']);
const fail=code=>{throw Error(code);},need=(v,code='NonrootArchiveInvalid')=>{if(!v)fail(code);};
const sha=b=>createHash('sha256').update(b).digest('hex'),hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const record=v=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&[Object.prototype,null].includes(Object.getPrototypeOf(v))&&Reflect.ownKeys(v).every(k=>typeof k==='string'&&Object.getOwnPropertyDescriptor(v,k).enumerable&&Object.hasOwn(Object.getOwnPropertyDescriptor(v,k),'value'));
const exact=(v,keys)=>record(v)&&Reflect.ownKeys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
const freeze=v=>{if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;};
function decode(bytes,maxBytes){
 need(bytes instanceof Uint8Array&&bytes.length>0&&bytes.length<=maxBytes,'NonrootArchiveBytes');
 const raw=Buffer.from(bytes),text=raw.toString('utf8');need(Buffer.from(text).equals(raw),'NonrootArchiveUtf8');
 const value=parseNonrootJson(text,{maxBytes});return {raw,value};
}
function reference(ref,encoding){
 inspectNonrootRecord(encoding==='json'?'JsonRef':'ByteRef',ref);
}
function get(context){const state=contexts.get(context);need(state,'NonrootArchiveContext');return state;}
function context(state){const value=Object.freeze({kind:'nonroot-evidence-archive'});contexts.set(value,state);return value;}

/** Verifies an independently pinned inventory, not its authority. readObject is
 * supplied by trusted code and receives only a validated fixed-owner basename.
 * It is never selected by a JSON field, remote path, URL or account override. */
export function createNonrootEvidenceArchive(rawManifest,{expectedManifestHash,readObject}={}){
 need(hex(expectedManifestHash)&&typeof readObject==='function','NonrootArchivePinRequired');
 const {raw,value:manifest}=decode(typeof rawManifest==='string'?Buffer.from(rawManifest):rawManifest,MAX_MANIFEST_BYTES);
 inspectNonrootRecord('ArchiveManifestV2',manifest);
 need(exact(manifest,['version','kind','owner','files'])&&manifest.version===2&&manifest.kind==='nonroot-proof-archive'&&/^[a-f0-9]{32}$/.test(manifest.owner)&&Array.isArray(manifest.files)&&manifest.files.length>0,'NonrootArchiveManifest');
 need(hash(manifest)===expectedManifestHash,'NonrootArchiveManifestPin');
 const byName=new Map(),byCanonical=new Map();
 for(const row of manifest.files){
  need(exact(row,['name','purpose','ref','encoding'])&&typeof row.name==='string'&&purposes.has(row.purpose)&&['json','bytes'].includes(row.encoding),'NonrootArchiveFile');
  reference(row.ref,row.encoding);
  const support=/^sha256-([a-f0-9]{64})\.(json|bin)$/.exec(row.name);
  need(names.has(row.name)?row.encoding==='json':support&&support[1]===(row.ref.bytesHash??row.ref.sha256)&&support[2]===(row.encoding==='json'?'json':'bin'),'NonrootArchiveName');
  need(!byName.has(row.name),'NonrootArchiveDuplicateName');byName.set(row.name,row);
  if(row.encoding==='json'){
   const key=row.purpose+'\0'+row.ref.canonicalHash;need(!byCanonical.has(key),'NonrootArchiveAmbiguousCommitment');byCanonical.set(key,row);
  }
 }
 return context({kind:'evidence-integrity',manifest:freeze(manifest),manifestText:raw.toString('utf8'),manifestHash:expectedManifestHash,manifestRef:freeze({bytesHash:sha(raw),canonicalHash:expectedManifestHash,bytesLength:raw.length}),byName,byCanonical,readObject,used:new Set()});
}

function options(value){need(record(value)&&Object.keys(value).every(k=>['purpose','kind'].includes(k))&&purposes.has(value.purpose)&&(value.kind===undefined||typeof value.kind==='string'&&value.kind.length>0&&value.kind.length<=256),'NonrootArchiveReadOptions');}
async function read(state,row,requested,rawOnly=false){
 const returned=await state.readObject(row.name);
 need(returned instanceof Uint8Array&&returned.length===row.ref.bytesLength&&returned.length<=(row.encoding==='json'?MAX_JSON_BYTES:MAX_BUFFERED_BYTES),'NonrootArchiveObjectSize');
 const raw=Buffer.from(returned);need(sha(raw)===(row.ref.bytesHash??row.ref.sha256),'NonrootArchiveObjectPin');
 let value;
 if(row.encoding==='json'){
  value=decode(raw,MAX_JSON_BYTES).value;need(hash(value)===row.ref.canonicalHash,'NonrootArchiveCanonicalPin');
  if(requested.kind!==undefined)need(value?.kind===requested.kind,'NonrootArchiveKind');
  freeze(value);
 }else{need(requested.kind===undefined,'NonrootArchiveKind');value=raw;}
 state.used.add(row.name);return rawOnly?raw:value;
}

export async function readNonrootArchiveRef(archive,ref,requested){
 const state=get(archive);options(requested);const encoding=Object.hasOwn(ref??{},'canonicalHash')?'json':'bytes';reference(ref,encoding);
 const rows=[...state.byName.values()].filter(row=>row.encoding===encoding&&row.purpose===requested.purpose&&hash(row.ref)===hash(ref));
 need(rows.length===1,'NonrootArchiveReferenceMissing');return read(state,rows[0],requested);
}

export async function resolveNonrootArchiveCommitment(archive,canonicalHash,requested){
 const state=get(archive);options(requested);need(hex(canonicalHash),'NonrootArchiveCommitment');
 const row=state.byCanonical.get(requested.purpose+'\0'+canonicalHash);need(row,'NonrootArchiveCommitmentMissing');return read(state,row,requested);
}

export function nonrootArchiveBindings(archive){
 const s=get(archive);return freeze({kind:s.kind,authority:false,owner:s.manifest.owner,manifestHash:s.manifestHash,manifestRef:{...s.manifestRef},...(s.binding?{binding:structuredClone(s.binding)}:{})});
}

/** Original frozen inventory only; selecting rows never reads object bodies. */
export function nonrootArchiveInventory(archive){return get(archive).manifest;}

/** Byte-preserving resolver pair for the shared runtime/launch verifiers. A
 * reference must select one inventory entry even when no purpose is supplied.
 * These functions do not accept caller filenames or parsed evidence objects. */
export function nonrootArchiveResolvers(archive){
 const state=get(archive);
 const resolve=async(ref,encoding)=>{
  reference(ref,encoding);const matches=[...state.byName.values()].filter(row=>row.encoding===encoding&&hash(row.ref)===hash(ref));
  need(matches.length===1,'NonrootArchiveReferenceAmbiguous');
  return read(state,matches[0],{purpose:matches[0].purpose},true);
 };
 return Object.freeze({resolveJson:ref=>resolve(ref,'json'),resolveBytes:ref=>resolve(ref,'bytes')});
}

/** Restore an original private receipt reference by its raw digest only. Its
 * historical filesystem path is never opened or treated as an archive key. */
export async function resolveNonrootArchiveRawJson(archive,bytesHash){
 const state=get(archive);need(hex(bytesHash),'NonrootArchiveRawCommitment');
 const rows=[...state.byName.values()].filter(row=>row.encoding==='json'&&row.ref.bytesHash===bytesHash);
 need(rows.length===1,'NonrootArchiveRawCommitmentMissing');
 return read(state,rows[0],{purpose:rows[0].purpose},true);
}

/** Each full verifier starts a private read scope. Prior caller reads cannot
 * make an otherwise unreferenced authority object count as verified evidence. */
export function forkNonrootArchive(archive){const s=get(archive);return context({...s,used:new Set(s.custodyNames??[])});}
export function assertNonrootArchiveConsumed(archive){
 const s=get(archive);for(const row of s.byName.values())if(authorityPurposes.has(row.purpose))need(s.used.has(row.name),'NonrootArchiveUnreferencedAuthority');
}

/** Custody from an independently read protected parameter. This does not run
 * the proof verifier or admit deployment; it only permits historical evidence
 * reconstruction. A prospective descriptor cannot satisfy initial live build. */
export async function authenticateNonrootArchive(archive,{parameter,operation},expected){
 archive=forkNonrootArchive(archive);const s=get(archive);s.used=new Set();
 need(exact(expected,['expectedProofHash','expectedDataHash','expectedReviewHash','expectedParameterVersion','expectedScope']),'NonrootArchiveExpected');
 for(const key of ['expectedProofHash','expectedDataHash','expectedReviewHash'])need(hex(expected[key]),'NonrootArchiveExpected');
 need(exact(expected.expectedScope,['account','region','runtimeNonce','authorizationId']),'NonrootArchiveExpected');
 const p=inspectNonrootRecord('ParameterCaptureV1',parameter),op=inspectNonrootRecord('NonrootOperationV2',operation),data=inspectNonrootRecord('DataDescriptorV3',parseNonrootJson(p.Value)),scope=expected.expectedScope;
 need(p.Version===expected.expectedParameterVersion&&p.Version===op.predecessor.Version+1&&p.ARN===`arn:aws:ssm:${scope.region}:${scope.account}:parameter${p.Name}`,'NonrootArchiveParameter');
 for(const key of ['account','region','runtimeNonce','authorizationId'])need(data[key]===scope[key],'NonrootArchiveScope');
 need(s.manifest.owner===data.authorizationId&&hash(data)===expected.expectedDataHash&&data.transition.proofHash===expected.expectedProofHash&&data.policyHash===expected.expectedReviewHash,'NonrootArchiveScope');
 need(hash(op.authorization.data)===expected.expectedDataHash&&op.authorization.hash===expected.expectedDataHash&&hash(op.authorization.review)===expected.expectedReviewHash&&op.expected.proofHash===expected.expectedProofHash,'NonrootArchiveOperation');
 need(hash(op.evidenceManifest)===hash(s.manifestRef),'NonrootArchiveManifestBinding');
 const proof=await resolveNonrootArchiveCommitment(archive,expected.expectedProofHash,{purpose:'protocol',kind:'ecs-nonroot-image-upgrade-proof'}),review=await resolveNonrootArchiveCommitment(archive,expected.expectedReviewHash,{purpose:'protocol',kind:'nonroot-deployment-policy-review'});
 inspectNonrootRecord('NonrootImageProofV2',proof);inspectNonrootRecord('FinalReviewV2',review);
 need(hash(op.predecessor)===proof.predecessorParameter.canonicalHash&&op.predecessor.Name===p.Name&&op.predecessor.ARN===p.ARN,'NonrootArchivePredecessor');
 const operationBindings={account:data.account,region:data.region,sourceEvidenceHash:proof.deploymentControl.sourceEvidence.canonicalHash,
  taskPlanHash:hash(proof.taskPlan),carrierBuildHash:hash(proof.taskPlan.carrierBuild),permissionsHash:hash(proof.taskPlan.permissions),
  availabilityRehearsalHash:hash(proof.taskPlan.overlap.rehearsal),rootBindingHash:hash(proof.root),oldRootAuditHash:hash(proof.predeploymentAudit),
  artifactReverificationHash:hash(proof.artifactReverification),artifactSecurityHash:proof.artifactSecurity.canonicalHash};
 for(const [key,value]of Object.entries(operationBindings))need(op.expected[key]===value,'NonrootArchiveOperation');
 need(review.proofHash===expected.expectedProofHash&&hash(review)===hash(op.authorization.review)&&data.issuedMs===review.reviewedMs&&data.expiresMs===review.expiresMs,'NonrootArchiveReview');
 need(op.operation.expected.revision===proof.deploymentControl.revision&&op.expected.controlRevision===proof.deploymentControl.revision&&op.expected.controlSourceTree===data.controlSourceTree,'NonrootArchiveSource');
 const commitment={version:2,kind:'image-security-nonroot-transition',predecessorHash:hash(op.predecessor),predecessorVersion:op.predecessor.Version,authorizationHash:expected.expectedDataHash,authorizationId:data.authorizationId,nextVersion:p.Version};
 need(op.operation.expected.newValue===JSON.stringify(commitment)&&op.operation.prior.value===op.predecessor.Value,'NonrootArchiveOperation');
 const previous=parseNonrootJson(op.predecessor.Value);need(previous.version===1&&data.transition.predecessorHash===hash(previous),'NonrootArchivePredecessor');
 const lineage=await readNonrootArchiveRef(archive,op.lineage,{purpose:'lineage'});need(validateSupersessionLineage(lineage,op.predecessor,data.authorizationId)===op.expected.lineageHash,'NonrootArchiveLineage');
 return context({...s,kind:'published-archive',binding:freeze({proofHash:expected.expectedProofHash,dataHash:expected.expectedDataHash,reviewHash:expected.expectedReviewHash,parameterVersion:p.Version,operationHash:hash(op),scope:structuredClone(scope)}),custodyNames:new Set(s.used),used:new Set(s.used)});
}

/** The wire form carries bytes, never a verifier or a restored authority flag. */
export async function exportNonrootArchive(archive){
 const s=get(archive),objects=[];
 for(const row of s.manifest.files){const raw=await read(s,row,{purpose:row.purpose},true);objects.push({name:row.name,base64:raw.toString('base64')});}
 return {version:1,kind:'nonroot-evidence-bytes',manifest:s.manifestText,objects};
}
export function importNonrootArchive(value,{expectedManifestHash}){
 need(exact(value,['version','kind','manifest','objects'])&&value.version===1&&value.kind==='nonroot-evidence-bytes'&&typeof value.manifest==='string'&&Array.isArray(value.objects),'NonrootArchiveWire');
 const objects=new Map();let total=0;
 for(const row of value.objects){
  need(exact(row,['name','base64'])&&typeof row.name==='string'&&typeof row.base64==='string'&&!objects.has(row.name),'NonrootArchiveWire');
  // Bound allocation before decoding. Re-encoding checks alphabet, padding
  // and unused pad bits without a repeated-group regexp that overflows the
  // JavaScript regexp stack on legitimate multi-megabyte source evidence.
  need(row.base64.length<=Math.ceil((32*1024*1024-total)/3)*4,'NonrootArchiveWireLimit');
  need(row.base64.length%4===0,'NonrootArchiveWire');
  const size=Buffer.byteLength(row.base64,'base64');total+=size;need(size<=MAX_BUFFERED_BYTES&&total<=32*1024*1024,'NonrootArchiveWireLimit');
  const raw=Buffer.from(row.base64,'base64');need(raw.toString('base64')===row.base64,'NonrootArchiveWire');objects.set(row.name,raw);
 }
 const archive=createNonrootEvidenceArchive(value.manifest,{expectedManifestHash,readObject:async name=>objects.get(name)}),s=get(archive);
 need(objects.size===s.byName.size&&[...objects.keys()].every(name=>s.byName.has(name)),'NonrootArchiveWireInventory');return archive;
}
