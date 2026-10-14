/** Decode only the owner's R9 framed context. No tar extraction, package
 * installation, credentials, user-selected recipe or executable callbacks. */
import {constants} from 'node:fs';
import {open,mkdir,lstat,realpath,readdir,readlink,symlink,chmod,rm} from 'node:fs/promises';
import {join,dirname,resolve,posix} from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {inspectCarrierFundingPlan} from './ci-carrier-before-copy.mjs';
import {copyNonrootJson} from './production-nonroot-contracts.mjs';
import {parseAcquisitionJson,hash,freeze} from './ci-smoke-acquisition-format.mjs';

export const CARRIER_CONTEXT_MAGIC=Buffer.from('MEM9-CARRIER-CONTEXT-V1\n');
export const CARRIER_OPERATOR_FILES=Object.freeze([
 'infra/gateway/service-auth.mjs','scripts/lib/canary-benchmark.mjs','scripts/lib/consolidation-preview-secrets.mjs',
 'scripts/lib/production-artifacts.mjs','scripts/lib/production-canary-compatibility.mjs','scripts/lib/production-canary-continuation.mjs',
 'scripts/lib/production-canary-paused-audit.mjs','scripts/lib/production-canary-performance.mjs','scripts/lib/production-canary-report.mjs',
 'scripts/lib/production-canary-snapshot.mjs','scripts/lib/production-canary-verification.mjs','scripts/lib/production-runtime-config.mjs',
 'scripts/lib/production-runtime-state.mjs','scripts/lib/runtime-credentials.mjs','scripts/lib/runtime-extension-catalog.mjs',
 'scripts/production-consolidation-operator.mjs','node_modules/pg/lib/index.js','node_modules/pg/package.json','package.json','package-lock.json',
]);
const operator=new Set(CARRIER_OPERATOR_FILES),operatorPrefix='rootfs/bootstrap/operator/';
const recipePaths=['Dockerfile','rootfs/carrier/guard-first.mjs','rootfs/carrier/supplemental-readonly.mjs'];
const fixedPaths=new Set([...recipePaths,'rootfs/carrier/legacy-audit.mjs','rootfs/carrier/manifest.json','rootfs/bootstrap/global-bundle.pem']);
const contexts=new WeakMap(),sha=b=>createHash('sha256').update(b).digest('hex');
const need=(v,c='CarrierContextInvalid')=>{if(!v)throw Error(c);};
const exact=(v,k)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===k.slice().sort().join(),'CarrierContextFields');
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const zero=()=>({ecrRequests:0,httpBodyBytes:0,logicalBytes:0,uncompressedBytes:0,processedEntries:0});
const same=(a,b,c)=>need(hash(a)===hash(b),c);
const keys=['dev','ino','uid','mode','nlink','size','mtimeMs','ctimeMs'];
const unchanged=(a,b)=>keys.every(k=>a[k]===b[k]);
const decode=b=>new TextDecoder('utf-8',{fatal:true}).decode(b);
const parse=b=>freeze(parseAcquisitionJson(b,33554432));
const pathAllowed=path=>typeof path==='string'&&Buffer.byteLength(path)<=4096&&!path.includes('\\')&&!/[\x00-\x1f\x7f]/.test(path)&&!path.startsWith('/')&&posix.normalize(path)===path&&!path.split('/').some(p=>p==='..'||p==='.ssh'||p.startsWith('.env')||p.includes('.local.'))&&
 (fixedPaths.has(path)||path.startsWith(operatorPrefix)&&(operator.has(path.slice(operatorPrefix.length))||path.startsWith(operatorPrefix+'node_modules/')));

export function carrierDockerfile(base,{caPresent=false,derived=false}={}){
 const image=base.account+'.dkr.ecr.'+base.region+'.amazonaws.com/'+base.repositoryName+'@'+base.rootDigest;
 need(!derived||caPresent,'CarrierDerivedCaRequired');
 return `FROM ${image}\nUSER 0:0\nRUN rm -rf /bootstrap/operator /carrier\nCOPY --chown=0:0 rootfs/ /\n${derived?'COPY --from=carrier_runtime --chown=0:0 rootfs/ /\n':''}RUN chmod 0555 /bootstrap && find /carrier /bootstrap/operator -type d -exec chmod 0555 {} +\nENV PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp NODE_EXTRA_CA_CERTS=${caPresent?'/bootstrap/global-bundle.pem':''}\nUSER 1000:1000\nENTRYPOINT ["/bin/setpriv","--no-new-privs","--","/usr/local/bin/node","/carrier/guard-first.mjs","audit-original-root"]\nCMD []\n`;
}
function inspectManifest(m,plan,baseEvidence){
 const t=plan.template,sourceOnly=m.version===2&&m.kind==='carrier-build-source-context';
 exact(m,['version','kind','templateHash','sourceTree','provenance','files',...(sourceOnly?['runtimeSource']:[])]);
 need((sourceOnly||m.version===1&&m.kind==='carrier-build-context')&&m.templateHash===plan.templateHash&&m.sourceTree===t.source.candidateTree&&hash(m)===plan.context.manifestHash,'CarrierContextBinding');
 if(sourceOnly){
  exact(m.runtimeSource,['legacyCodeHash','expandedSourceHash','minifiedSourceHash','dependencyHash','operatorInventoryHash']);
  need(Object.values(m.runtimeSource).every(hex)&&m.runtimeSource.legacyCodeHash===t.anchors.hostCodeHash&&m.runtimeSource.expandedSourceHash===t.anchors.hostSourceHash,'CarrierRuntimeSource');
  need(baseEvidence===undefined,'CarrierSourceContextNoNativeFacts');
 }
 same(m.provenance,{oldImageHash:hash(t.anchors.oldImage),oldImageEvidenceHash:t.anchors.oldImageEvidenceHash,hostEvidenceHash:t.anchors.hostEvidenceHash,sourceCiHash:t.anchors.sourceCiHash,baseEvidenceHash:t.anchors.baseEvidenceHash},'CarrierContextProvenance');
 if(baseEvidence!==undefined){
  exact(baseEvidence,['version','kind','image','native','ca']);need(baseEvidence.version===1&&baseEvidence.kind==='carrier-secure-base-evidence'&&hash(baseEvidence)===t.anchors.baseEvidenceHash,'CarrierContextBaseEvidence');same(baseEvidence.image,t.base,'CarrierContextBaseImage');
  exact(baseEvidence.native,['nodeSha256','setprivSha256']);need(Object.values(baseEvidence.native).every(hex),'CarrierContextNativePin');
  need(typeof baseEvidence.ca?.present==='boolean','CarrierContextCa');exact(baseEvidence.ca,baseEvidence.ca.present?['present','ref','sourceEvidenceHash']:['present']);
 }
 need(Array.isArray(m.files)&&m.files.length>0&&m.files.length<=t.bounds.contextFiles,'CarrierContextFileCount');
 const byPath=new Map();let total=0;
 for(const row of m.files){
  exact(row,['path','type','mode','sha256','bytesLength',...(row.type==='symlink'?['target']:[])]);
  need(pathAllowed(row.path)&&!byPath.has(row.path),'CarrierContextPath');
  if(sourceOnly)need(!['rootfs/carrier/manifest.json','rootfs/bootstrap/global-bundle.pem'].includes(row.path),'CarrierSuppliedDerivedCollision');
  need(['file','symlink'].includes(row.type)&&hex(row.sha256)&&Number.isSafeInteger(row.bytesLength)&&row.bytesLength>=0&&row.bytesLength<=67108864&&(row.type==='file'?[0o444,0o555].includes(row.mode):row.mode===0o777),'CarrierContextMember');
  if(row.type==='symlink')need(row.path.startsWith(operatorPrefix)&&typeof row.target==='string'&&!row.target.includes('\\')&&!/[\x00-\x1f\x7f]/.test(row.target)&&!posix.isAbsolute(row.target)&&sha(row.target)===row.sha256&&Buffer.byteLength(row.target)===row.bytesLength,'CarrierContextLink');
  else if(fixedPaths.has(row.path))need(row.mode===0o444,'CarrierContextRecipeMode');
  total+=row.bytesLength;need(Number.isSafeInteger(total)&&total<=t.bounds.contextBytes,'CarrierContextSize');byPath.set(row.path,row);
 }
 same(m.files.map(r=>r.path),[...byPath.keys()].sort((a,b)=>a.localeCompare(b)),'CarrierContextOrder');
 for(const row of m.files){
  let parent=dirname(row.path);while(parent!=='.'){need(!byPath.has(parent),'CarrierContextParent');parent=dirname(parent);}
  if(row.type==='symlink'){
   let path=row.path;const seen=new Set();
   for(let i=0;i<32;i++){
    need(!seen.has(path),'CarrierContextLinkCycle');seen.add(path);const current=byPath.get(path);need(current,'CarrierContextLinkTarget');if(current.type==='file')break;
    path=posix.normalize(posix.join(posix.dirname(path),current.target));need(path.startsWith(operatorPrefix)&&i<31,'CarrierContextLinkEscape');
   }
  }
 }
 for(const path of [...recipePaths,'rootfs/carrier/legacy-audit.mjs',...(!sourceOnly?['rootfs/carrier/manifest.json']:[]),...CARRIER_OPERATOR_FILES.map(p=>operatorPrefix+p)])need(byPath.get(path)?.type==='file','CarrierContextMissingClosure');
 if(baseEvidence!==undefined)need(byPath.has('rootfs/bootstrap/global-bundle.pem')===baseEvidence.ca.present,'CarrierContextCa');
 const recipe=recipePaths.map(path=>{const r=byPath.get(path);return {path,sha256:r.sha256,bytesLength:r.bytesLength};}).sort((a,b)=>a.path.localeCompare(b.path));
 need(hash(recipe)===t.recipe.sourceClosureHash&&byPath.get('Dockerfile').sha256===t.recipe.dockerfileHash&&byPath.get('rootfs/carrier/guard-first.mjs').sha256===t.recipe.guardHash&&byPath.get('rootfs/carrier/legacy-audit.mjs').sha256===t.anchors.hostCodeHash,'CarrierContextCodePin');
 return {byPath,total};
}
function inspectRuntime(runtime,m,plan,baseEvidence){
 exact(runtime,['version','legacyCodeHash','expandedSourceHash','minifiedSourceHash','dependencyHash','operatorInventoryHash','runtime','files','caPath']);
 need(runtime.version===1&&runtime.legacyCodeHash===plan.template.anchors.hostCodeHash&&runtime.expandedSourceHash===plan.template.anchors.hostSourceHash&&['minifiedSourceHash','dependencyHash','operatorInventoryHash'].every(k=>hex(runtime[k])),'CarrierRuntimeManifest');
 exact(runtime.runtime,['nodeSha256','setprivSha256']);need(Object.values(runtime.runtime).every(hex),'CarrierRuntimeNative');
 if(baseEvidence!==undefined)same(runtime.runtime,baseEvidence.native,'CarrierRuntimeNative');
 need(runtime.caPath===(m.files.some(r=>r.path==='rootfs/bootstrap/global-bundle.pem')?'/bootstrap/global-bundle.pem':null),'CarrierRuntimeCa');
 const expected=m.files.filter(r=>r.path!=='Dockerfile'&&r.path!=='rootfs/carrier/manifest.json').map(({path,bytesLength,...r})=>({...r,path:path.slice(6),bytes:bytesLength})).sort((a,b)=>a.path.localeCompare(b.path));
 need(Array.isArray(runtime.files),'CarrierRuntimeFiles');same([...runtime.files].sort((a,b)=>a.path.localeCompare(b.path)),expected,'CarrierRuntimeFiles');
}

class Cursor{
 constructor(stream,cap,charge,check){this.iterator=stream[Symbol.asyncIterator]();this.cap=cap;this.charge=charge;this.check=check;this.buffer=Buffer.alloc(0);this.position=0;this.count=0;this.digest=createHash('sha256');}
 async available(){while(this.position===this.buffer.length){this.check();const next=await this.iterator.next();if(next.done)return false;need(next.value instanceof Uint8Array&&next.value.length<=8388608,'CarrierContextChunk');this.buffer=Buffer.from(next.value);this.position=0;this.count+=this.buffer.length;need(this.count<=this.cap,'CarrierContextSize');this.charge(this.buffer.length);this.digest.update(this.buffer);if(this.buffer.length)return true;}return true;}
 async *chunks(n){while(n){need(await this.available(),'CarrierContextTruncated');const size=Math.min(n,this.buffer.length-this.position);yield this.buffer.subarray(this.position,this.position+size);this.position+=size;n-=size;}}
 async read(n){need(n<=33554432,'CarrierContextBuffer');const chunks=[];for await(const chunk of this.chunks(n))chunks.push(Buffer.from(chunk));return Buffer.concat(chunks,n);}
 async close(){await this.iterator.return?.();}
}

export async function materializeCarrierBuildContext({stream,plan:input,baseEvidence:base,tempRoot,metadataReads,signal}){
 const plan=inspectCarrierFundingPlan(input),baseEvidence=base===undefined?undefined:copyNonrootJson(base);
 need(typeof metadataReads?.reserveLocal==='function'&&typeof stream?.[Symbol.asyncIterator]==='function','CarrierContextBudget');
 need(resolve(tempRoot)===tempRoot&&await realpath(tempRoot)===tempRoot&&(await lstat(tempRoot)).isDirectory(),'CarrierContextTemporaryRoot');
 const check=()=>{signal?.throwIfAborted();need(Date.now()<plan.deadlineMs,'CarrierContextExpired');metadataReads.reserveLocal(zero());};
 const charge=n=>{check();metadataReads.reserveLocal({...zero(),logicalBytes:n});};check();
 const directory=join(tempRoot,'mem9-carrier-context-'+randomBytes(16).toString('hex'));await mkdir(directory,{mode:0o700});
 const identities=new Map(),directories=new Map(),small=new Map(),cursor=new Cursor(stream,plan.context.bytesLength,charge,check);let complete=false;
 directories.set(directory,await lstat(directory));
 const parents=async path=>{const parts=dirname(path).split('/');let at=directory;for(const part of parts){if(part==='.')continue;at=join(at,part);if(!directories.has(at)){await mkdir(at,{mode:0o700});directories.set(at,await lstat(at));}}};
 try{
  need((await cursor.read(CARRIER_CONTEXT_MAGIC.length)).equals(CARRIER_CONTEXT_MAGIC),'CarrierContextMagic');const headerSize=(await cursor.read(4)).readUInt32BE();
  need(headerSize>0&&headerSize<=33554432&&headerSize+4+CARRIER_CONTEXT_MAGIC.length<=plan.context.bytesLength,'CarrierContextHeader');
  const manifest=parse(await cursor.read(headerSize)),{total}=inspectManifest(manifest,plan,baseEvidence);
  need(total+headerSize+4+CARRIER_CONTEXT_MAGIC.length===plan.context.bytesLength,'CarrierContextSize');
  for(const row of manifest.files){
   check();await parents(row.path);const path=join(directory,row.path);metadataReads.reserveLocal({...zero(),processedEntries:1});
   if(row.type==='symlink'){
    const bytes=await cursor.read(row.bytesLength);need(decode(bytes)===row.target,'CarrierContextLinkBytes');charge(bytes.length);await symlink(row.target,path);
   }else{
    charge(row.bytesLength);const fd=await open(path,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600),digest=createHash('sha256'),pieces=[];
    try{for await(const bytes of cursor.chunks(row.bytesLength)){check();digest.update(bytes);let at=0;while(at<bytes.length){const r=await fd.write(bytes,at,bytes.length-at);need(r.bytesWritten>0,'CarrierContextWrite');at+=r.bytesWritten;}if(fixedPaths.has(row.path))pieces.push(Buffer.from(bytes));}
     need(digest.digest('hex')===row.sha256,'CarrierContextFileHash');await fd.sync();await fd.chmod(row.mode);
    }finally{await fd.close();}
    if(fixedPaths.has(row.path))small.set(row.path,Buffer.concat(pieces,row.bytesLength));
   }
   identities.set(path,await lstat(path));
  }
  need(!await cursor.available()&&cursor.count===plan.context.bytesLength&&cursor.digest.digest('hex')===plan.context.sha256,'CarrierContextWireHash');
  const sourceOnly=manifest.version===2;
  need(small.get('Dockerfile').equals(Buffer.from(carrierDockerfile(plan.template.base,{caPresent:sourceOnly||manifest.files.some(r=>r.path==='rootfs/bootstrap/global-bundle.pem'),derived:sourceOnly}))),'CarrierCleanRecipeRequired');
  const runtimeManifest=sourceOnly?null:parse(small.get('rootfs/carrier/manifest.json'));if(runtimeManifest)inspectRuntime(runtimeManifest,manifest,plan,baseEvidence);
  // Store no caller-supplied cleanup path. All members are fixed below this
  // fresh directory; all symlink targets were resolved against the inventory.
  const state={plan,baseEvidence,manifest,runtimeManifest,directory,identities,directories,metadataReads,check,charge,closed:false,consumed:false};
  const handle=Object.freeze({kind:'carrier-materialized-context'});contexts.set(handle,state);complete=true;return handle;
 }finally{await cursor.close();if(!complete)await rm(directory,{recursive:true,force:true});}
}

function context(handle){const s=contexts.get(handle);need(s&&!s.closed,'CarrierContextHandle');s.check();return s;}
export function inspectMaterializedCarrierContext(handle){const s=context(handle);return Object.freeze({directory:s.directory,plan:copyNonrootJson(s.plan),manifest:s.manifest,runtimeManifest:s.runtimeManifest,...(s.runtimeManifest?{nativePins:s.runtimeManifest.runtime}:{runtimeSource:s.manifest.runtimeSource})});}
export async function verifyMaterializedCarrierContext(handle){
 const s=context(handle),expected=new Set([...s.identities.keys(),...s.directories.keys()]);
 for(const [path,before]of s.directories){const now=await lstat(path);need(now.isDirectory()&&now.uid===process.getuid()&&(now.mode&511)===0o700&&before.dev===now.dev&&before.ino===now.ino&&await realpath(path)===path,'CarrierContextDirectoryChanged');for(const name of await readdir(path))need(expected.has(join(path,name)),'CarrierContextUnknownFile');}
 for(const row of s.manifest.files){const path=join(s.directory,row.path),before=s.identities.get(path);need(unchanged(before,await lstat(path)),'CarrierContextChanged');
  if(row.type==='symlink'){need(await readlink(path)===row.target,'CarrierContextChanged');continue;}
  s.charge(row.bytesLength);const fd=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK),digest=createHash('sha256');let bytes=0;
  try{need(unchanged(before,await fd.stat())&&before.nlink===1&&before.uid===process.getuid(),'CarrierContextChanged');const buffer=Buffer.alloc(65536);while(true){s.check();const r=await fd.read(buffer,0,buffer.length,null);if(!r.bytesRead)break;bytes+=r.bytesRead;need(bytes<=row.bytesLength,'CarrierContextChanged');digest.update(buffer.subarray(0,r.bytesRead));}need(bytes===row.bytesLength&&digest.digest('hex')===row.sha256&&unchanged(before,await fd.stat())&&unchanged(before,await lstat(path)),'CarrierContextChanged');}finally{await fd.close();}
 }return inspectMaterializedCarrierContext(handle);
}
export async function consumeCarrierBuildContext(handle){const s=context(handle);need(!s.consumed,'CarrierContextAlreadyConsumed');s.consumed=true;return verifyMaterializedCarrierContext(handle);}
export async function closeCarrierBuildContext(handle){const s=context(handle);await verifyMaterializedCarrierContext(handle);await rm(s.directory,{recursive:true});s.closed=true;}
