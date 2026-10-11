/** R13: generate only the runtime manifest and required public CA after the
 * prepaid base has been read and probed. Supplied bytes remain untouched. */
import {mkdir,open,lstat,realpath,readdir,rm} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,resolve} from 'node:path';
import {randomBytes,createHash,X509Certificate} from 'node:crypto';
import {inspectMaterializedCarrierContext,verifyMaterializedCarrierContext} from './ci-carrier-context.mjs';
import {controlImageGraphBinding,imageGraphState} from './production-image-graph.mjs';
import {inspectImageFilesystemEvidence,imageFilesystemVerificationKind,assertImageFilesystemUncompressedLimit,assertImageFilesystemEntryLimit} from './production-image-filesystem.mjs';
import {readControlSourceFile} from './production-control-source.mjs';
import {collectCarrierBasePrerequisites,inspectNonrootControlPrerequisites} from './production-nonroot-control-prerequisites.mjs';
import {formatCarrierDerivedMaterial,CARRIER_RUNTIME_MANIFEST_PATH} from './ci-carrier-derived-format.mjs';
import {hash,sha,zero,need,freeze} from './ci-smoke-acquisition-format.mjs';

const states=new WeakMap(),attempted=new WeakSet(),fileKeys=['dev','ino','uid','mode','nlink','size','mtimeMs','ctimeMs'];
const sameFile=(a,b)=>fileKeys.every(k=>a[k]===b[k]);
const same=(a,b,code)=>need(hash(a)===hash(b),code);
export const CARRIER_DERIVED_PATHS=Object.freeze(['rootfs/carrier/manifest.json','rootfs/bootstrap/global-bundle.pem']);

export async function deriveCarrierRuntimeMaterial({context,baseGraph,baseFilesystem,baseCacheDirectory,sourceContext,metadataReads,tempRoot,signal}){
 const supplied=inspectMaterializedCarrierContext(context),p=supplied.plan,t=p.template;
 need(supplied.manifest.version===2&&supplied.manifest.kind==='carrier-build-source-context'&&supplied.runtimeManifest===null&&!attempted.has(context),'CarrierDerivationContext');
 need(metadataReads?.admission?.config?.grantHash&&typeof metadataReads.reserveLocal==='function','CarrierDerivationGrant');
 same(metadataReads.admission.config.plan,p,'CarrierDerivationGrant');
 need(sourceContext?.tree===t.source.candidateTree&&resolve(tempRoot)===tempRoot&&await realpath(tempRoot)===tempRoot,'CarrierDerivationSource');
 const bound=controlImageGraphBinding(baseGraph),{graphHash,...base}=bound,filesystem=inspectImageFilesystemEvidence(baseFilesystem);
 same(base,t.base,'CarrierDerivationBase');need(filesystem.graphHash===graphHash&&imageFilesystemVerificationKind(baseFilesystem)==='live-filesystem-evidence','CarrierDerivationFilesystem');
 assertImageFilesystemUncompressedLimit(baseFilesystem,t.bounds.uncompressedBytes);assertImageFilesystemEntryLimit(baseFilesystem,t.bounds.processedEntries);
 attempted.add(context);await verifyMaterializedCarrierContext(context);
 const check=()=>{signal?.throwIfAborted();need(Date.now()<p.deadlineMs,'CarrierDerivationExpired');metadataReads.reserveLocal(zero());};
 const charge=bytes=>{check();metadataReads.reserveLocal({...zero(),logicalBytes:bytes});};
 const directory=join(tempRoot,'mem9-carrier-derived-'+randomBytes(16).toString('hex')),materialDirectory=join(directory,'material');
 await mkdir(directory,{mode:0o700});for(const path of ['material','material/rootfs','material/rootfs/carrier','material/rootfs/bootstrap'])await mkdir(join(directory,path),{mode:0o700});
 let complete=false,unknown=false;
 try{
  const state=imageGraphState(baseGraph),usage=state.budget.usage();
  need(Number.isSafeInteger(usage.uncompressedBytes)&&usage.uncompressedBytes>0&&usage.uncompressedBytes<=t.bounds.uncompressedBytes&&Number.isSafeInteger(usage.fsEntries)&&usage.fsEntries<=t.bounds.processedEntries,'CarrierDerivationBaseBounds');
  // The Docker base import may materialize every already-verified layer. Its
  // entire read/write/entry bound is reserved before the native operation.
  metadataReads.reserveLocal({...zero(),logicalBytes:2*usage.uncompressedBytes,uncompressedBytes:usage.uncompressedBytes,processedEntries:usage.fsEntries});
  const collector=await readControlSourceFile(sourceContext,'scripts/lib/production-nonroot-control-prerequisites.mjs');charge(collector.bytes.length);
  const closure={version:1,kind:'git-file-closure',tree:sourceContext.tree,files:[collector.file],closureHash:hash([collector.file])};
  const options={controlVerification:{graph:baseGraph,filesystem:baseFilesystem},sourceContext,expected:{candidateTree:sourceContext.tree},deadlineMs:p.deadlineMs,metadataReads,tempRoot:directory,baseCacheDirectory,...(signal?{signal}:{})};
  const handle=await collectCarrierBasePrerequisites({image:base,sourceClosure:closure},options),native=inspectNonrootControlPrerequisites(handle,options);
  need(native.record.cleanupConfirmed===true&&native.record.container.exitCode===0&&native.environment.caBindings.length===1,'CarrierDerivationNative');
  const ca=native.environment.caBindings[0];need(ca.value==='/bootstrap/global-bundle.pem'&&ca.resolvedPath===ca.value,'CarrierDerivationCaPath');
  const object=native.objects.find(row=>row.ref.sha256===ca.file.sha256&&row.ref.bytesLength===ca.file.bytesLength),caBytes=object?.bytes;
  need(caBytes instanceof Uint8Array&&caBytes.length>0&&caBytes.length<=1048576&&sha(caBytes)===ca.file.sha256,'CarrierDerivationCaBytes');
  const caText=new TextDecoder('utf-8',{fatal:true}).decode(caBytes),certificates=caText.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  need(certificates?.length>0&&caText.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,'').trim()==='','CarrierDerivationPublicCa');for(const cert of certificates)new X509Certificate(cert);
  // Serialize this exact successful probe and the complete authenticated base
  // metadata through the owner-shared format. No new probe or AWS read occurs.
  const record=freeze(await formatCarrierDerivedMaterial({context,grantHash:metadataReads.admission.config.grantHash,baseGraph,baseFilesystem,prerequisites:handle,sourceContext,metadataReads}));
  const manifestBytes=Buffer.from(record.files.find(f=>f.path===CARRIER_RUNTIME_MANIFEST_PATH).bytesBase64,'base64'),runtimeManifest=JSON.parse(manifestBytes);
  need(manifestBytes.length<=1048576&&manifestBytes.length+caBytes.length<=t.bounds.contextBytes&&runtimeManifest.files.length+2<=t.bounds.contextFiles,'CarrierDerivedSize');
  const identities=new Map();
  for(const {path,bytesBase64}of record.files){
   const bytes=Buffer.from(bytesBase64,'base64');
   need(!supplied.manifest.files.some(row=>row.path===path),'CarrierSuppliedDerivedCollision');charge(bytes.length);metadataReads.reserveLocal({...zero(),processedEntries:1});
   const full=join(materialDirectory,path),fd=await open(full,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
   try{await fd.writeFile(bytes);await fd.sync();await fd.chmod(0o444);}finally{await fd.close();}
   identities.set(full,await lstat(full));
  }
  const recordBytes=Buffer.from(JSON.stringify(record));need(recordBytes.length<=t.bounds.resultBytes,'CarrierDerivedRecordSize');charge(recordBytes.length);const fd=await open(join(directory,'derivation.json'),'wx',0o600);try{await fd.writeFile(recordBytes);await fd.sync();}finally{await fd.close();}
  await verifyMaterializedCarrierContext(context);check();
  const token=Object.freeze({kind:'carrier-derived-runtime-context'});states.set(token,{context,baseGraph,baseFilesystem,metadataReads,directory,materialDirectory,record,recordStat:await lstat(join(directory,'derivation.json')),directoryStat:await lstat(directory),runtimeManifest:freeze(runtimeManifest),identities,check,charge,consumed:false,closed:false});complete=true;return token;
 }catch(e){unknown=e.code==='ECLEANUP';throw e;}finally{if(!complete&&!unknown)await rm(directory,{recursive:true,force:true});}
}
export async function inspectCarrierRuntimeMaterial(handle,{context,baseGraph,baseFilesystem,metadataReads}={}){
 const s=states.get(handle);need(s&&!s.closed&&s.context===context&&s.baseGraph===baseGraph&&s.baseFilesystem===baseFilesystem&&s.metadataReads===metadataReads,'CarrierDerivedHandle');s.check();
 const root=await lstat(s.directory);need(root.isDirectory()&&root.dev===s.directoryStat.dev&&root.ino===s.directoryStat.ino&&root.uid===process.getuid()&&(root.mode&511)===0o700&&await realpath(s.directory)===s.directory,'CarrierDerivedDirectory');
 same((await readdir(s.directory)).sort(),['derivation.json','material'],'CarrierDerivedUnknownFile');need(sameFile(s.recordStat,await lstat(join(s.directory,'derivation.json'))),'CarrierDerivedChanged');
 const expected=new Set(['rootfs','rootfs/carrier','rootfs/bootstrap',...s.record.files.map(f=>f.path)]);
 const walk=async(relative='')=>{const directory=join(s.materialDirectory,relative),d=await lstat(directory);need(d.isDirectory()&&d.uid===process.getuid()&&(d.mode&511)===0o700&&await realpath(directory)===directory,'CarrierDerivedDirectory');for(const name of await readdir(directory)){const p=relative?relative+'/'+name:name;need(expected.has(p),'CarrierDerivedUnknownFile');const item=await lstat(join(s.materialDirectory,p));if(item.isDirectory())await walk(p);}};await walk();
 for(const row of s.record.files){const full=join(s.materialDirectory,row.path),before=s.identities.get(full),fd=await open(full,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);s.charge(row.bytesLength);
  try{need(sameFile(before,await fd.stat())&&sameFile(before,await lstat(full))&&before.nlink===1,'CarrierDerivedChanged');const digest=createHash('sha256'),bytes=await fd.readFile();digest.update(bytes);need(bytes.length===row.bytesLength&&digest.digest('hex')===row.sha256&&sameFile(before,await fd.stat()),'CarrierDerivedChanged');}finally{await fd.close();}
 }
 return Object.freeze({directory:s.directory,materialDirectory:s.materialDirectory,record:s.record,recordHash:hash(s.record),runtimeManifest:s.runtimeManifest,nativePins:s.runtimeManifest.runtime});
}
export async function consumeCarrierRuntimeMaterial(handle,bindings){const s=states.get(handle);need(s&&!s.consumed,'CarrierDerivedConsumed');s.consumed=true;return inspectCarrierRuntimeMaterial(handle,bindings);}
export async function closeCarrierRuntimeMaterial(handle,bindings){const s=states.get(handle);await inspectCarrierRuntimeMaterial(handle,bindings);await rm(s.directory,{recursive:true});s.closed=true;}
