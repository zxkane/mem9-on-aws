/** Host/isolated-verifier code only. Do not import through the regular
 * bootstrap compatibility/runtime path: graph and filesystem verification
 * intentionally have a different dependency and credential boundary. */
import {inspectNonrootRecord,copyNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {readNonrootEvidence} from './production-nonroot-runtime.mjs';
import {controlImageGraphBinding} from './production-image-graph.mjs';
import {inspectImageFilesystemEvidence,inspectImageFilesystemFile,imageFilesystemVerificationKind} from './production-image-filesystem.mjs';

const need=(ok,code)=>{if(!ok)throw Error(code);};
const same=(a,b)=>need(hash(a)===hash(b),'NonrootControlArtifactBinding');
const imageOnly=v=>({rootDigest:v.rootDigest,arm64Digest:v.arm64Digest,configDigest:v.configDigest});
const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join(),'NonrootControlArtifactFields');

function controlArtifact(value,options){
 const c=options?.controlVerification;need(c,'NonrootControlVerificationRequired');exact(c,['graph','filesystem']);
 const binding=controlImageGraphBinding(c.graph),fs=inspectImageFilesystemEvidence(c.filesystem);
 need(imageFilesystemVerificationKind(c.filesystem)==='live-filesystem-evidence'&&fs.component==='bootstrap'&&fs.graphHash===binding.graphHash&&fs.rootDigest===binding.rootDigest&&fs.arm64Digest===binding.arm64Digest,'NonrootControlFilesystemBinding');
 const {graphHash,...image}=binding;same(image,value.image);
 return {binding,graph:c.graph,filesystem:c.filesystem,filesystemHash:hash(fs)};
}
export function inspectNonrootControlArtifactBinding(value,options){
 const {binding,filesystemHash}=controlArtifact(value,options);return copyNonrootJson({...binding,filesystemHash});
}

/** Actual file facts only. Missing root/implicit-parent metadata is reported,
 * never replaced by a JSON permission claim. The full provenance gate must
 * resolve those observations through a separately authenticated runtime check. */
export async function verifyNonrootControlArtifactFiles(value,options){
 const b=inspectNonrootRecord('DeployedControlBuildV1',value),actual=controlArtifact(b,options),unknown=new Set(),checked=new Map();
 const checkMetadata=row=>{
  if(row.implicit||!Number.isSafeInteger(row.mode)||!Number.isSafeInteger(row.uid)||!Number.isSafeInteger(row.gid)){unknown.add(row.path);return;}
  need(row.uid===0&&row.gid===0&&(row.mode&0o6000)===0&&!row.privilegeAttributes.length,'NonrootControlPathPrivilege');
  if(row.type!=='symlink')need((row.mode&0o022)===0,'NonrootControlPathWritable');
  if(row.type==='directory')need((row.mode&0o001)!==0,'NonrootControlPathUnsearchable');
 };
 const file=(path,expectedHash,executable=false)=>{
  const fact=inspectImageFilesystemFile(actual.filesystem,path);
  need(fact.sha256===expectedHash,'NonrootControlFileHash');checkMetadata(fact);
  need(executable?fact.mode===0o755:(fact.mode&0o004)!==0,'NonrootControlFileMode');
  for(const row of [...fact.parents,...fact.symlinkChain])checkMetadata(row);
  if(fact.rootMetadata==='not-recorded')unknown.add('/');
  checked.set(path,fact);return fact;
 };
 const dependencies=async ref=>{
  const d=await readNonrootEvidence(ref,options);need(d&&Array.isArray(d.files)&&d.files.length<=512&&new Set(d.files.map(f=>f.path)).size===d.files.length,'NonrootControlNativeLibraries');
  for(const row of d.files){exact(row,['path','sha256']);file(row.path,row.sha256);}
 };
 const node=b.guardImports.nodeRuntime;file(node.executablePath,node.executableSha256,true);await dependencies(node.loaderAndNativeLibraries);
 for(const source of b.guardSource.files){
  need(source.path.startsWith('docker/bootstrap/'),'NonrootControlGuardPath');file('/bootstrap/'+source.path.slice('docker/bootstrap/'.length),source.sha256);
 }
 for(const launch of b.resolvedLaunches){
  const primitive=inspectNonrootRecord('PrimitiveEvidenceV1',await readNonrootEvidence(launch.primitiveEvidence,options));same(primitive.image,imageOnly(b.image));
  const fact=file(primitive.invokedPath,primitive.fileSha256,true);need(fact.resolvedPath===primitive.resolvedPath&&fact.uid===primitive.uid&&fact.gid===primitive.gid&&fact.mode===primitive.mode,'NonrootControlPrimitiveBinding');
  same(await readNonrootEvidence(primitive.symlinkChain,options),fact.symlinkChain);await dependencies(primitive.loaderAndLibraries);
  if(launch.originalModule.present){need(launch.originalModuleSha256.present,'NonrootControlApplicationHash');file(launch.originalModule.value,launch.originalModuleSha256.value);}
  for(const ca of launch.environment.caBindings){const observed=file(ca.value,ca.file.sha256);need(observed.resolvedPath===ca.resolvedPath&&observed.size===ca.file.bytesLength&&observed.mode===ca.mode&&observed.uid===ca.uid&&observed.gid===ca.gid,'NonrootControlCaBinding');}
 }
 controlImageGraphBinding(actual.graph);
 return copyNonrootJson({image:b.image,graphHash:actual.binding.graphHash,filesystemHash:actual.filesystemHash,files:[...checked.values()],unknownRuntimePaths:[...unknown].sort()});
}
