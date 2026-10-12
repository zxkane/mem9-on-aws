import {createHash} from 'node:crypto';
import {open,lstat,realpath,mkdtemp,chmod,appendFile,unlink,rmdir} from 'node:fs/promises';
import {constants} from 'node:fs';
import {GetParametersCommand} from '@aws-sdk/client-ssm';
import {resolve,join,dirname,basename} from 'node:path';
import {tmpdir} from 'node:os';
import {requireActiveDataRelease} from './production-data-release.mjs';
import {restoreImageVerificationEvidence} from './production-image-restoration.mjs';
import {parseImageTransitionJson,imageTransitionProofExpected,verifyImageTransitionProof,bindImageTransitionAuthorization} from './production-image-transition-proof.mjs';
import {verifyImageDeploymentSource,imageDeploymentParameterBinding as parameterBinding} from './production-image-deployment.mjs';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {installImageAuthorization} from './production-image-admission.mjs';
import {parseNonrootJson,copyNonrootJson} from './production-nonroot-contracts.mjs';
import {importNonrootArchive,exportNonrootArchive,authenticateNonrootArchive,nonrootArchiveBindings} from './production-nonroot-archive.mjs';
import {nonrootProofExpected,verifyNonrootImageTransitionProof,bindNonrootTransitionAuthorization,assertNonrootDataRelease,nonrootAuthorizationBindings,bindNonrootDeploymentContext,nonrootDeploymentPhaseEvidence} from './production-nonroot-proof.mjs';
import {verifyNonrootActualMain} from './production-nonroot-provenance.mjs';
import {createNonrootActualMainRecord} from './production-nonroot-source-reader.mjs';
const fail=()=>{throw Error('ImageDeploymentBundleInvalid');};
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join();
const nonrootKind='image-security-nonroot-deployment-bundle';
const nonrootBase=['version','kind','phase','parameter','proof','operation','proofArchive','source','sourceReceiptHash'];
const nonrootDeployment=['deploymentArchive','deploymentSource','phaseEvidence','targetObservation','phaseReceipt'];
const cacheKeys=value=>Object.hasOwn(value,'controlCache')?['controlCache']:[];
function controlCache(value){
 const c=copyNonrootJson(value);
 if(!exact(c,['directory','inventory'])||typeof c.directory!=='string'||resolve(c.directory)!==c.directory||c.inventory?.kind!=='readonly-control-image-graph')fail();
 return c;
}
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const sourceExpected=control=>({repository:control.repository,prNumber:control.prNumber,candidateRevision:control.revision,candidateTree:control.sourceTree,baseRevision:control.baseRevision});
function assertDeploymentSource(source,record,control){
 if(record.actualMain.authenticatedSource.canonicalHash!==hash(source)||record.deployedControlBuild.source.sourceEvidence.canonicalHash!==hash(source))throw Error('NonrootDeploymentSourceChanged');
 const main=createNonrootActualMainRecord(source,record.actualMain.authenticatedSource,sourceExpected(control));
 if(hash(main)!==hash(record.actualMain))throw Error('NonrootDeploymentSourceChanged');
}

export function createImageDeploymentPhaseReceipt(context,{sourceReceiptHash,phase,now=Date.now()}){
 if(!hex(sourceReceiptHash))throw Error('NonrootSourceReceiptRequired');
 const b=nonrootDeploymentPhaseEvidence(context,{phase,now});
 return copyNonrootJson({version:1,kind:'image-deployment-phase-receipt',phase,sourceReceiptHash,
  descriptorHash:b.descriptorHash,parameterVersion:b.parameterVersion,proofHash:b.proofHash,reviewHash:b.reviewHash,
  deploymentSourceHash:b.deploymentSourceHash,phaseEvidenceHash:hash(b.phaseEvidence),observedMs:b.phaseEvidence.observedMs,expiresMs:b.expiresMs});
}

/** Only evidence bytes cross the file boundary. Callers retain genuine CONTROL
 * graph/FS/source/runtime handles separately; no JSON flag reconstructs them. */
export async function createNonrootDeploymentBundle(loaded,source,parameter,{phase,sourceReceiptHash,now=Date.now()}){
 if(!['source','deployment'].includes(phase)||!hex(sourceReceiptHash))fail();
 const b=nonrootAuthorizationBindings(loaded.context),data=parseNonrootJson(parameter.Value);
 assertNonrootDataRelease(loaded.context,{current:data,controlSourceTree:data.controlSourceTree,now});
 if(data.version!==3||parameter.Version!==b.parameterVersion||hash(loaded.proof)!==data.transition.proofHash)fail();
 if(phase==='deployment'){
  const checked=nonrootDeploymentPhaseEvidence(loaded.context,{phase:loaded.phaseEvidence?.phase,now});
  if(hash(loaded.deploymentSource)!==checked.deploymentSourceHash||hash(loaded.phaseEvidence)!==hash(checked.phaseEvidence)||hash(loaded.targetObservation)!==checked.targetObservationHash)throw Error('NonrootDeploymentMaterialChanged');
  assertDeploymentSource(source,loaded.deploymentSource,b.control);
 }
 const value={version:2,kind:nonrootKind,phase,parameter:parameterBinding(parameter),proof:copyNonrootJson(loaded.proof),operation:copyNonrootJson(loaded.operation),
  proofArchive:await exportNonrootArchive(loaded.proofArchive),source:copyNonrootJson(source),sourceReceiptHash};
 if(phase==='deployment')Object.assign(value,{deploymentArchive:await exportNonrootArchive(loaded.evidence.archive),deploymentSource:copyNonrootJson(loaded.deploymentSource),
  phaseEvidence:copyNonrootJson(loaded.phaseEvidence),targetObservation:copyNonrootJson(loaded.targetObservation),
   phaseReceipt:createImageDeploymentPhaseReceipt(loaded.context,{sourceReceiptHash,phase:loaded.phaseEvidence.phase,now})});
 if(phase==='deployment'&&loaded.evidence.controlCache)value.controlCache=controlCache(loaded.evidence.controlCache);
 return value;
}

export async function restoreNonrootBundleAuthorization(bundle,{parameter,expected,controlRevision,now=Date.now()}){
 if(!exact(bundle,[...nonrootBase,...(bundle?.phase==='deployment'?[...nonrootDeployment,...cacheKeys(bundle)]:[])])||bundle.version!==2||bundle.kind!==nonrootKind||!['source','deployment'].includes(bundle.phase)||!hex(bundle.sourceReceiptHash)||hash(bundle.parameter)!==hash(parameterBinding(parameter)))fail();
 if(Object.hasOwn(bundle,'controlCache'))controlCache(bundle.controlCache);
 const selected=requireActiveDataRelease(parameter.Value,expected,{now}),data=selected.data;
 if(data.version!==3||hash(bundle.proof)!==data.transition.proofHash||bundle.source?.checkout?.sha!==controlRevision)fail();
 const proofArchive=importNonrootArchive(bundle.proofArchive,{expectedManifestHash:bundle.operation?.evidenceManifest?.canonicalHash});
 const archive=await authenticateNonrootArchive(proofArchive,{parameter,operation:bundle.operation},{expectedProofHash:data.transition.proofHash,expectedDataHash:selected.hash,expectedReviewHash:data.policyHash,expectedParameterVersion:parameter.Version,
  expectedScope:{account:data.account,region:data.region,runtimeNonce:data.runtimeNonce,authorizationId:data.authorizationId}});
 const proof=await verifyNonrootImageTransitionProof(bundle.proof,{proofHash:data.transition.proofHash,expected:nonrootProofExpected(bundle.proof,{proofHash:data.transition.proofHash}),evidence:{archive},now,mode:'admission'});
 const context=bindNonrootTransitionAuthorization(proof,{review:bundle.operation.authorization.review,now}),b=nonrootAuthorizationBindings(context);
 assertNonrootDataRelease(context,{current:data,controlSourceTree:expected.controlSourceTree,now});
 const raw=Buffer.from(JSON.stringify(bundle.source)),ref={bytesHash:createHash('sha256').update(raw).digest('hex'),canonicalHash:hash(bundle.source),bytesLength:raw.length};
 const main=createNonrootActualMainRecord(bundle.source,ref,sourceExpected(b.control));
 await verifyNonrootActualMain(main,{expected:sourceExpected(b.control),resolveJson:async requested=>{if(hash(requested)!==hash(ref))fail();return raw;}});
 if(bundle.phase==='deployment')assertDeploymentSource(bundle.source,bundle.deploymentSource,b.control);
 return {context,archive,selected};
}
export function createImageDeploymentBundle({records,targetObservation},source,parameter){
 return {version:1,kind:'image-security-deployment-bundle',parameter:parameterBinding(parameter),proof:structuredClone(records.proof),operation:structuredClone(records.operation),graphEvidence:structuredClone(records.graphEvidence),filesystemEvidence:structuredClone(records.filesystemEvidence),targetObservation:structuredClone(targetObservation),source:structuredClone(source)};
}
/** A private file carries evidence, never authority. The current protected
 * parameter and current checked-out source are independently supplied again. */
export async function restoreImageDeploymentBundle(bundle,{parameter,expected,controlRevision,nonrootEvidence,env,now=Date.now()}){
 if(bundle?.version===2&&bundle.kind===nonrootKind){
  if(bundle.phase!=='deployment')throw Error('NonrootDeploymentPhaseRequired');
  if(!nonrootEvidence&&(!env||!bundle.controlCache))throw Error('NonrootDeploymentEvidenceRequired');
  const restored=await restoreNonrootBundleAuthorization(bundle,{parameter,expected,controlRevision,now});
  const manifest=parseNonrootJson(bundle.deploymentArchive.manifest),archive=importNonrootArchive(bundle.deploymentArchive,{expectedManifestHash:hash(manifest)});
  if(nonrootArchiveBindings(archive).owner!==restored.selected.data.authorizationId||nonrootEvidence?.archive&&nonrootArchiveBindings(nonrootEvidence.archive).manifestHash!==hash(manifest))fail();
  let local,owned;
  try{
   if(!nonrootEvidence){
    const {openCiSmokeDeploymentLocalReplay}=await import('./ci-smoke-acquisition.mjs');
    local=await openCiSmokeDeploymentLocalReplay({env:{...env,STAGE:expected.stage},
     completionRef:{path:env.MEM9_CI_ACQUISITION_COMPLETION_FILE,sha256:env.MEM9_CI_ACQUISITION_COMPLETION_HASH},
     bundleRef:{path:env.MEM9_IMAGE_TRANSITION_BUNDLE_FILE,sha256:env.MEM9_IMAGE_TRANSITION_BUNDLE_HASH},knownParameter:parameter});
    const {collectOwnedNonrootControlEvidence}=await import('./production-nonroot-deployment-provider.mjs');
    const cache=controlCache(bundle.controlCache);
    owned=await collectOwnedNonrootControlEvidence({cacheDirectory:cache.directory,inventory:cache.inventory,metadataReads:local,
     deadlineMs:Math.min(local.expiresMs,Date.now()+120000),archive,build:bundle.deploymentSource.deployedControlBuild,
     contract:bundle.proof.taskPlan.deployedControlBuildContract,repositoryDirectory:env.GITHUB_WORKSPACE??process.cwd()});
    nonrootEvidence=owned;now=Date.now();
   }
   const context=await bindNonrootDeploymentContext(restored.context,{parameter,deploymentSource:bundle.deploymentSource,phaseEvidence:bundle.phaseEvidence,
    evidence:{...nonrootEvidence,archive,targetObservation:bundle.targetObservation},now});
   if(hash(createImageDeploymentPhaseReceipt(context,{sourceReceiptHash:bundle.sourceReceiptHash,phase:bundle.phaseEvidence.phase,now}))!==hash(bundle.phaseReceipt))fail();
   if(local)await local.finish();return context;
  }catch(error){if(local)await local.hold();throw error;}
  finally{if(owned)await owned.close();}
 }
 if(!exact(bundle,['version','kind','parameter','proof','operation','graphEvidence','filesystemEvidence','targetObservation','source'])||bundle.version!==1||bundle.kind!=='image-security-deployment-bundle'||hash(bundle.parameter)!==hash(parameterBinding(parameter)))fail();
 const selected=requireActiveDataRelease(parameter.Value,expected,{now}),data=selected.data;
 const review=bundle.operation?.authorization?.review;
 if(data.version!==2)fail();
 if(typeof controlRevision!=='string'||!/^[a-f0-9]{40}$/.test(controlRevision)||bundle.source?.checkout?.sha!==controlRevision)fail();
 const restored=restoreImageVerificationEvidence({proof:bundle.proof,data,review,graphEvidence:bundle.graphEvidence,filesystemEvidence:bundle.filesystemEvidence},
  {expectedProofHash:data.transition.proofHash,expectedReviewHash:data.policyHash,expectedDataHash:selected.hash,expectedScope:{account:data.account,region:data.region,runtimeNonce:data.runtimeNonce,authorizationId:data.authorizationId}});
 const pins=imageTransitionProofExpected(bundle.proof,{proofHash:data.transition.proofHash});
 const verified=await verifyImageTransitionProof(bundle.proof,{proofHash:data.transition.proofHash,expected:pins,...restored,current:data,review,targetObservation:bundle.targetObservation,now});
 const context=bindImageTransitionAuthorization(verified,{review,now});
 verifyImageDeploymentSource({parameter,source:bundle.source,imageTransition:context,operation:bundle.operation},{now});
 return context;
}
export async function readImageDeploymentBundle(path,expectedHash){
 if(typeof path!=='string'||resolve(path)!==path||typeof expectedHash!=='string'||!/^[a-f0-9]{64}$/.test(expectedHash)||await realpath(path)!==path)fail();
 const fd=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const before=await fd.stat();if(!before.isFile()||before.uid!==process.getuid()||(before.mode&0o777)!==0o600||before.nlink!==1||before.size>32*1024*1024)fail();
  const raw=await fd.readFile(),after=await fd.stat(),named=await lstat(path);
  if(['dev','ino','size','mtimeMs','ctimeMs','mode','uid','nlink'].some(k=>before[k]!==after[k]||before[k]!==named[k])||createHash('sha256').update(raw).digest('hex')!==expectedHash)fail();
  const text=raw.toString('utf8');if(!Buffer.from(text).equals(raw))fail();return parseImageTransitionJson(text);
 }finally{await fd.close();}
}

export async function writeImageDeploymentBundle(bundle,{environmentFile,mask=()=>{}}){
 if(typeof environmentFile!=='string'||!environmentFile)fail();
 const directory=await mkdtemp(join(tmpdir(),'mem9-image-deployment-'));
 const file=join(directory,'bundle.local.json');
 try{
  await chmod(directory,0o700);
  const raw=JSON.stringify(bundle),digest=createHash('sha256').update(raw).digest('hex');
  const fd=await open(file,'wx',0o600);try{await fd.writeFile(raw);await fd.sync();}finally{await fd.close();}
  const parent=await open(directory,'r');try{await parent.sync();}finally{await parent.close();}
  mask(digest);mask(file);
  await appendFile(environmentFile,`MEM9_IMAGE_TRANSITION_BUNDLE_FILE=${file}\nMEM9_IMAGE_TRANSITION_BUNDLE_HASH=${digest}\n`);
  return {file,digest};
 }catch(error){
  await unlink(file).catch(e=>{if(e.code!=='ENOENT')throw e;});await rmdir(directory);throw error;
 }
}

/** Only remove the exact owned bundle. Never recursively clean runner state. */
export async function removeImageDeploymentBundle(env){
 const file=env.MEM9_IMAGE_TRANSITION_BUNDLE_FILE,digest=env.MEM9_IMAGE_TRANSITION_BUNDLE_HASH;
 if(!file&&!digest)return;
 if(!file||!digest||basename(file)!=='bundle.local.json')fail();
 const directory=dirname(file),parent=await lstat(directory);
 if(!/^mem9-image-deployment-[A-Za-z0-9]+$/.test(basename(directory))||dirname(directory)!==await realpath(tmpdir())||await realpath(directory)!==directory||!parent.isDirectory()||parent.uid!==process.getuid()||(parent.mode&0o777)!==0o700)fail();
 await readImageDeploymentBundle(file,digest);
 await unlink(file);await rmdir(directory);
}

export async function installImageDeploymentBundle(clients,{env,expected,controlRevision,nonrootEvidence,parameter:knownParameter,now=Date.now()}){
 const path=env?.MEM9_IMAGE_TRANSITION_BUNDLE_FILE,digest=env?.MEM9_IMAGE_TRANSITION_BUNDLE_HASH;
 if(!path&&!digest)return;
 if(!path||!digest||expected?.stage!=='prod')fail();
 const bundle=await readImageDeploymentBundle(path,digest),name='/mem9-on-aws/prod/consolidation-runtime/data-release';
 const result=knownParameter?{Parameters:[knownParameter]}:await clients.ssm.send(new GetParametersCommand({Names:[name],WithDecryption:true}),{abortSignal:AbortSignal.timeout(30000)});
 if(result.Parameters?.length!==1||result.InvalidParameters?.length||result.Parameters[0].Name!==name)fail();const parameter=result.Parameters[0];
 const context=await restoreImageDeploymentBundle(bundle,{parameter,expected,controlRevision,nonrootEvidence,env,now});
 const data=requireActiveDataRelease(parameter.Value,expected,{now}).data;
 installImageAuthorization(clients,context,{data,controlSourceTree:expected.controlSourceTree,now});return context;
}
