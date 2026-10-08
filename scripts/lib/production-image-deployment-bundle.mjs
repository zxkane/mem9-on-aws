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
const fail=()=>{throw Error('ImageDeploymentBundleInvalid');};
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join();
export function createImageDeploymentBundle({records,targetObservation},source,parameter){
 return {version:1,kind:'image-security-deployment-bundle',parameter:parameterBinding(parameter),proof:structuredClone(records.proof),operation:structuredClone(records.operation),graphEvidence:structuredClone(records.graphEvidence),filesystemEvidence:structuredClone(records.filesystemEvidence),targetObservation:structuredClone(targetObservation),source:structuredClone(source)};
}
/** A private file carries evidence, never authority. The current protected
 * parameter and current checked-out source are independently supplied again. */
export async function restoreImageDeploymentBundle(bundle,{parameter,expected,controlRevision,now=Date.now()}){
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

export async function installImageDeploymentBundle(clients,{env,expected,controlRevision,now=Date.now()}){
 const path=env?.MEM9_IMAGE_TRANSITION_BUNDLE_FILE,digest=env?.MEM9_IMAGE_TRANSITION_BUNDLE_HASH;
 if(!path&&!digest)return;
 if(!path||!digest||expected?.stage!=='prod')fail();
 const bundle=await readImageDeploymentBundle(path,digest),name='/mem9-on-aws/prod/consolidation-runtime/data-release';
 const result=await clients.ssm.send(new GetParametersCommand({Names:[name],WithDecryption:true}),{abortSignal:AbortSignal.timeout(30000)});
 if(result.Parameters?.length!==1||result.InvalidParameters?.length)fail();const parameter=result.Parameters[0];
 const context=await restoreImageDeploymentBundle(bundle,{parameter,expected,controlRevision,now});
 const data=requireActiveDataRelease(parameter.Value,expected,{now}).data;
 installImageAuthorization(clients,context,{data,controlSourceTree:expected.controlSourceTree,now});return context;
}
