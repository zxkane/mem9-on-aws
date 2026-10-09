/** Capture the actual CONTROL build job. Captures are private observations;
 * only the later full deployment verifier can admit the completed artifact. */
import {mkdir,lstat,realpath,readdir,unlink,rmdir,appendFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {ciSmokeHost,smokePrivateRead,smokePrivateWrite} from './lib/ci-smoke-host.mjs';
import {readImageDeploymentBundle,restoreNonrootBundleAuthorization} from './lib/production-image-deployment-bundle.mjs';
import {nonrootArchiveResolvers} from './lib/production-nonroot-archive.mjs';
import {inspectNonrootRecord,parseNonrootJson,nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {captureNonrootControlCheckout} from './lib/production-nonroot-deployment-provider.mjs';
import {verifyControlBuildCheckout} from './lib/production-control-source.mjs';
import {captureNonrootMainSource} from './lib/production-nonroot-source-reader.mjs';
import {captureNonrootControlBuildAction} from './lib/production-nonroot-control-build.mjs';
export {completeControlRecorderJob} from './lib/production-nonroot-control-build.mjs';
import {readNonrootEvidence} from './lib/production-nonroot-runtime.mjs';
import {parseConfiguredAwsExpiration} from './lib/ci-smoke-session.mjs';

const need=(ok,code='NonrootControlRecorderInvalid')=>{if(!ok)throw Error(code);};
const parse=raw=>parseNonrootJson(new TextDecoder('utf-8',{fatal:true}).decode(raw));
const same=(a,b,code)=>need(hash(a)===hash(b),code);
const buildJob='build-image-transition-control';
const identity=env=>({repository:env.GITHUB_REPOSITORY,revision:env.GITHUB_SHA,runId:Number(env.GITHUB_RUN_ID),attempt:Number(env.GITHUB_RUN_ATTEMPT)});

async function directory(env,{create=false}={}){
 need(typeof env.RUNNER_TEMP==='string'&&resolve(env.RUNNER_TEMP)===env.RUNNER_TEMP&&await realpath(env.RUNNER_TEMP)===env.RUNNER_TEMP,'NonrootControlRecorderDirectory');
 const path=join(env.RUNNER_TEMP,'mem9-control-build');
 if(create)await mkdir(path,{mode:0o700});
 const st=await lstat(path);
 need(st.isDirectory()&&!st.isSymbolicLink()&&st.uid===process.getuid()&&(st.mode&0o777)===0o700&&await realpath(path)===path,'NonrootControlRecorderDirectory');
 return path;
}

/** The source gate has already read the protected parameter. This command
 * replays its same-job private bundle; it neither refreshes that read nor
 * grants itself deployment or registry authority. */
export async function loadControlRecorderSource(host){
 const env=host.env;
 need(env.STAGE==='prod'&&env.GITHUB_EVENT_NAME==='push'&&env.GITHUB_REF==='refs/heads/main'&&env.GITHUB_WORKFLOW_SHA===env.GITHUB_SHA,'NonrootControlRecorderSource');
 const bundle=await readImageDeploymentBundle(env.MEM9_IMAGE_TRANSITION_BUNDLE_FILE,env.MEM9_IMAGE_TRANSITION_BUNDLE_HASH);
 need(bundle.version===2&&bundle.phase==='source'&&bundle.sourceReceiptHash===env.MEM9_CI_SMOKE_SOURCE_RECEIPT_HASH,'NonrootControlRecorderSource');
 const data=parse(Buffer.from(bundle.parameter.Value));
 const restored=await restoreNonrootBundleAuthorization(bundle,{parameter:bundle.parameter,expected:{stage:'prod',account:data.account,region:data.region,controlSourceTree:data.controlSourceTree},controlRevision:env.GITHUB_SHA});
 const contract=inspectNonrootRecord('ControlBuildContractV1',bundle.proof.taskPlan.deployedControlBuildContract);
 const sourceContext=await captureNonrootControlCheckout({directory:host.cwd,tree:contract.candidate.tree});
 const expected={repository:contract.repository,prNumber:contract.prNumber,candidateRevision:contract.candidate.revision,candidateTree:contract.candidate.tree,baseRevision:contract.candidate.baseRevision};
 const source=await captureNonrootMainSource({git:args=>host.run('git',args),api:host.api},env,expected);
 same(source,bundle.source,'NonrootControlRecorderSourceChanged');
 return {contract,source,sourceContext,options:{...nonrootArchiveResolvers(restored.archive),expected:{sourceContext}},bundleHash:env.MEM9_IMAGE_TRANSITION_BUNDLE_HASH,data};
}

export async function captureControlRecorderJob(host,material,{metadata,outputDigest,now=Date.now()}){
 const {contract,source,options}=material;
 const run=await host.api('actions/runs/'+source.run.id+'/attempts/'+source.run.attempt);
 const list=await host.api('actions/runs/'+source.run.id+'/attempts/'+source.run.attempt+'/jobs?per_page=100');
 need(Array.isArray(list.jobs)&&list.jobs.length===list.total_count&&list.jobs.length<=100,'NonrootControlRecorderJobsIncomplete');
 const jobSource=parse(await readNonrootEvidence(contract.workflow.jobSource,options,false));
 const matches=list.jobs.filter(job=>job.name===jobSource.name);
 need(matches.length===1,'NonrootControlRecorderJobAmbiguous');
 return captureNonrootControlBuildAction({contract,source,run,job:matches[0],metadata,outputDigest,observedMs:now},options);
}

export async function main(env=process.env,args=process.argv.slice(2),adapters={}){
 need(args.length===1&&['prepare','capture','publish','cleanup'].includes(args[0]),'NonrootControlRecorderArguments');
 const mode=args[0];
 if(mode==='cleanup'){
  let dir;try{dir=await directory(env);}catch(error){if(error.code==='ENOENT')return {phase:'control-build-capture-absent'};throw error;}
  const names=await readdir(dir),allowed=['prepared.local.json','capture.local.json','completion.local.json','build-log.local.bin','put-intent.local.json','put-result.local.json'];
  need(names.every(name=>allowed.includes(name)),'NonrootControlRecorderCleanupInventory');
  for(const name of names)await smokePrivateRead(join(dir,name),16777216);
  if(names.includes('put-intent.local.json')){
   need(names.includes('put-result.local.json'),'NonrootControlPublishUnresolved');
   const intent=parse(await smokePrivateRead(join(dir,'put-intent.local.json'))),result=parse(await smokePrivateRead(join(dir,'put-result.local.json')));
   same(intent.commitment,result.commitment,'NonrootControlPublishUnresolved');
   need(typeof result.etag==='string'&&result.etag.length>0,'NonrootControlPublishUnresolved');
  }
  for(const name of names)await unlink(join(dir,name));await rmdir(dir);
  return {phase:'control-build-capture-removed'};
 }
 const host=adapters.host??ciSmokeHost(env);
 need(host.env===env&&env.GITHUB_ACTIONS==='true'&&env.STAGE==='prod'&&env.GITHUB_EVENT_NAME==='push'&&env.GITHUB_REF==='refs/heads/main','NonrootControlRecorderJob');
 need(env.GITHUB_JOB===buildJob,'NonrootControlRecorderJob');
 const material=await loadControlRecorderSource(host);
 const fingerprint=await verifyControlBuildCheckout(material.sourceContext,host.cwd);
 if(mode==='prepare'){
  const dir=await directory(env,{create:true});
  await smokePrivateWrite(join(dir,'prepared.local.json'),{version:1,kind:'control-build-prepared',identity:identity(env),bundleHash:material.bundleHash,contractHash:hash(material.contract),fingerprint,preparedMs:Date.now()});
  return {phase:'control-build-context-prepared'};
 }
 const dir=await directory(env),prepared=parse(await smokePrivateRead(join(dir,'prepared.local.json')));
 need(prepared.version===1&&prepared.kind==='control-build-prepared'&&prepared.contractHash===hash(material.contract),'NonrootControlRecorderPrepared');
 same(prepared.identity,identity(env),'NonrootControlRecorderIdentityChanged');same(prepared.fingerprint,fingerprint,'NonrootControlRecorderCheckoutChanged');
 if(mode==='capture'){
  need(prepared.bundleHash===material.bundleHash,'NonrootControlRecorderBundleChanged');
  const capture=await captureControlRecorderJob(host,material,{metadata:env.MEM9_CONTROL_BUILD_METADATA,outputDigest:env.MEM9_EXPECTED_BOOTSTRAP_DIGEST});
  need(Number.isSafeInteger(prepared.preparedMs)&&prepared.preparedMs<=Date.parse(capture.action.started_at)&&capture.observedMs-prepared.preparedMs<=1800000,'NonrootControlRecorderTime');
  await smokePrivateWrite(join(dir,'capture.local.json'),capture);
  return {phase:'control-build-action-captured'};
 }
 const capture=parse(await smokePrivateRead(join(dir,'capture.local.json')));
 if(mode==='publish'){
  need(prepared.bundleHash===material.bundleHash,'NonrootControlRecorderBundleChanged');
  same(capture.source,material.source,'NonrootControlRecorderSourceChanged');
  // Revalidate the original observation without replacing its capture clock
  // or inventing completion of the still-running build job.
  const checked=await captureNonrootControlBuildAction({...capture,contract:material.contract},material.options);
  same(checked,capture,'NonrootControlRecorderCaptureChanged');
  const {encodeControlBuildCapture,controlBuildArchiveKey,controlBuildArchiveLocation,putControlBuildCapture}=await import('./lib/production-control-capture-archive.mjs');
  const encoded=encodeControlBuildCapture({prepared,capture}),{account,region}=material.data;
  const bucket=env.MEM9_DECISION_ARTIFACT_BUCKET||'mem9-audit-'+account,bucketArn='arn:aws:s3:::'+bucket;
  const config={stage:'prod',account,region,bucket,bucketArn,objectArn:bucketArn+'/'+controlBuildArchiveKey('prod',encoded.commitment),roleArn:env.MEM9_DEPLOY_ROLE_ARN,
   encryption:{algorithm:'aws:kms',keyArn:env.MEM9_CI_EVIDENCE_KMS_KEY_ARN,bucketKeyEnabled:true}};
  controlBuildArchiveLocation(config,encoded.commitment);
  const expiration=parseConfiguredAwsExpiration(env.MEM9_CI_CREDENTIALS_EXPIRES,Date.now());
  const credentials={accessKeyId:env.AWS_ACCESS_KEY_ID,secretAccessKey:env.AWS_SECRET_ACCESS_KEY,sessionToken:env.AWS_SESSION_TOKEN,expiration};
  need(typeof env.GITHUB_OUTPUT==='string'&&env.GITHUB_OUTPUT.length>0,'NonrootControlRecorderOutput');
  await smokePrivateWrite(join(dir,'put-intent.local.json'),{version:1,commitment:encoded.commitment});
  const result=await putControlBuildCapture(encoded,{config,credentials,deadlineMs:Math.min(Date.now()+60000,expiration.getTime()),requestHandler:adapters.requestHandler});
  await smokePrivateWrite(join(dir,'put-result.local.json'),result);
  const commitment=JSON.stringify(encoded.commitment);
  await appendFile(env.GITHUB_OUTPUT,'commitment='+commitment+'\n');
  process.stdout.write('MEM9_CONTROL_BUILD_COMMITMENT '+commitment+'\n');
  return {phase:'control-build-capture-published'};
 }
 throw Error('NonrootControlRecorderArguments');
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)main().then(value=>console.log(JSON.stringify(value))).catch(error=>{
 console.error(JSON.stringify({phase:'control-build-record-held',code:/^[A-Za-z][A-Za-z0-9_.-]{0,127}$/.test(error.message)?error.message:'NonrootControlRecorderFailed'}));process.exitCode=1;
});
