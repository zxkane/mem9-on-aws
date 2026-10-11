import {SSMClient,GetParametersCommand} from '@aws-sdk/client-ssm';
import {S3Client} from '@aws-sdk/client-s3';
import {STSClient,GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import {ECSClient} from '@aws-sdk/client-ecs';
import {IAMClient} from '@aws-sdk/client-iam';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {appendFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {resolveApplicationRegion} from './lib/application-region.mjs';
import {inspectDataRelease} from './lib/production-data-release.mjs';
import {PRODUCTION_DATA_RELEASE_PARAMETER as parameterName} from './lib/production-data-issuance.mjs';
import {dataReleaseEcrReader} from './lib/production-data-evidence.mjs';
import {loadImageTransitionAuthority} from './lib/production-image-archive.mjs';
import {parseImageTransitionJson,imageTransitionAdmissionDeadline} from './lib/production-image-transition-proof.mjs';
import {captureImageDeploymentSource} from './lib/production-image-deployment-reader.mjs';
import {captureNonrootMainSource} from './lib/production-nonroot-source-reader.mjs';
import {loadNonrootDeploymentAuthority} from './lib/production-nonroot-deployment-reader.mjs';
import {nonrootAuthorizationBindings,nonrootAdmissionDeadline,bindNonrootDeploymentContext} from './lib/production-nonroot-proof.mjs';
import {verifyImageDeploymentSource,imageDeploymentParameterBinding as binding} from './lib/production-image-deployment.mjs';
import {createImageDeploymentBundle,createNonrootDeploymentBundle,writeImageDeploymentBundle,removeImageDeploymentBundle} from './lib/production-image-deployment-bundle.mjs';
import {collectNonrootPreviewTarget,nonrootPreviewPhaseEvidence} from './lib/production-nonroot-preview-provider.mjs';
import {captureNonrootControlCheckout,loadNonrootProductionEvidence} from './lib/production-nonroot-deployment-provider.mjs';
import {smokePrivateRead,smokeHash,ciSmokeHost} from './lib/ci-smoke-host.mjs';
import {assertNonrootMetadataReads,createNonrootBudgetedReads} from './lib/production-nonroot-budget-transport.mjs';

const exec=promisify(execFile),fail=code=>{throw Error(code);};
export async function verifyImageSecurityDeployment({clients,git,api,readEcr,loadAuthority,loadNonrootEvidence,host,collectRootAudit,collectControlScan,controlSourceContext,previewSourceContext,previewSource,metadataReads,budgetedReads,controlMetadataReads,clock=Date.now},{env,region,minimumValidityMs=0,phase='source',sourceReceiptHash}){
 if(![0,35*60*1000,80*60*1000].includes(minimumValidityMs))fail('ImageDeploymentWindowInvalid');
 if(!['source','preupdate','preconfigure','presst','prereadiness'].includes(phase))fail('ImageDeploymentPhaseInvalid');
 const preview=/^pr-[1-9][0-9]*$/.test(env.STAGE??'')&&phase!=='source';
 if(env.STAGE!=='prod'&&!preview)return {phase:'image-target-not-production'};
 const role=/^arn:aws:iam::(\d{12}):role\/(?:[^/]+\/)*([^/]+)$/.exec(env.MEM9_DEPLOY_ROLE_ARN??'');
 if(!role||env.GITHUB_ACTIONS!=='true')fail('ImageDeploymentIdentityRequired');
 const identity=await clients.sts.send(new GetCallerIdentityCommand({}),{abortSignal:AbortSignal.timeout(30000)});
 if(identity.Account!==role[1]||!identity.Arn?.startsWith(`arn:aws:sts::${role[1]}:assumed-role/${role[2]}/`))fail('ImageDeploymentCallerMismatch');
 if(preview){
  const source=async()=>{
   if((await git(['diff','--quiet'])).trim()!==''||(await git(['diff','--cached','--quiet'])).trim()!=='')fail('NonrootPreviewSourceChanged');
   const revision=(await git(['rev-parse','HEAD'])).trim(),sourceTree=(await git(['rev-parse','HEAD^{tree}'])).trim();
   if(!/^[a-f0-9]{40}$/.test(sourceTree)||!/^[a-f0-9]{40}$/.test(revision)||revision!==env.GITHUB_SHA)fail('NonrootPreviewSourceChanged');
   return {revision,sourceTree};
  };
  const initial=await source(),scope={stage:env.STAGE,account:identity.Account,region,sourceTree:initial.sourceTree};
  if(previewSource&&(previewSource.checkout.revision!==initial.revision||previewSource.checkout.tree!==initial.sourceTree||previewSource.provenance.sourceTree!==initial.sourceTree))fail('NonrootPreviewSourceChanged');
  previewSourceContext??=await captureNonrootControlCheckout({directory:process.cwd(),tree:initial.sourceTree,metadataReads,budgetedReads});
  const context=await collectNonrootPreviewTarget(clients,{...scope,sourceRevision:previewSource?.provenance.sourceRevision??initial.revision,sourceContext:previewSourceContext,phase,sourceReceiptHash,metadataReads:controlMetadataReads,env,clock});
  if(JSON.stringify(await source())!==JSON.stringify(initial))fail('NonrootPreviewSourceChanged');
  const checked=nonrootPreviewPhaseEvidence(context,{...scope,phase,sourceReceiptHash,now:clock()});
  return {phase:'nonroot-preview-bootstrap-observed',...checked,previewBundle:{version:1,kind:'nonroot-preview-phase-bundle',source:initial,...checked}};
 }
 const read=async()=>{
  const r=await clients.ssm.send(new GetParametersCommand({Names:[parameterName],WithDecryption:true}),{abortSignal:AbortSignal.timeout(30000)});
  if((r.Parameters??[]).length===0&&r.InvalidParameters?.length===1&&r.InvalidParameters[0]===parameterName)return null;
  if(r.InvalidParameters?.length||r.Parameters?.length!==1)fail('ImageDeploymentParameterIncomplete');const p=r.Parameters[0];
  if(p.Name!==parameterName||p.Type!=='SecureString'||p.ARN!==`arn:aws:ssm:${region}:${role[1]}:parameter${parameterName}`||!Number.isSafeInteger(p.Version)||p.Version<1||typeof p.Value!=='string')fail('ImageDeploymentParameterInvalid');
  return binding(p);
 };
 const parameter=await read();if(!parameter)return {phase:'image-target-not-configured'};
 const raw=parseImageTransitionJson(parameter.Value),expected={stage:'prod',account:role[1],region,controlSourceTree:raw.controlSourceTree};
 const selected=inspectDataRelease(raw,expected);if(selected.data.version===1)return {phase:'legacy-data-target'};
 const checkWindow=()=>{if(selected.data.expiresMs-clock()<minimumValidityMs)fail('ImageDeploymentWindowInsufficient');};
 checkWindow();
 const nonroot=selected.data.version===3,load=loadAuthority??(nonroot?loadNonrootDeploymentAuthority:loadImageTransitionAuthority);
 const loaded=await load(clients,{raw:parameter.Value,parameter,expected,bucket:env.MEM9_DECISION_ARTIFACT_BUCKET||undefined,readEcr,metadataReads,budgetedReads,clock});
 const checkEvidenceWindow=()=>{const deadline=(nonroot?nonrootAdmissionDeadline:imageTransitionAdmissionDeadline)(loaded.context),now=clock();if(deadline<=now||deadline-now<minimumValidityMs)fail('ImageDeploymentWindowInsufficient');};
 checkEvidenceWindow();
 if(nonroot){
  if(!/^[a-f0-9]{64}$/.test(sourceReceiptHash??''))fail('NonrootSourceReceiptRequired');
  const b=nonrootAuthorizationBindings(loaded.context),c=b.control;
  const source=await captureNonrootMainSource({git,api},env,{repository:c.repository,prNumber:c.prNumber,candidateRevision:c.revision,candidateTree:c.sourceTree,baseRevision:c.baseRevision});
  let material;
  try{
  if(phase!=='source'){
   const input={clients,parameter,source,phase,context:loaded.context,records:loaded.records,readEcr,metadataReads,budgetedReads,clock};
   material=loadNonrootEvidence?await loadNonrootEvidence(input):await loadNonrootProductionEvidence({...input,env,host:host??ciSmokeHost(env),collectRootAudit,collectControlScan,...(controlSourceContext?{sourceContext:controlSourceContext}:{})});
   if(!material.evidence||!material.deploymentSource||material.phaseEvidence?.phase!==phase)fail('NonrootDeploymentEvidenceRequired');
   loaded.context=await bindNonrootDeploymentContext(loaded.context,{parameter,deploymentSource:material.deploymentSource,phaseEvidence:material.phaseEvidence,
    evidence:{...material.evidence,targetObservation:material.targetObservation},now:clock()});
  }
  const latest=await read();if(!latest||JSON.stringify(latest)!==JSON.stringify(parameter))fail('ImageDeploymentTargetChanged');
  // Recheck actual checkout/main after collection, without restamping its proof.
  const finalSource=await captureNonrootMainSource({git,api},env,{repository:c.repository,prNumber:c.prNumber,candidateRevision:c.revision,candidateTree:c.sourceTree,baseRevision:c.baseRevision});
  if(JSON.stringify(finalSource)!==JSON.stringify(source))fail('ImageDeploymentSourceChanged');
  checkWindow();checkEvidenceWindow();
  const bundle=await createNonrootDeploymentBundle({...loaded.records,...material,context:loaded.context},source,latest,{phase:phase==='source'?'source':'deployment',sourceReceiptHash,now:clock()});
  return {phase:phase==='source'?'nonroot-security-source-verified':'nonroot-deployment-phase-verified',bundle,context:loaded.context,...(bundle.phaseReceipt?{phaseEvidence:bundle.phaseEvidence,phaseReceipt:bundle.phaseReceipt}:{})};
  }catch(error){await metadataReads?.hold?.();throw error;}
  finally{await material?.close?.();}
 }
 const source=await captureImageDeploymentSource({git,api},env,loaded.context);
 const checked=verifyImageDeploymentSource({parameter,source,imageTransition:loaded.context,operation:loaded.records.operation},{now:clock()});
 const latest=await read();if(!latest||JSON.stringify(latest)!==JSON.stringify(parameter))fail('ImageDeploymentTargetChanged');
 verifyImageDeploymentSource({parameter:latest,source,imageTransition:loaded.context,operation:loaded.records.operation},{now:clock()});
 checkWindow();
 checkEvidenceWindow();
 return {phase:'image-security-source-verified',checked,bundle:createImageDeploymentBundle(loaded,source,parameter)};
}
export function parseImageDeploymentArguments(args){
 if(!Array.isArray(args)||args.length&&!['--build','--deploy'].includes(args[0])||args.length!==0&&args.length!==1&&!(args.length===3&&args[0]==='--deploy'&&args[1]==='--phase'&&['preupdate','preconfigure','presst','prereadiness'].includes(args[2])))fail('ImageDeploymentArgumentsInvalid');
 const phase=args[0]==='--deploy'?(args[2]??'preconfigure'):'source';
 const minimumValidityMs=args[0]==='--build'?35*60*1000:phase==='presst'?80*60*1000:0;
 return {phase,minimumValidityMs};
}
export async function main(env=process.env,args=process.argv.slice(2),adapters={}){
 if(args.length===1&&args[0]==='--cleanup'){if(env.GITHUB_ACTIONS==='true'){const {cleanupCiSmokeControlResources}=await import('./lib/ci-smoke-control-resources.mjs');await cleanupCiSmokeControlResources({env});}await removeImageDeploymentBundle(env);return {phase:'image-deployment-bundle-removed'};}
 const {phase,minimumValidityMs}=parseImageDeploymentArguments(args);
 // Named target checkpoints must consume their existing allocation, including
 // the very first identity read. Legacy source/build gates keep their route.
 if(phase!=='source'||Object.hasOwn(adapters,'metadataReads'))assertNonrootMetadataReads(adapters.metadataReads);
 const region=await resolveApplicationRegion();if(env.AWS_REGION&&env.AWS_REGION!==region)fail('ImageDeploymentRegionMismatch');
 if(env.STAGE!=='prod'&&!(/^pr-[1-9][0-9]*$/.test(env.STAGE??'')&&phase!=='source'))return {phase:'image-target-not-production'};
 let previewSource;
 if(env.STAGE!=='prod'){
  const file=env.MEM9_CI_SMOKE_SOURCE_RECEIPT;
  if(typeof env.RUNNER_TEMP!=='string'||file!==resolve(env.RUNNER_TEMP,'mem9-ci-smoke-source/receipt.json'))fail('NonrootPreviewSourceReceiptRequired');
  const raw=await smokePrivateRead(file);if(smokeHash(raw)!==env.MEM9_CI_SMOKE_SOURCE_RECEIPT_HASH)fail('NonrootPreviewSourceReceiptChanged');
  previewSource=parseImageTransitionJson(raw.toString('utf8'));
  const current={repository:env.GITHUB_REPOSITORY,runId:Number(env.GITHUB_RUN_ID),runAttempt:Number(env.GITHUB_RUN_ATTEMPT),job:env.GITHUB_JOB,revision:env.GITHUB_SHA};
  if(previewSource.version!==1||previewSource.kind!=='ci-smoke-source-receipt'||JSON.stringify(previewSource.current)!==JSON.stringify(current)||
   !Number.isSafeInteger(previewSource.observedMs)||previewSource.observedMs>Date.now()||!Number.isSafeInteger(previewSource.expiresMs)||previewSource.expiresMs<=Date.now()||
   !/^[a-f0-9]{40}$/.test(previewSource.provenance?.sourceRevision??''))fail('NonrootPreviewSourceReceiptChanged');
 }
 const account=/::(\d{12}):role\//.exec(env.MEM9_DEPLOY_ROLE_ARN??'')?.[1];
 const budgetedReads=adapters.metadataReads?createNonrootBudgetedReads({region,env,metadataReads:adapters.metadataReads,requestHandler:adapters.requestHandler}):undefined;
 const clients=budgetedReads?.clients??{ssm:new SSMClient({region,maxAttempts:1}),s3:new S3Client({region,maxAttempts:1}),sts:new STSClient({region,maxAttempts:1}),ecs:new ECSClient({region,maxAttempts:1}),iam:new IAMClient({region:'us-east-1',maxAttempts:1})};
 const run=async(file,args)=>(await exec(file,args,{cwd:process.cwd(),env,encoding:'utf8',timeout:30000,maxBuffer:8*1024*1024})).stdout;
 try{
  const result=await verifyImageSecurityDeployment({clients,git:args=>run('git',args),api:async path=>parseImageTransitionJson(await run('gh',['api','--hostname','github.com','repos/'+env.GITHUB_REPOSITORY+'/'+path])),
   readEcr:budgetedReads?(operation,input)=>budgetedReads.readEcr(operation,input,{account}):dataReleaseEcrReader({account,region}),
   metadataReads:adapters.metadataReads,budgetedReads,controlMetadataReads:budgetedReads?.controlMetadata({account,region}),
   loadNonrootEvidence:adapters.loadNonrootEvidence,host:adapters.host,collectRootAudit:adapters.collectRootAudit,collectControlScan:adapters.collectControlScan,controlSourceContext:adapters.controlSourceContext,previewSource},{env,region,minimumValidityMs,phase,sourceReceiptHash:env.MEM9_CI_SMOKE_SOURCE_RECEIPT_HASH});
  if(args[0]==='--build'&&!result.bundle||env.MEM9_EXPECT_IMAGE_TRANSITION!==undefined&&env.MEM9_EXPECT_IMAGE_TRANSITION!==String(Boolean(result.bundle)))fail('ImageDeploymentSelectionChanged');
  // A successful fresh read replaces the prior private bundle. It never
  // changes the authorization's issue/review timestamps or its expiry.
  let bundleRef;
  if(result.bundle||result.previewBundle){
   await removeImageDeploymentBundle(env);
   const written=await writeImageDeploymentBundle(result.bundle??result.previewBundle,{environmentFile:env.GITHUB_ENV});
   bundleRef=Object.freeze({path:written.file,sha256:written.digest});
  }
  if(env.GITHUB_OUTPUT)await appendFile(env.GITHUB_OUTPUT,`image_transition=${result.bundle?'true':'false'}\n`);
  return {phase:result.phase,...(bundleRef?{bundleRef}:{})};
 }finally{if(budgetedReads)budgetedReads.close();else for(const client of Object.values(clients))client.destroy();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)main().then(({phase})=>console.log(JSON.stringify({phase}))).catch(e=>{console.error(JSON.stringify({phase:'image-deployment-held',code:/^[A-Za-z][A-Za-z0-9_.-]{0,127}$/.test(e.message)?e.message:'ImageDeploymentFailed'}));process.exitCode=1;});
