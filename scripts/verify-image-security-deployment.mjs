import {SSMClient,GetParametersCommand} from '@aws-sdk/client-ssm';
import {S3Client} from '@aws-sdk/client-s3';
import {STSClient,GetCallerIdentityCommand} from '@aws-sdk/client-sts';
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
import {verifyImageDeploymentSource,imageDeploymentParameterBinding as binding} from './lib/production-image-deployment.mjs';
import {createImageDeploymentBundle,writeImageDeploymentBundle,removeImageDeploymentBundle} from './lib/production-image-deployment-bundle.mjs';

const exec=promisify(execFile),fail=code=>{throw Error(code);};
export async function verifyImageSecurityDeployment({clients,git,api,readEcr,loadAuthority=loadImageTransitionAuthority,clock=Date.now},{env,region,minimumValidityMs=0}){
 if(![0,35*60*1000,80*60*1000].includes(minimumValidityMs))fail('ImageDeploymentWindowInvalid');
 if(env.STAGE!=='prod')return {phase:'image-target-not-production'};
 const role=/^arn:aws:iam::(\d{12}):role\/(?:[^/]+\/)*([^/]+)$/.exec(env.MEM9_DEPLOY_ROLE_ARN??'');
 if(!role||env.GITHUB_ACTIONS!=='true')fail('ImageDeploymentIdentityRequired');
 const identity=await clients.sts.send(new GetCallerIdentityCommand({}),{abortSignal:AbortSignal.timeout(30000)});
 if(identity.Account!==role[1]||!identity.Arn?.startsWith(`arn:aws:sts::${role[1]}:assumed-role/${role[2]}/`))fail('ImageDeploymentCallerMismatch');
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
 const loaded=await loadAuthority(clients,{raw:parameter.Value,expected,bucket:env.MEM9_DECISION_ARTIFACT_BUCKET||undefined,readEcr,clock});
 const checkEvidenceWindow=()=>{if(imageTransitionAdmissionDeadline(loaded.context)-clock()<minimumValidityMs)fail('ImageDeploymentWindowInsufficient');};
 checkEvidenceWindow();
 const source=await captureImageDeploymentSource({git,api},env,loaded.context);
 const checked=verifyImageDeploymentSource({parameter,source,imageTransition:loaded.context,operation:loaded.records.operation},{now:clock()});
 const latest=await read();if(!latest||JSON.stringify(latest)!==JSON.stringify(parameter))fail('ImageDeploymentTargetChanged');
 verifyImageDeploymentSource({parameter:latest,source,imageTransition:loaded.context,operation:loaded.records.operation},{now:clock()});
 checkWindow();
 checkEvidenceWindow();
 return {phase:'image-security-source-verified',checked,bundle:createImageDeploymentBundle(loaded,source,parameter)};
}
export async function main(env=process.env,args=process.argv.slice(2)){
 if(args.length===1&&args[0]==='--cleanup'){await removeImageDeploymentBundle(env);return {phase:'image-deployment-bundle-removed'};}
 if(args.length>1||args.length&&!['--build','--deploy'].includes(args[0]))fail('ImageDeploymentArgumentsInvalid');
 const minimumValidityMs=args[0]==='--build'?35*60*1000:args[0]==='--deploy'?80*60*1000:0;
 const region=await resolveApplicationRegion();if(env.AWS_REGION&&env.AWS_REGION!==region)fail('ImageDeploymentRegionMismatch');
 if(env.STAGE!=='prod')return {phase:'image-target-not-production'};
 const clients={ssm:new SSMClient({region,maxAttempts:1}),s3:new S3Client({region,maxAttempts:1}),sts:new STSClient({region,maxAttempts:1})};
 const run=async(file,args)=>(await exec(file,args,{cwd:process.cwd(),env,encoding:'utf8',timeout:30000,maxBuffer:8*1024*1024})).stdout;
 try{
  const result=await verifyImageSecurityDeployment({clients,git:args=>run('git',args),api:async path=>parseImageTransitionJson(await run('gh',['api','--hostname','github.com','repos/'+env.GITHUB_REPOSITORY+'/'+path])),readEcr:dataReleaseEcrReader({account:/::(\d{12}):role\//.exec(env.MEM9_DEPLOY_ROLE_ARN??'')?.[1],region})},{env,region,minimumValidityMs});
  if(args[0]==='--build'&&!result.bundle||env.MEM9_EXPECT_IMAGE_TRANSITION!==undefined&&env.MEM9_EXPECT_IMAGE_TRANSITION!==String(Boolean(result.bundle)))fail('ImageDeploymentSelectionChanged');
  // A successful fresh read replaces the prior private bundle. It never
  // changes the authorization's issue/review timestamps or its expiry.
  if(result.bundle){
   await removeImageDeploymentBundle(env);
   await writeImageDeploymentBundle(result.bundle,{environmentFile:env.GITHUB_ENV,mask:value=>process.stdout.write('::add-mask::'+value+'\n')});
  }
  if(env.GITHUB_OUTPUT)await appendFile(env.GITHUB_OUTPUT,`image_transition=${result.bundle?'true':'false'}\n`);
  return {phase:result.phase};
 }finally{for(const client of Object.values(clients))client.destroy();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)main().then(v=>console.log(JSON.stringify(v))).catch(e=>{console.error(JSON.stringify({phase:'image-deployment-held',code:/^[A-Za-z][A-Za-z0-9_.-]{0,127}$/.test(e.message)?e.message:'ImageDeploymentFailed'}));process.exitCode=1;});
