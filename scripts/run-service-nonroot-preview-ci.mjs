import assert from 'node:assert/strict';
import {mkdir,writeFile,appendFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {STSClient,GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import {S3Client,GetPublicAccessBlockCommand,GetBucketEncryptionCommand} from '@aws-sdk/client-s3';
import {runServiceNonrootPreview} from './run-service-nonroot-preview.mjs';
import {collectPreviewEvidence,uploadPreviewEvidence} from './lib/service-nonroot-preview-evidence.mjs';

const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const env=process.env;
assert(env.GITHUB_ACTIONS==='true'&&env.GITHUB_REPOSITORY==='zxkane/mem9-on-aws'&&env.GITHUB_EVENT_NAME==='workflow_dispatch');
assert(/^pr-[1-9][0-9]*$/.test(env.STAGE)&&/^[a-f0-9]{40}$/.test(env.GITHUB_SHA)&&/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ID)&&/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ATTEMPT));
assert(env.RUNNER_TEMP&&resolve(env.RUNNER_TEMP)===env.RUNNER_TEMP&&env.GITHUB_OUTPUT);
const directory=join(env.RUNNER_TEMP,'service-nonroot-'+env.GITHUB_RUN_ID+'-'+env.GITHUB_RUN_ATTEMPT);
await mkdir(directory,{mode:0o700});let report,expectedAccount;
try{
 const baseline=env.MEM9_SERVICE_NONROOT_BASELINE;delete env.MEM9_SERVICE_NONROOT_BASELINE;
 assert(baseline&&Buffer.byteLength(baseline)<=32768,'BaselineSecretMissing');
 const definition=JSON.parse(baseline).taskDefinition,identity=/^arn:aws:ecs:([a-z0-9-]+):(\d{12}):task-definition\/mem9-on-aws-prod-/.exec(definition?.taskDefinitionArn??'');
 assert(identity&&identity[1]===env.AWS_REGION,'BaselineAccountRegionInvalid');expectedAccount=identity[2];
 const baselinePath=join(directory,'baseline.local.json');await writeFile(baselinePath,baseline,{mode:0o600,flag:'wx'});
 report=await runServiceNonrootPreview({stage:env.STAGE,baselinePath,baselineHash:sha(baseline),evidenceRoot:directory,expectedSource:env.GITHUB_SHA,ciRunId:env.MEM9_SERVICE_NONROOT_CI_RUN});
}catch{
 const evidence=join(directory,'failure.local.json');
 report={version:1,stage:env.STAGE,sourceCommit:env.GITHUB_SHA,outcome:'HELD',failures:['PreviewVerificationIncomplete'],cleanup:{verified:false,failures:['InspectWorkflowAndOwnedResources']},evidence};
 const body=JSON.stringify(report);await writeFile(evidence,body,{mode:0o600,flag:'wx'});report.evidenceHash=sha(body);
}
const s3=new S3Client({region:env.AWS_REGION,maxAttempts:1}),sts=new STSClient({region:env.AWS_REGION,maxAttempts:1});
const call=(client,command)=>client.send(command,{abortSignal:AbortSignal.timeout(30000)});
try{
 const account=(await call(sts,new GetCallerIdentityCommand({}))).Account;assert(/^\d{12}$/.test(account)&&account===expectedAccount,'EvidenceAccountMismatch');
 const bucket=env.MEM9_DECISION_ARTIFACT_BUCKET||'mem9-audit-'+account,input={Bucket:bucket,ExpectedBucketOwner:account};
 const [block,encryption]=await Promise.all([call(s3,new GetPublicAccessBlockCommand(input)),call(s3,new GetBucketEncryptionCommand(input))]);
 assert.deepEqual(block.PublicAccessBlockConfiguration,{BlockPublicAcls:true,IgnorePublicAcls:true,BlockPublicPolicy:true,RestrictPublicBuckets:true});
 assert(encryption.ServerSideEncryptionConfiguration.Rules.some(r=>r.ApplyServerSideEncryptionByDefault.SSEAlgorithm==='aws:kms'));
 const bundle=await collectPreviewEvidence(report),prefix=`runtime-service-hardening/previews/${env.STAGE}/${env.GITHUB_SHA}/${env.GITHUB_RUN_ID}-${env.GITHUB_RUN_ATTEMPT}/`;
 const uploaded=await uploadPreviewEvidence({bundle,client:s3,bucket,account,prefix});
 if(uploaded.evidenceUploaded)await appendFile(env.GITHUB_OUTPUT,'evidence_uploaded=true\n');
 if(uploaded.cleanupAuthorized)await appendFile(env.GITHUB_OUTPUT,'cleanup_authorized=true\n');
 console.log(JSON.stringify(uploaded));
 if(bundle.outcome!=='PASS')process.exitCode=1;
}catch{console.error('PrivatePreviewEvidenceUploadFailed');process.exitCode=1;}
finally{s3.destroy();sts.destroy();}
