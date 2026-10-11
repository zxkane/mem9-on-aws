import {FUTURE_CONTROL_CAPACITY} from './lib/production-control-capacity.mjs';
import {NONROOT_REMAINING_WORK_LIMITS_HASH_V2,NONROOT_REMAINING_WORK_CAPS_V2} from './lib/production-nonroot-budget-revision.mjs';
import {collectNonrootControlImage} from './lib/production-nonroot-control-download.mjs';
import {digestAliases} from './production-image-response.fixture.mjs';
import {it,expect,vi,afterEach} from 'vitest';
import {Readable} from 'node:stream';
import {createHash} from 'node:crypto';
import {nonrootDeploymentWrapperFixture} from './production-nonroot-deployment.fixture.mjs';
import {captureNonrootControlBuildAction,completeNonrootControlBuildAction} from './lib/production-nonroot-control-build.mjs';
import {encodeControlBuildCapture} from './lib/production-control-capture-archive.mjs';
import {nonrootArchiveResolvers} from './lib/production-nonroot-archive.mjs';
import {createImageBudget,IMAGE_MEDIA,readControlImageGraph,controlImageGraphBinding} from './lib/production-image-graph.mjs';
import {inspectImageFilesystem} from './lib/production-image-filesystem.mjs';
import {tar} from './production-image.fixture.mjs';
import {registerControlCache,beginControlImageLoad,recordControlImageLoad,cleanupCiSmokeControlResources} from './lib/ci-smoke-control-resources.mjs';
import {mkdtemp,mkdir,readFile,writeFile,rm,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {DefaultArtifactClient} from '@actions/artifact';
import {NodeHttpHandler} from '@smithy/node-http-handler';
import {GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import {GetParametersCommand} from '@aws-sdk/client-ssm';
import {GetObjectCommand} from '@aws-sdk/client-s3';
import {createProspectiveCiRootRequestPolicy} from './lib/ci-smoke-root-request-cost.mjs';
import {ciRootReadyStatus} from './lib/ci-smoke-root-request.mjs';
import {createFutureOwnerDeliveryTemplate} from './lib/ci-smoke-owner-delivery.mjs';
import {ListTasksCommand,DescribeTasksCommand,DescribeTaskDefinitionCommand} from '@aws-sdk/client-ecs';
import {nonrootHash as hash,NONROOT_LIMITS_HASH} from './lib/production-nonroot-contracts.mjs';
import {zero,sha,addCounters} from './lib/ci-smoke-acquisition-format.mjs';
import {createFutureFundingPlan,inspectFutureFundingPlan,FUTURE_OWNER_PUBLICATION} from './lib/ci-smoke-grants.mjs';
import {makeCiStartupRunBinding,ciStartupCheckpointSelection} from './lib/ci-smoke-startup.mjs';
import {futureAcquisitionScope} from './lib/ci-smoke-future-config.mjs';
import {openCiSmokeAcquisition,openCiSmokeDeploymentLocalReplay} from './lib/ci-smoke-acquisition.mjs';
import {openFutureCiSmokeAcquisition} from './lib/ci-smoke-future-acquisition.mjs';
import {createNonrootBudgetedReads} from './lib/production-nonroot-budget-transport.mjs';
import {PRODUCTION_DATA_RELEASE_PARAMETER as parameterName} from './lib/production-data-issuance.mjs';
const NOW=Date.now(),account='123456789012',region='us-east-1',roots=[];let sequence=0;
afterEach(async()=>{vi.restoreAllMocks();vi.unstubAllEnvs();for(const p of roots.splice(0))await rm(p,{recursive:true,force:true});});
const profile=(id,action,request,extra={})=>({version:1,id,kind:'EXACT',action,request,requestBytes:4096,responseBytes:16384,count:1,ecr:false,...extra});
function ownerStatuses(f){
 const b=f.binding.source,base={id:1,url:`https://api.github.com/repos/${b.repository}/statuses/${b.mainRevision}`,creator:{id:42}};
 const rows=[{...base,context:'mem9/prepaid/'+f.config.startup.grantSetId,state:'success',description:'binding:'+hash(f.binding),target_url:`https://github.com/${b.repository}/actions/runs/${b.runId}`}];
 // Synthetic owner selection is separate from upload success. The inbox
 // permits duplicate names; only its fixed first selection gets announced.
 if(f.artifact&&f.ownerWinner){const selected=ciStartupCheckpointSelection(f.config.startup,f.binding,f.scope,f.ownerWinner);rows.unshift({...base,id:2,...selected.announcement.payload});}
 return rows;
}

function fixture(){
 const scope={kind:'target',jobKey:'deploy-prod',route:'deploy-prod',phase:'presst',checkpoint:'deploy-prod/19'};
 const descriptor={version:3,stage:'prod',account,region,controlSourceTree:'2'.repeat(40),dataRevision:'3'.repeat(40),dataSourceTree:'4'.repeat(40),dataSourceTag:'mem9-3333333',images:{},runtimeNonce:'1'.repeat(32),authorizationId:'2'.repeat(32),issuedMs:NOW-1000,expiresMs:NOW+600000,
  transition:{version:2,kind:'image-security-nonroot-upgrade',proofHash:hash({synthetic:'proof'}),predecessorHash:'b'.repeat(64),limitsHash:NONROOT_LIMITS_HASH}};
 for(const k of ['parentProofHash','backendBindingHash','generation','targetsHash','schemaDigest','operatorDigest','buildInputsHash','securityEvidenceHash','policyHash'])descriptor[k]='b'.repeat(64);
 for(const k of ['llm-proxy','mnemo-server','qwen3-embed'])descriptor.images[k]={rootDigest:'sha256:'+'c'.repeat(64),arm64Digest:'sha256:'+'d'.repeat(64)};
 const startup={version:1,kind:'owner-prepaid-startup-config',grantSetId:hash({synthetic:++sequence}),grantHash:'2'.repeat(64),ledgerStartHash:'3'.repeat(64),catalogHash:'4'.repeat(64),descriptorHash:hash(descriptor),proofHash:descriptor.transition.proofHash,
  source:{repository:'example/repository',prNumber:17,candidateRevision:'1'.repeat(40),candidateTree:descriptor.controlSourceTree,baseRevision:'3'.repeat(40)},consumers:[scope],ownerGithubActorId:42,notAfter:NOW+300000};
 const config={version:2,kind:'owner-ci-acquisition-config',startup,target:{kind:'production-data-release',descriptor,parameterVersion:2},account,region,ownerRoot:{runtimeNonce:descriptor.runtimeNonce,authorizationId:descriptor.authorizationId},
  storage:{bucket:'example-ci-reader',kmsKeyArn:`arn:aws:kms:${region}:${account}:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee`,bucketKeyEnabled:true},bootstrap:[{checkpoint:scope.checkpoint,responseBytes:1048576}]};
 const roleArn=`arn:aws:iam::${account}:role/github-actions-mem9-on-aws-prod`;
 const env={GITHUB_ACTIONS:'true',GITHUB_SERVER_URL:'https://github.com',GITHUB_REPOSITORY:startup.source.repository,GITHUB_RUN_ID:'77',GITHUB_RUN_ATTEMPT:'1',GITHUB_JOB:scope.jobKey,GITHUB_SHA:'4'.repeat(40),GITHUB_WORKFLOW_SHA:'4'.repeat(40),GITHUB_EVENT_NAME:'push',GITHUB_REF:'refs/heads/main',AWS_REGION:region,
  ACTIONS_ID_TOKEN_REQUEST_TOKEN:'synthetic-oidc-request',ACTIONS_ID_TOKEN_REQUEST_URL:'https://pipelines.actions.githubusercontent.com/synthetic/_apis/distributedtask/hubs/build/plans/00000000-0000-4000-8000-000000000001/jobs/00000000-0000-4000-8000-000000000002/idtoken?api-version=2.0',MEM9_CI_ACQUISITION_CONFIG:JSON.stringify(config)};
 return {config,scope,roleArn,env};
}
function fundedGrant(f){
 const tick=f.tick??NOW;
 const ledgerBinding={owner:'a'.repeat(32),executionId:'b'.repeat(32),planHash:'c'.repeat(64),publicationHash:'d'.repeat(64)},reserve={ecrRequests:100,logicalBytes:100000000,httpBodyBytes:500000000,uncompressedBytes:100000000,processedEntries:1000};
 if(f.controlCapacity){Object.assign(reserve,{ecrRequests:20000,logicalBytes:32*1024**3,httpBodyBytes:16*1024**3,uncompressedBytes:32*1024**3,processedEntries:1000000});}
 const start={version:f.controlCapacity?2:1,...(f.controlCapacity?{budgetRevision:f.config.budgetRevision}:{}),kind:'custody-ledger-start',binding:ledgerBinding,startingCounters:zero(),reserve,deadlineMs:tick+2700000,mode:'adoption'},startRaw=Buffer.from(JSON.stringify(start));
 const identity={version:1,id:'identity',kind:'EXACT',action:'GetCallerIdentity',request:{},requestBytes:1024,responseBytes:4096,count:1,ecr:false};
 const catalog={version:1,kind:'future-ci-profile-catalog',source:f.config.startup.source,ledgerBinding,consumers:[{scope:f.scope,profiles:f.profiles,localBudget:f.localBudget,handshake:{terminalResponseBytes:f.config.bootstrap[0].responseBytes}}],owner:{publication:FUTURE_OWNER_PUBLICATION,localBudget:zero()},finalization:{profiles:[identity],localBudget:zero()},localBudget:zero()};
 let rootCarrier;
 if(f.controlCapacity){
  catalog.version=2;catalog.cumulativeLimitsHash=NONROOT_REMAINING_WORK_LIMITS_HASH_V2;
  const row=catalog.consumers[0];catalog.consumers=f.config.startup.consumers.map(scope=>({...structuredClone(row),scope,controlCapacity:FUTURE_CONTROL_CAPACITY}));
  const root={version:1,kind:'future-owner-root-template',rootBindingHash:'b'.repeat(64),carrierTemplateHash:'c'.repeat(64),carrierSlot:{owner:ledgerBinding.owner,executionId:ledgerBinding.executionId,slotNonce:'e'.repeat(32)},source:f.config.startup.source};catalog.owner.roots=root;
  rootCarrier={...root,kind:'future-owner-root-carrier',carrierBuildHash:'f'.repeat(64),image:{account:f.config.account,region:f.config.region,repositoryName:'mem9-on-aws/preview/bootstrap',rootDigest:'sha256:'+'a'.repeat(64),arm64Digest:'sha256:'+'b'.repeat(64),configDigest:'sha256:'+'c'.repeat(64)}};
  if(f.prospectiveRoot){
   catalog.owner.delivery=createFutureOwnerDeliveryTemplate({source:{profile:'default',provider:'instance-metadata',configFile:'/synthetic/config',credentialsFile:'/synthetic/credentials',configHash:'a'.repeat(64),credentialsHash:null},storage:f.config.storage});
   for(const row of catalog.consumers){row.rootRequest=createProspectiveCiRootRequestPolicy(row.scope.checkpoint);row.profiles.push({...profile('root-audit','GetObject',{Bucket:f.config.storage.bucket,ExpectedBucketOwner:f.config.account},{requestBytes:0,responseBytes:33554432}),kind:'OWNER_ROOT_ARTIFACT_FROM_FUNDED_CHECKPOINT',late:{field:'Key',checkpoint:row.scope.checkpoint}});}
  }
 }
 const plan=createFutureFundingPlan({...(f.controlCapacity?{rootCarrier,budgetRevision:f.config.budgetRevision,compiledCeiling:f.config.compiledCeiling}:{}),binding:{grantSetId:f.config.startup.grantSetId,source:f.config.startup.source,anchors:{predecessorParameterHash:'a'.repeat(64),rootBindingHash:'b'.repeat(64),copyCheckpointHash:'c'.repeat(64),authorizationId:f.config.ownerRoot.authorizationId,nextParameterVersion:f.config.target.parameterVersion}},catalogRaw:Buffer.from(JSON.stringify(catalog)).toString('base64'),ledgerStartHash:sha(startRaw),ownerGithubActorId:42,ownerStateDirectory:'/synthetic/grant-'+f.config.startup.grantSetId,issuedMs:tick-1000});
 const funding=inspectFutureFundingPlan(plan),spent=f.controlCapacity?Object.fromEntries(Object.keys(zero()).map(k=>[k,start.startingCounters[k]+plan.budget[k]])):addCounters(start.startingCounters,plan.budget),remaining=Object.fromEntries(Object.entries(reserve).map(([k,v])=>[k,v-plan.budget[k]]));
 const event={version:f.controlCapacity?2:1,...(f.controlCapacity?{budgetRevision:f.config.budgetRevision}:{}),sequence:1,...ledgerBinding,previousHash:null,type:'prepayment',data:{allocationId:funding.planHash,planHash:funding.planHash,scopeHash:funding.scopeHash,charge:plan.budget,reserveDebit:plan.budget},spent,remaining};
 const checkpoint={binding:ledgerBinding,startingCounters:start.startingCounters,counters:spent,remainingReservation:remaining,eventCount:1,lastEventHash:hash(event),active:0,sealed:false,...(f.controlCapacity?{budgetRevision:f.config.budgetRevision}:{})};
 const grantSet={...plan,version:f.controlCapacity?3:2,kind:'owner-prepaid-future-grant-set',authority:false,planHash:funding.planHash,allocationId:funding.planHash,debit:{start,startRaw:startRaw.toString('base64'),events:[event],checkpoint}};
 const expected={grantSetId:plan.grantSetId,grantHash:hash(grantSet),ledgerStartHash:plan.ledgerStartHash,catalogHash:plan.catalogHash};
 return {grantSet,expected};
}

async function setup({profiles=[],localBudget={...zero(),logicalBytes:10000}}={}){
 const f=fixture();f.localBudget=localBudget;f.profiles=[profile('identity','GetCallerIdentity',{}),profile('descriptor','GetParameters',{Names:[parameterName],WithDecryption:true}),...profiles];
 f.funding=fundedGrant(f);Object.assign(f.config.startup,f.funding.expected);
 const root=await mkdtemp(join(tmpdir(),'ci-future-target-'));roots.push(root);f.root=root;f.events=[];f.now=Date.now();f.offset=0;f.http=[];
 Object.assign(f.env,{STAGE:'prod',RUNNER_TEMP:root,AWS_ACCESS_KEY_ID:'ASIASYNTHETIC',AWS_SECRET_ACCESS_KEY:'synthetic-secret',AWS_SESSION_TOKEN:'synthetic-token',MEM9_DEPLOY_ROLE_ARN:f.roleArn,MEM9_CI_ACQUISITION_CONFIG:JSON.stringify(f.config)});
 const s=f.config.startup.source,main=f.env.GITHUB_SHA,parents=[s.baseRevision,s.candidateRevision];
 f.source={repository:s.repository,event:'push',ref:'refs/heads/main',checkout:{sha:main,tree:s.candidateTree,parents,clean:true},main:{sha:main,tree:s.candidateTree},run:{id:77,attempt:1,event:'push',headSha:main,repository:s.repository,path:'.github/workflows/infra-ci.yml',workflowSha:main},pullRequest:{number:17,state:'closed',merged:true,headSha:s.candidateRevision,headRepository:s.repository,baseRef:'main',mergeCommitSha:main}};
 f.binding=makeCiStartupRunBinding(f.config.startup,f.source);
 const run={id:77,run_attempt:1,status:'in_progress',event:'push',head_sha:main,head_branch:'main',path:f.source.run.path,repository:{full_name:s.repository},head_repository:{full_name:s.repository}};
 f.host={env:f.env,cwd:root,checkout:async()=>({revision:main,tree:s.candidateTree}),run:vi.fn(async(file,args)=>{expect(file).toBe('git');if(args[0]==='diff')return '';if(args[0]==='show')return [main,s.candidateTree,parents.join(' ')].join('\n');throw Error('UnexpectedGit');}),api:vi.fn(async path=>{
  if(path==='commits/main'||path==='commits/'+main)return {sha:main,commit:{tree:{sha:s.candidateTree}},parents:parents.map(sha=>({sha}))};
  if(path==='pulls/17')return {number:17,state:'closed',merged:true,head:{sha:s.candidateRevision,repo:{full_name:s.repository}},base:{ref:'main'},merge_commit_sha:main};
  if(path==='actions/runs/77'||path==='actions/runs/77/attempts/1')return run;
  if(path.startsWith('commits/'+main+'/statuses?'))return ownerStatuses(f);
  if(path==='actions/artifacts/'+f.artifact?.id)return {...f.artifact,created_at:new Date(Date.now()).toISOString()};throw Error('UnexpectedGithub');
 })};
 f.save=async(name,value)=>{const path=join(root,name),raw=Buffer.from(JSON.stringify(value));await writeFile(path,raw,{mode:0o600});return {path,sha256:sha(raw)};};
 await mkdir(join(root,'mem9-ci-smoke-source'),{mode:0o700});
 f.receipt={version:1,kind:'ci-smoke-source-receipt',current:{repository:s.repository,runId:77,runAttempt:1,job:'deploy-prod',revision:main},checkout:{revision:main,tree:s.candidateTree},observedMs:NOW,expiresMs:NOW+300000};
 const ref=await f.save('mem9-ci-smoke-source/receipt.json',f.receipt);f.env.MEM9_CI_SMOKE_SOURCE_RECEIPT=ref.path;f.env.MEM9_CI_SMOKE_SOURCE_RECEIPT_HASH=ref.sha256;
 f.artifactClient={uploadArtifact:vi.fn(async(name,files)=>{f.events.push('artifact');f.artifactPayload=JSON.parse(await readFile(files[0],'utf8'));const id=(f.artifact?.id??122)+1,artifactDigest=id===123?'e'.repeat(64):hash({id,nonce:f.artifactPayload.nonce});f.artifact={id,name,size_in_bytes:256,digest:'sha256:'+artifactDigest,expired:false,expires_at:new Date(NOW+86400000).toISOString(),workflow_run:{id:77,head_sha:main,head_branch:'main'}};f.ownerWinner??={...f.artifactPayload,artifactId:id,artifactDigest};return {id,size:256,digest:artifactDigest};})};
 f.parameter={Name:parameterName,Type:'SecureString',ARN:`arn:aws:ssm:${region}:${account}:parameter${parameterName}`,Version:2,Value:JSON.stringify(f.config.target.descriptor)};
 f.response=()=>({version:1,kind:'owner-ci-allowance-response',runBinding:f.binding,scope:f.scope,nonce:f.request.nonce,artifactId:123,requestHash:hash(f.request),grantSet:f.funding.grantSet,expiresMs:NOW+300000});
 f.handler={destroy:vi.fn(),handle:vi.fn(async request=>{
  const record={method:request.method,path:request.path,headers:{...request.headers},body:request.body};f.http.push(record);let raw,statusCode=200,headers={'content-type':'application/json'};
  if(request.hostname.startsWith('s3.')){
   if(request.method==='PUT'){f.events.push('put');f.request=JSON.parse(Buffer.from(request.body).toString());expect(request.headers['if-none-match']).toBe('*');raw=Buffer.from('');headers={etag:'"synthetic-etag"','x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':f.config.storage.kmsKeyArn,'x-amz-server-side-encryption-bucket-key-enabled':'true'};}
   else {f.events.push('get');raw=Buffer.from(JSON.stringify(f.response()));headers={...headers,'x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':f.config.storage.kmsKeyArn,'x-amz-server-side-encryption-bucket-key-enabled':'true'};}
  }else if(request.hostname.startsWith('sts.')){raw=Buffer.from(`<GetCallerIdentityResponse><GetCallerIdentityResult><Account>${f.config.account}</Account><Arn>arn:aws:sts::${f.config.account}:assumed-role/github-actions-mem9-on-aws-prod/synthetic</Arn><UserId>AROASYNTHETIC:synthetic</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`);headers={'content-type':'text/xml'};}
  else raw=Buffer.from(JSON.stringify({Parameters:[f.parameter],InvalidParameters:[]}));
  return {response:{statusCode,headers:{...headers,'content-length':String(raw.length)},body:Readable.from([raw],{objectMode:false})}};
 })};
 f.input={env:f.env,scope:{route:f.scope.route,phase:f.scope.phase,checkpoint:f.scope.checkpoint},sourceReceipt:f.receipt,host:f.host};f.seams={now:()=>Date.now()+f.offset,artifactClient:f.artifactClient,requestHandler:f.handler,sleep:vi.fn(async ms=>{f.offset+=ms;})};
 f.bundle=async()=>f.save('bundle.json',{kind:'image-security-nonroot-deployment-bundle',phase:'deployment',source:f.source,parameter:f.parameter,proof:{synthetic:'proof'},phaseReceipt:{phase:f.scope.phase,sourceReceiptHash:ref.sha256,observedMs:Date.now(),expiresMs:NOW+120000}});
 f.readRequired=async a=>{const t=createNonrootBudgetedReads({region:f.config.region,env:f.env,metadataReads:a,requestHandler:f.handler});try{await t.clients.sts.send(new GetCallerIdentityCommand({}));await t.clients.ssm.send(new GetParametersCommand({Names:[parameterName],WithDecryption:true}));}finally{t.close();}};
 return f;
}
it('uses one original artifact claim, one conditional request Put and an authenticated funded response before metered reads',async()=>{
 const f=await setup(),a=await openFutureCiSmokeAcquisition(f.input,f.seams);expect(f.events).toEqual(['artifact','put','get']);expect(f.request).toEqual({version:1,kind:'ci-prepaid-acquisition-request',bindingHash:hash(f.binding),scope:f.scope,nonce:f.artifactPayload.nonce,artifactId:123,artifactDigest:'e'.repeat(64),sourceReceiptHash:f.env.MEM9_CI_SMOKE_SOURCE_RECEIPT_HASH});
 await f.readRequired(a);a.reserveLocal({...zero(),logicalBytes:100});const bundleRef=await f.bundle(),done=await a.finish({bundleRef});expect(done.authority).toBe(false);expect(JSON.parse(await readFile(done.receiptRef.path))).toMatchObject({kind:'ci-future-acquisition-complete',ownerRefund:0});
});
it('CFG2 public entry uses the actual default SDK path; normal V1/preview dispatch is separate',async()=>{
 const f=await setup();for(const [k,v]of Object.entries({ACTIONS_RUNTIME_TOKEN:'synthetic-runtime-token',ACTIONS_RESULTS_URL:'https://results-receiver.actions.githubusercontent.com'})){f.env[k]=v;vi.stubEnv(k,v);}
 vi.spyOn(DefaultArtifactClient.prototype,'uploadArtifact').mockImplementation(f.artifactClient.uploadArtifact);vi.spyOn(NodeHttpHandler.prototype,'handle').mockImplementation(f.handler.handle);
 const a=await openCiSmokeAcquisition(f.input);expect(f.events).toEqual(['artifact','put','get']);await f.readRequired(a);await a.finish({bundleRef:await f.bundle()});
});
it('completed CFG2 acquisition replays only unused local budget without AWS or another startup capability',async()=>{
 const f=await setup(),a=await openFutureCiSmokeAcquisition(f.input,f.seams);await f.readRequired(a);a.reserveLocal({...zero(),logicalBytes:100});const bundleRef=await f.bundle(),done=await a.finish({bundleRef}),calls=f.http.length;
 const input={env:f.env,completionRef:done.receiptRef,bundleRef,knownParameter:f.parameter},local=await openCiSmokeDeploymentLocalReplay(input);expect(local.beforeRead).toBeUndefined();expect(local.reserveLocal({...zero(),logicalBytes:200}).logicalBytes).toBe(300);await local.finish();expect(f.http.length).toBe(calls);await expect(openCiSmokeDeploymentLocalReplay(input)).rejects.toThrow();
});
it.each(['config','source-hash','scope','manual','account'])('rejects %s before the startup claim or AWS',async fault=>{
 const f=await setup();if(fault==='config')f.env.MEM9_CI_ACQUISITION_CONFIG='{}';if(fault==='source-hash')f.env.MEM9_CI_SMOKE_SOURCE_RECEIPT_HASH='0'.repeat(64);
 if(fault==='scope')f.input.scope.phase='preupdate';if(fault==='manual')f.env.GITHUB_EVENT_NAME='workflow_dispatch';if(fault==='account')f.env.AWS_REGION='us-west-2';
 await expect(openFutureCiSmokeAcquisition(f.input,f.seams)).rejects.toThrow();expect(f.http).toEqual([]);expect(f.artifactClient.uploadArtifact).not.toHaveBeenCalled();
});
it.each([403,409,412,500])('holds an ambiguous/conflicting Put %s without any retry or allowance GET',async statusCode=>{
 const f=await setup();f.handler.handle=vi.fn(async()=>({response:{statusCode,headers:{'content-type':'application/xml'},body:Readable.from([Buffer.from('<Error><Code>Conflict</Code></Error>')])}}));
 await expect(openFutureCiSmokeAcquisition(f.input,f.seams)).rejects.toThrow();expect(f.handler.handle).toHaveBeenCalledTimes(1);expect(f.handler.destroy).toHaveBeenCalled();
 await expect(openFutureCiSmokeAcquisition(f.input,f.seams)).rejects.toThrow('CiStartupAlreadyAttempted');expect(f.handler.handle).toHaveBeenCalledTimes(1);
});
it('polls only twelve known 404s and never renews the funding deadline',async()=>{
 const f=await setup(),base=f.handler.handle;f.handler.handle=vi.fn(async request=>request.method==='PUT'?base(request):({response:{statusCode:404,headers:{'content-type':'application/xml'},body:Readable.from([Buffer.from('<Error><Code>NoSuchKey</Code></Error>')])}}));
 await expect(openFutureCiSmokeAcquisition(f.input,f.seams)).rejects.toThrow('CiFutureAllowancePending');expect(f.handler.handle).toHaveBeenCalledTimes(13);expect(f.seams.sleep).toHaveBeenCalledTimes(11);expect(f.offset).toBe(55000);
});
it.each(['nonce','run','request','grant','oversized'])('rejects an owner response with changed %s',async fault=>{
 const f=await setup(),get=f.response;f.response=()=>{const value=structuredClone(get());if(fault==='nonce')value.nonce='0'.repeat(64);if(fault==='run')value.runBinding.source.runId++;
  if(fault==='request')value.requestHash='0'.repeat(64);if(fault==='grant')value.grantSet.debit.checkpoint.counters.httpBodyBytes=0;if(fault==='oversized')value.unexpected='x'.repeat(1048576);return value;};
 await expect(openFutureCiSmokeAcquisition(f.input,f.seams)).rejects.toThrow();expect(f.events).toEqual(['artifact','put','get']);expect(f.handler.destroy).toHaveBeenCalled();
});
it('checks expiry synchronously at actual metered dispatch and seals without refund',async()=>{
 const f=await setup(),a=await openFutureCiSmokeAcquisition(f.input,f.seams),r=await a.beforeRead('GetCallerIdentity',{}),count=f.http.length;
 f.offset=400000;expect(()=>r.finalGuard()).toThrow();await r.unknown();expect(f.http.length).toBe(count);await expect(a.finish({bundleRef:await f.bundle()})).rejects.toThrow();
});
it('requires identity then the exact protected descriptor before any other read or local work',async()=>{
 const f=await setup(),a=await openFutureCiSmokeAcquisition(f.input,f.seams);expect(()=>a.reserveLocal(zero())).toThrow('CiFutureDescriptorFirst');await expect(a.beforeRead('GetCallerIdentity',{})).rejects.toThrow();
 const g=await setup(),b=await openFutureCiSmokeAcquisition(g.input,g.seams);await expect(b.beforeRead('GetParameters',{Names:[parameterName],WithDecryption:true})).rejects.toThrow('CiFutureIdentityFirst');
});
it('resolves tasks and definitions only from completed scoped service responses',async()=>{
 const cluster='mem9-on-aws-prod',task=`arn:aws:ecs:${region}:${account}:task/${cluster}/a`,definition=`arn:aws:ecs:${region}:${account}:task-definition/mem9-on-aws-prod:1`;
 const profiles=[profile('tasks','ListTasks',{cluster,serviceName:'service',desiredStatus:'RUNNING',maxResults:2}),profile('describe','DescribeTasks',{cluster,include:['TAGS']},{kind:'CURRENT_TASKS_FROM_SCOPED_LIST',late:{field:'tasks',fromProfile:'tasks',maxItems:2}}),profile('definition','DescribeTaskDefinition',{include:['TAGS']},{kind:'DEFINITION_FROM_VALIDATED_TASK_OR_SERVICE',late:{field:'taskDefinition',fromProfile:'describe',source:'task'}})];
 const f=await setup({profiles}),base=f.handler.handle;f.handler.handle=vi.fn(async request=>{
  const action=request.headers['x-amz-target']?.split('.').at(-1);if(!['ListTasks','DescribeTasks','DescribeTaskDefinition'].includes(action))return base(request);
  const value=action==='ListTasks'?{taskArns:[task]}:action==='DescribeTasks'?{tasks:[{taskArn:task,clusterArn:`arn:aws:ecs:${region}:${account}:cluster/${cluster}`,taskDefinitionArn:definition}],failures:[]}:{taskDefinition:{taskDefinitionArn:definition}};
  const raw=Buffer.from(JSON.stringify(value));return {response:{statusCode:200,headers:{'content-type':'application/x-amz-json-1.1','content-length':String(raw.length)},body:Readable.from([raw])}};
 });
 const a=await openFutureCiSmokeAcquisition(f.input,f.seams),t=createNonrootBudgetedReads({region,env:f.env,metadataReads:a,requestHandler:f.handler});
 try{await t.clients.sts.send(new GetCallerIdentityCommand({}));await t.clients.ssm.send(new GetParametersCommand({Names:[parameterName],WithDecryption:true}));
  await t.clients.ecs.send(new ListTasksCommand(profiles[0].request));await t.clients.ecs.send(new DescribeTasksCommand({cluster,tasks:[task],include:['TAGS']}));await t.clients.ecs.send(new DescribeTaskDefinitionCommand({taskDefinition:definition,include:['TAGS']}));
  const done=await a.finish({bundleRef:await f.bundle()});expect(JSON.parse(await readFile(done.receiptRef.path)).reads).toHaveLength(5);
 }finally{t.close();}
});
it('rejects caller-invented dynamic task IDs without a completed list',async()=>{
 const cluster='mem9-on-aws-prod',f=await setup({profiles:[profile('tasks','ListTasks',{cluster,serviceName:'service',desiredStatus:'RUNNING',maxResults:2}),profile('describe','DescribeTasks',{cluster},{kind:'CURRENT_TASKS_FROM_SCOPED_LIST',late:{field:'tasks',fromProfile:'tasks',maxItems:2}})]}),a=await openFutureCiSmokeAcquisition(f.input,f.seams);await f.readRequired(a);
 await expect(a.beforeRead('DescribeTasks',{cluster,tasks:[`arn:aws:ecs:${region}:${account}:task/${cluster}/invented`]})).rejects.toThrow('CiFutureProfileRequest');
});
it('S3BlobGet completes only exact digest/size metadata and never records a URL',async()=>{
 const raw=Buffer.from('synthetic blob'),layerDigest='sha256:'+sha(raw),repositoryName='mem9-on-aws/bootstrap',f=await setup({profiles:[profile('blob','S3BlobGet',{repositoryName,layerDigest},{requestBytes:0,responseBytes:raw.length})]}),a=await openFutureCiSmokeAcquisition(f.input,f.seams);await f.readRequired(a);
 const r=await a.beforeRead('S3BlobGet',{repositoryName,layerDigest});r.finalGuard();r.charge(raw.length);await r.complete({repositoryName,layerDigest,size:raw.length},sha(raw));const done=await a.finish({bundleRef:await f.bundle()}),record=JSON.parse(await readFile(done.receiptRef.path));
 const last=JSON.parse(await readFile(record.reads.at(-1).resultRef.path));expect(last.value).toEqual({repositoryName,layerDigest,size:raw.length});expect(JSON.stringify(last)).not.toContain('https:');
});
it.each(['used','omitted-read','extra-intent','journal','source','bundle'])('local replay rejects tampered %s without AWS',async fault=>{
 const f=await setup(),a=await openFutureCiSmokeAcquisition(f.input,f.seams);await f.readRequired(a);a.reserveLocal({...zero(),logicalBytes:100});const bundleRef=await f.bundle(),done=await a.finish({bundleRef}),record=JSON.parse(await readFile(done.receiptRef.path)),count=f.http.length;
 if(fault==='used')record.localUsed.logicalBytes=0;if(fault==='omitted-read')record.reads.pop();if(fault==='extra-intent')await writeFile(record.claimRef.path.replace('-claim.json','-read-999.json'),'{}',{mode:0o600});
 if(fault==='journal')await writeFile(record.localRef.path,'',{mode:0o600});if(fault==='source')await writeFile(f.env.MEM9_CI_SMOKE_SOURCE_RECEIPT,'{}',{mode:0o600});if(fault==='bundle')await writeFile(bundleRef.path,'{}',{mode:0o600});
 await writeFile(done.receiptRef.path,JSON.stringify(record),{mode:0o600});done.receiptRef.sha256=sha(JSON.stringify(record));
 await expect(openCiSmokeDeploymentLocalReplay({env:f.env,completionRef:done.receiptRef,bundleRef,knownParameter:f.parameter})).rejects.toThrow();expect(f.http.length).toBe(count);
});
it('R6 TARGET 403 then 200 keeps actual status receipts and verifies full funded content',async()=>{
 const f=await setup(),base=f.handler.handle;let gets=0;f.handler.handle=vi.fn(async request=>request.method==='GET'&&++gets===1?{response:{statusCode:403,headers:{'content-type':'application/xml'},body:Readable.from([Buffer.from('<Error><Code>NotAnAbsenceAssertion</Code></Error>')])}}:base(request));
 const a=await openFutureCiSmokeAcquisition(f.input,f.seams);await f.readRequired(a);const done=await a.finish({bundleRef:await f.bundle()}),record=JSON.parse(await readFile(done.receiptRef.path));
 expect(gets).toBe(2);expect(f.seams.sleep).toHaveBeenCalledExactlyOnceWith(5000);expect(await Promise.all(record.handshakeRefs.map(async r=>JSON.parse(await readFile(r.result.path)).status))).toEqual([200,403,200]);
});
it('R6 TARGET permanent fully received 403 stops after twelve GETs',async()=>{
 const f=await setup(),base=f.handler.handle;f.handler.handle=vi.fn(async request=>request.method==='PUT'?base(request):{response:{statusCode:403,headers:{'content-type':'application/xml'},body:Readable.from([Buffer.from('<Error><Code>AccessDenied</Code></Error>')])}});
 await expect(openFutureCiSmokeAcquisition(f.input,f.seams)).rejects.toThrow('CiFutureAllowancePending');expect(f.handler.handle).toHaveBeenCalledTimes(13);expect(f.seams.sleep).toHaveBeenCalledTimes(11);
});
it.each(['overflow','incomplete','deadline'])('R6 TARGET 403 %s is terminal',async fault=>{
 const f=await setup(),base=f.handler.handle;f.handler.handle=vi.fn(async request=>{
  if(request.method==='PUT')return base(request);if(fault==='deadline')f.offset=400000;
  return {response:{statusCode:403,headers:{'content-type':'application/xml',...(fault==='incomplete'?{'content-length':'999'}:{})},body:Readable.from([fault==='overflow'?Buffer.alloc(16385):Buffer.from('<Error><Code>AccessDenied</Code></Error>')])}};
 });
 await expect(openFutureCiSmokeAcquisition(f.input,f.seams)).rejects.toThrow();expect(f.handler.handle).toHaveBeenCalledTimes(2);expect(f.seams.sleep).not.toHaveBeenCalled();
});

async function attestedControlFixture(scope,bodies,archiveBytes){
 const directories=new Set();
 for(const path of bodies.keys()){const parts=path.slice(1).split('/');parts.pop();while(parts.length){directories.add(parts.join('/'));parts.pop();}}
 const entries=[...[...directories].sort().map(path=>({path,type:'5',mode:0o755})),...[...bodies].map(([path,body])=>({path:path.slice(1),body,mode:['/usr/local/bin/node','/bin/busybox'].includes(path)?0o755:0o644})),{path:'bin/setpriv',type:'2',link:'busybox',mode:0o777}];
 const layerBytes=tar(entries);let offset=0;
 for(const entry of entries){const header=layerBytes.subarray(offset,offset+512);header.write(entry.mode.toString(8).padStart(7,'0')+'\0',100);header.fill(32,148,156);let checksum=0;for(const byte of header)checksum+=byte;header.write(checksum.toString(8).padStart(6,'0')+'\0 ',148);offset+=512+Math.ceil(Buffer.byteLength(entry.body??'')/512)*512;}
 const blobs=new Map(),cache=new Map();
 const put=(value,mediaType)=>{const raw=Buffer.isBuffer(value)?value:Buffer.from(JSON.stringify(value)),digest='sha256:'+createHash('sha256').update(raw).digest('hex');blobs.set(digest,raw);return {mediaType,digest,size:raw.length};};
 const layer=put(layerBytes,IMAGE_MEDIA.tar),config=put({architecture:'arm64',os:'linux',rootfs:{type:'layers',diff_ids:[layer.digest]},config:{Env:[]}},IMAGE_MEDIA.config);
 const child=put({schemaVersion:2,mediaType:IMAGE_MEDIA.manifest,config,layers:[layer]},IMAGE_MEDIA.manifest);
 const empty=put({},IMAGE_MEDIA.config),payload=put({_type:'https://in-toto.io/Statement/v0.1',subject:[{name:'bootstrap',digest:{sha256:child.digest.slice(7)}}],predicateType:'https://slsa.dev/provenance/v0.2',predicate:{complete:true}},IMAGE_MEDIA.attestation);
 const attestation=put({schemaVersion:2,mediaType:IMAGE_MEDIA.manifest,config:empty,layers:[payload]},IMAGE_MEDIA.manifest),root=put({schemaVersion:2,mediaType:IMAGE_MEDIA.index,manifests:[{...child,platform:{os:'linux',architecture:'arm64'}},{...attestation,platform:{os:'unknown',architecture:'unknown'},annotations:{'vnd.docker.reference.type':'attestation-manifest','vnd.docker.reference.digest':child.digest}}]},IMAGE_MEDIA.index);
 const source={async manifest(_repository,descriptor){return blobs.get(descriptor.digest);},async *blob(_repository,descriptor){yield blobs.get(descriptor.digest);}};
 const store={async put(descriptor,stream){const chunks=[];for await(const chunk of stream)chunks.push(chunk);cache.set(descriptor.digest,Buffer.concat(chunks));},async *open(descriptor){yield cache.get(descriptor.digest);}};
 const graph=await readControlImageGraph({...scope,root,arm64Digest:child.digest,configDigest:config.digest},{source,store,budget:createImageBudget({credentialExpiresMs:Date.now()+3600000})});
 const filesystem=await inspectImageFilesystem(graph,{component:'bootstrap'}),{graphHash,...image}=controlImageGraphBinding(graph);
 const refs=Object.fromEntries([['rootManifest',root],['arm64Manifest',child],['config',config]].map(([name,descriptor])=>[name,archiveBytes(blobs.get(descriptor.digest),'image-graph')]));
 return {graph,filesystem,image,refs,blobs,root,child,attestation,empty,payload,layer,config};
}

async function realControlSetup({capacity=false}={}){
 const w=await nonrootDeploymentWrapperFixture({controlArtifactFactory:({scope,bodies,archiveBytes})=>attestedControlFixture(scope,bodies,archiveBytes)}),tick=w.f.now;
 vi.spyOn(Date,'now').mockReturnValue(tick);
 const repositoryName='mem9-on-aws/bootstrap',late=(id,action,artifact,field,count=1)=>profile(id,action,action==='GetObject'?{Bucket:'example-ci-reader',ExpectedBucketOwner:account}:{...(action==='S3BlobGet'?{}:{registryId:account}),repositoryName},{kind:'CONTROL_ARTIFACT_FROM_AUTHENTICATED_BUILD',late:{field,buildContractKey:'deployed-bootstrap',artifact},ecr:!['GetObject','S3BlobGet'].includes(action),responseBytes:1048576,count});
 const profiles=[late('capsule','GetObject','private-capsule','Key'),late('root','BatchGetImage','root','imageIds'),late('arm','BatchGetImage','arm64','imageIds'),late('manifests','BatchGetImage','manifest','imageIds',2),late('configs','S3BlobGet','config','layerDigest',2),late('layers','S3BlobGet','layer','layerDigest',2)];
 const f=await setup({profiles});
 if(capacity){
  f.controlCapacity=true;f.config.version=3;f.config.budgetRevision={version:2,limitsHash:NONROOT_REMAINING_WORK_LIMITS_HASH_V2,envelopeHash:hash('synthetic-capacity-envelope'),historyHeadHash:hash('synthetic-capacity-history')};f.config.compiledCeiling=NONROOT_REMAINING_WORK_CAPS_V2;
  const phases=[[9,'preupdate'],[17,'preconfigure'],[19,'presst'],[21,'preupdate'],[23,'prereadiness']];
  f.config.startup.consumers=phases.map(([n,phase])=>({...f.scope,phase,checkpoint:'deploy-prod/'+n}));f.config.bootstrap=f.config.startup.consumers.map(s=>({checkpoint:s.checkpoint,responseBytes:1048576}));
  Object.assign(f.scope,{phase:'preconfigure',checkpoint:'deploy-prod/17'});Object.assign(f.input.scope,{phase:f.scope.phase,checkpoint:f.scope.checkpoint});
  const p=(id,action,artifact,field,count,responseBytes)=>({...late(id,action,artifact,field,count),requestBytes:action==='S3BlobGet'?0:16384,responseBytes});
  f.profiles=[...f.profiles.slice(0,2),late('capsule','GetObject','private-capsule','Key'),p('root','BatchGetImage','root','imageIds',1,8388608),p('manifests','BatchGetImage','manifest','imageIds',2,8388608),p('config-urls','GetDownloadUrlForLayer','config','layerDigest',2,16384),p('layer-urls','GetDownloadUrlForLayer','layer','layerDigest',64,16384),p('configs','S3BlobGet','config','layerDigest',2,FUTURE_CONTROL_CAPACITY.graphBytes),p('layers','S3BlobGet','layer','layerDigest',64,FUTURE_CONTROL_CAPACITY.graphBytes),p('scan','DescribeImageScanFindings','arm64','imageId',1,8388608)];
  f.localBudget={...zero(),logicalBytes:3*1024**3,uncompressedBytes:4*1024**3,processedEntries:100000};
 }
 f.tick=tick;f.source=w.d.source;f.parameter=w.parameter;
 f.config.target={kind:'production-data-release',descriptor:w.current,parameterVersion:w.parameter.Version};f.config.account=w.current.account;f.config.region=w.current.region;f.config.ownerRoot={runtimeNonce:w.current.runtimeNonce,authorizationId:w.current.authorizationId};f.config.storage.kmsKeyArn=`arn:aws:kms:${w.current.region}:${w.current.account}:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee`;f.env.AWS_REGION=w.current.region;for(const p of f.profiles){if(p.request.registryId)p.request.registryId=w.current.account;if(p.request.ExpectedBucketOwner)p.request.ExpectedBucketOwner=w.current.account;}
 f.config.startup.source={repository:w.d.source.repository,prNumber:w.d.main.prNumber,candidateRevision:w.d.main.candidateRevision,candidateTree:w.d.main.candidateTree,baseRevision:w.d.main.baseRevision};
 Object.assign(f.config.startup,{descriptorHash:hash(w.current),proofHash:w.built.proofHash,notAfter:Math.min(w.current.expiresMs,tick+240000)});
 f.funding=fundedGrant(f);Object.assign(f.config.startup,f.funding.expected);f.binding=makeCiStartupRunBinding(f.config.startup,f.source);
 Object.assign(f.env,{GITHUB_REPOSITORY:f.source.repository,GITHUB_SHA:f.source.checkout.sha,GITHUB_WORKFLOW_SHA:f.source.run.workflowSha,GITHUB_RUN_ID:String(f.source.run.id),GITHUB_RUN_ATTEMPT:String(f.source.run.attempt),MEM9_CI_ACQUISITION_CONFIG:JSON.stringify(f.config)});
 f.receipt={...f.receipt,current:{repository:f.source.repository,runId:f.source.run.id,runAttempt:f.source.run.attempt,job:'deploy-prod',revision:f.source.checkout.sha},checkout:{revision:f.source.checkout.sha,tree:f.source.checkout.tree},observedMs:tick,expiresMs:f.config.startup.notAfter};
 const sourceRef=await f.save('mem9-ci-smoke-source/receipt.json',f.receipt);f.env.MEM9_CI_SMOKE_SOURCE_RECEIPT_HASH=sourceRef.sha256;f.input.sourceReceipt=f.receipt;
 const started=tick-10000,ended=tick-5000,run={...w.d.rawRun,status:'in_progress',head_repository:{full_name:f.source.repository}};
 const job={...w.d.rawJob,status:'in_progress',conclusion:null,started_at:new Date(started).toISOString(),completed_at:null,steps:[{name:w.d.job.steps[0].name,status:'completed',conclusion:'success',started_at:new Date(started+1000).toISOString(),completed_at:new Date(ended).toISOString()}]};
 const records={proof:w.built.proof,proofArchive:w.f.evidence.archive},capture=await captureNonrootControlBuildAction({contract:w.d.contract,source:f.source,run,job,metadata:JSON.stringify({'containerimage.digest':w.d.build.image.rootDigest,'containerimage.config.digest':w.d.build.image.configDigest}),outputDigest:w.d.build.image.rootDigest,observedMs:tick-4000},{...nonrootArchiveResolvers(records.proofArchive),expected:{sourceContext:w.d.sourceContext}});
 const buildLog=Buffer.from(`#7 exporting manifest list ${capture.outputDigest}\n#7 exporting config ${w.d.build.image.configDigest}\n#7 DONE 1.0s\n`),completedJob={...job,status:'completed',conclusion:'success',completed_at:new Date(tick-3000).toISOString()},completion=completeNonrootControlBuildAction(capture,{contract:w.d.contract,run,job:completedJob,buildLog,now:tick-2000});
 const prepared={version:1,kind:'control-build-prepared',identity:{repository:f.source.repository,revision:f.source.checkout.sha,runId:f.source.run.id,attempt:f.source.run.attempt},bundleHash:hash({synthetic:'source-bundle'}),contractHash:hash(w.d.contract),fingerprint:w.d.checkoutFingerprint,preparedMs:started-1000};
 const encoded=encodeControlBuildCapture({prepared,capture}),build={prepared,capture,commitment:encoded.commitment,contract:w.d.contract,completion,buildLog,sourceContext:w.d.sourceContext};
 f.host.checkout=async()=>f.receipt.checkout;f.host.run=async(_file,args)=>{if(args[0]==='diff')return '';if(args[1]==='HEAD:.github/workflows/infra-ci.yml')return JSON.stringify({jobs:{'build-image-transition-control':w.d.job}});return [f.source.checkout.sha,f.source.checkout.tree,f.source.checkout.parents.join(' ')].join('\n');};
 f.host.api=async path=>{
  if(path==='commits/main'||path==='commits/'+f.source.checkout.sha)return {sha:f.source.checkout.sha,commit:{tree:{sha:f.source.checkout.tree}},parents:f.source.checkout.parents.map(sha=>({sha}))};
  if(path==='pulls/'+f.source.pullRequest.number)return {number:f.source.pullRequest.number,state:'closed',merged:true,head:{sha:f.source.pullRequest.headSha,repo:{full_name:f.source.repository}},base:{ref:'main'},merge_commit_sha:f.source.checkout.sha};
  if(path.includes('/jobs?'))return {total_count:1,jobs:[completedJob]};
  if(path.startsWith('actions/runs/'))return run;
  if(path.startsWith('commits/')&&path.includes('/statuses?'))return ownerStatuses(f);
  if(path==='actions/artifacts/'+f.artifact?.id)return {...f.artifact,created_at:new Date(tick).toISOString(),expires_at:new Date(tick+86400000).toISOString(),workflow_run:{id:f.source.run.id,head_sha:f.source.checkout.sha,head_branch:'main'}};throw Error('UnexpectedGithub');
 };
 f.host.readLog=async()=>`MEM9_CONTROL_BUILD_COMMITMENT ${JSON.stringify(encoded.commitment)}\n`;
 f.response=()=>({version:1,kind:'owner-ci-allowance-response',runBinding:f.binding,scope:f.scope,nonce:f.request.nonce,artifactId:123,requestHash:hash(f.request),grantSet:f.funding.grantSet,expiresMs:f.config.startup.notAfter});
 f.bundle=async()=>f.save('bundle.json',{kind:'image-security-nonroot-deployment-bundle',phase:'deployment',source:f.source,parameter:f.parameter,proof:w.built.proof,deploymentSource:w.deploymentSource,phaseReceipt:{phase:f.scope.phase,sourceReceiptHash:sourceRef.sha256,observedMs:tick,expiresMs:tick+120000}});
 return {f,w,build,records,encoded};
}
it.each(['clean','tamper','root-clean','root-drift','root-put-held','root-other-guard'])('aggregate SDK graph/FS and public replay enforce original admitted caps; mode=%s',async mode=>{
 const tamper=mode==='tamper',prospectiveRoot=mode.startsWith('root-');
 const {f,w,build,records}=await realControlSetup({capacity:true}),v=w.d.controlVerification;let allocation,loaded=false;
 if(prospectiveRoot){f.prospectiveRoot=true;f.funding=fundedGrant(f);Object.assign(f.config.startup,f.funding.expected);f.binding=makeCiStartupRunBinding(f.config.startup,f.source);f.env.MEM9_CI_ACQUISITION_CONFIG=JSON.stringify(f.config);f.env.GH_TOKEN='synthetic-root-reader';}
 const rootBytes=Buffer.from(JSON.stringify(w.phaseEvidence));
 const docker=async args=>{if(args[1]==='rm'){loaded=false;return {status:0,stdout:'Untagged',stderr:''};}return loaded?{status:0,stdout:JSON.stringify([{Id:build.capture.outputDigest,Descriptor:{digest:build.capture.outputDigest},RepoTags:[allocation.tag],Os:'linux',Architecture:'arm64'}]),stderr:''}:{status:1,stdout:'',stderr:'No such image: '+args[2]};};
 const old=f.handler.handle;let blobReads=0,metadataReads=0;
 f.handler.handle=vi.fn(async request=>{
  let value,raw;
  if(prospectiveRoot&&request.path.endsWith('/root-request.json')){
   const files=await readdir(join(f.root,'mem9-ci-future-acquisitions')),journal=files.find(n=>n.endsWith('-local.ndjson'));
   const lines=(await readFile(join(f.root,'mem9-ci-future-acquisitions',journal),'utf8')).trim().split('\n').map(JSON.parse);
   expect(lines.filter(r=>r.logicalBytes===createProspectiveCiRootRequestPolicy(f.scope.checkpoint).localBytes)).toHaveLength(1);
   if(mode==='root-put-held')return {response:{statusCode:503,headers:{'content-length':'2'},body:Readable.from([Buffer.from('{}')],{objectMode:false})}};
   return {response:{statusCode:200,headers:{'content-length':'0','x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':f.config.storage.kmsKeyArn,'x-amz-server-side-encryption-bucket-key-enabled':'true'},body:Readable.from([],{objectMode:false})}};
  }else if(prospectiveRoot&&request.path.endsWith('/root-audit.json'))raw=rootBytes;
  else if(request.hostname.startsWith('api.ecr.')){
   metadataReads++;const q=JSON.parse(request.body);
   if(request.headers['x-amz-target'].endsWith('.BatchGetImage')){const d=v.graph.inventory.nodes.find(d=>d.digest===q.imageIds[0].imageDigest);value=digestAliases({images:[{registryId:f.config.account,repositoryName:q.repositoryName,imageId:q.imageIds[0],imageManifest:v.blobs.get(d.digest).toString(),imageManifestMediaType:d.mediaType}],failures:[]});}
   else if(request.headers['x-amz-target'].endsWith('.GetDownloadUrlForLayer')){
    const date=new Date(Date.now()).toISOString().replace(/[-:]/g,'').replace(/\.\d{3}/,'');
    const params=new URLSearchParams({'X-Amz-Algorithm':'AWS4-HMAC-SHA256','X-Amz-Credential':'ASIASYNTHETIC/'+date.slice(0,8)+'/'+f.config.region+'/s3/aws4_request','X-Amz-Date':date,'X-Amz-Expires':'900','X-Amz-SignedHeaders':'host','X-Amz-Signature':'a'.repeat(64)});
    value={layerDigest:q.layerDigest,downloadUrl:`https://prod-${f.config.region}-starport-layer-bucket.s3.${f.config.region}.amazonaws.com/${q.layerDigest.slice(7)}?${params}`};
   }else throw Error('UnexpectedCapacityEcr');
   raw=Buffer.from(JSON.stringify(value));
  }else if(request.hostname.startsWith('prod-')){blobReads++;raw=v.blobs.get('sha256:'+request.path.slice(1));}
  else return old(request);
  return {response:{statusCode:200,headers:{'content-length':String(raw.length),'content-type':'application/json'},body:Readable.from([raw],{objectMode:false})}};
 });
 const rootGithubRequest=async()=>{const bytes=Buffer.from(JSON.stringify([{...ciRootReadyStatus(f.config,f.scope,sha(rootBytes)),creator:{id:42}}])),body=Readable.from([bytes],{objectMode:false});body.statusCode=200;body.headers={'content-length':String(bytes.length)};return body;};
 const a=await openFutureCiSmokeAcquisition(f.input,{...f.seams,controlResourceDocker:docker,...(prospectiveRoot?{rootGithubRequest}:{})});
 expect(a.controlCapacity).toEqual(FUTURE_CONTROL_CAPACITY);await f.readRequired(a);await a.bindControlBuild({context:w.authorization,records,build});
 allocation=await a.allocateControlResources();
 const transport=createNonrootBudgetedReads({region:f.config.region,env:f.env,metadataReads:a,requestHandler:f.handler});
 const collected=await collectNonrootControlImage({capture:build.capture,contract:build.contract,budgetedReads:transport,metadataReads:transport,tempRoot:allocation.tempRoot,resourceHandle:allocation.handle});
 expect(collected.graph.inventory).toEqual(v.graph.inventory);expect(blobReads).toBe(4);expect(metadataReads).toBe(7);
 const loaderDirectory=await mkdtemp(join(allocation.tempRoot,'mem9-control-docker-'));
 for(const name of ['index.json','oci-layout','image.tar'])await writeFile(join(loaderDirectory,name),name,{mode:0o600});
 await beginControlImageLoad(allocation.handle,{loaderDirectory});loaded=true;await recordControlImageLoad(allocation.handle,{outcome:'loaded',completedMs:Date.now()});
 let bundleRef=await f.bundle();const bundle=JSON.parse(await readFile(bundleRef.path));bundle.controlCache={directory:collected.cacheDirectory,inventory:collected.inventory};bundleRef=await f.save('bundle.json',bundle);
 if(prospectiveRoot){
  const requestRoot=()=>a.requestRootAudit({context:w.authorization,records,parameter:f.parameter,source:f.source,phase:f.scope.phase,deploymentSource:w.deploymentSource,targetObservation:{...w.targetObservation,serviceObservation:w.serviceObservation}});
  if(mode==='root-put-held'){
   await expect(requestRoot()).rejects.toThrow();const calls=f.handler.handle.mock.calls.length;await expect(requestRoot()).rejects.toThrow();expect(f.handler.handle.mock.calls).toHaveLength(calls);
   const directory=join(f.root,'mem9-ci-future-acquisitions'),name=(await readdir(directory)).find(n=>n.endsWith('-root-local-accounting.json')),held=JSON.parse(await readFile(join(directory,name)));
   expect(held.checkpoints.at(-1).held).toBe(true);expect(held.debit.logicalBytes).toBe(createProspectiveCiRootRequestPolicy(f.scope.checkpoint).localBytes);
   await expect(a.finish({bundleRef})).rejects.toThrow();await expect(readFile(held.claimRef.path.replace(/-claim\.json$/,'-complete.json'))).rejects.toMatchObject({code:'ENOENT'});
   await collected.close();transport.close();return;
  }
  const result=await requestRoot();
  expect(result.archiveHash).toBe(sha(rootBytes));
  const {runtimeNonce,authorizationId}=f.config.ownerRoot,Key=`data-authorizations/${runtimeNonce}/${authorizationId}/ci-grants/${f.config.startup.grantSetId}/${hash(f.scope.checkpoint)}/root-audit.json`;
  const response=await transport.clients.s3.send(new GetObjectCommand({Bucket:f.config.storage.bucket,Key,ExpectedBucketOwner:f.config.account}));await response.Body.transformToByteArray();
 }
 const resourceReceiptRef=await a.sealControlResources({bundleRef}),done=await a.finish({bundleRef,resourceReceiptRef});
 if(tamper){
  const completion=JSON.parse(await readFile(done.receiptRef.path));
  const pair=completion.reads[completion.reads.length-1],intent=JSON.parse(await readFile(pair.intentRef.path));
  intent.caps.responseBytes--;const raw=Buffer.from(JSON.stringify(intent));await writeFile(pair.intentRef.path,raw);pair.intentRef.sha256=sha(raw);
  const completeRaw=Buffer.from(JSON.stringify(completion));await writeFile(done.receiptRef.path,completeRaw);
  // Even rehashing the intent and completion cannot change the original
  // native resource binding; rejection occurs before replay can spend LOCAL.
  await expect(openCiSmokeDeploymentLocalReplay({env:f.env,completionRef:{...done.receiptRef,sha256:sha(completeRaw)},bundleRef,knownParameter:f.parameter})).rejects.toThrow('CiControlResourceBinding');
 }else{
  const replay=await openCiSmokeDeploymentLocalReplay({env:f.env,completionRef:done.receiptRef,bundleRef,knownParameter:f.parameter});expect(replay.controlCapacity).toEqual(FUTURE_CONTROL_CAPACITY);
  if(mode==='root-drift'){const completion=JSON.parse(await readFile(done.receiptRef.path)),exchange=JSON.parse(await readFile(completion.rootExchangeRef.path));const requestPath=completion.rootExchangeRef.path.replace(/root-exchange-complete\.json$/,'')+exchange.requestRef.path;const bytes=await readFile(requestPath);bytes[20]^=1;await writeFile(requestPath,bytes);}
  if(prospectiveRoot)for(let i=0;i<100;i++)replay.reserveLocal(zero());
  if(mode==='root-other-guard'){
   const before=f.env.MEM9_CI_ACQUISITION_CONFIG;f.env.MEM9_CI_ACQUISITION_CONFIG='{}';expect(()=>replay.reserveLocal(zero())).toThrow('CiFutureLocalExpired');f.env.MEM9_CI_ACQUISITION_CONFIG=before;
   await expect(replay.finish()).rejects.toThrow('CiFutureLocalClosed');await replay.hold();
  }else if(mode==='root-drift')await expect(replay.finish()).rejects.toThrow();else await replay.finish();
 }
 const receipt=JSON.parse(await readFile(done.receiptRef.path));expect(receipt.reads.length).toBe(prospectiveRoot?14:13);
 const blobResults=await Promise.all(receipt.reads.map(async r=>JSON.parse(await readFile(r.resultRef.path))));expect(blobResults.filter(r=>r.value?.layerDigest&&r.value.size!==undefined).length).toBe(4);
 await collected.close();transport.close();
 if(tamper)await expect(cleanupCiSmokeControlResources({env:f.env},{docker})).rejects.toThrow('CiControlResourceCleanupHeld');
 else {await cleanupCiSmokeControlResources({env:f.env},{docker});expect(loaded).toBe(false);}
},60000);

it.each(['S3BlobGet','GetDownloadUrlForLayer'])('aggregate blocks %s before the full attestation metadata closure',async action=>{
 const {f,w,build,records}=await realControlSetup({capacity:true}),a=await openFutureCiSmokeAcquisition(f.input,f.seams);
 await f.readRequired(a);await a.bindControlBuild({context:w.authorization,records,build});const v=w.d.controlVerification;
 for(const d of [v.root,v.child]){
  const request={registryId:f.config.account,repositoryName:'mem9-on-aws/bootstrap',imageIds:[{imageDigest:d.digest}]};
  const value={images:[{registryId:f.config.account,repositoryName:request.repositoryName,imageId:request.imageIds[0],imageManifest:v.blobs.get(d.digest).toString(),imageManifestMediaType:d.mediaType}],failures:[]};
  const r=await a.beforeRead('BatchGetImage',request);r.finalGuard();r.charge(Buffer.byteLength(JSON.stringify(value)));await r.complete(value,sha(JSON.stringify(value)));
 }
 const before=f.http.length;
 await expect(a.beforeRead(action,{...(action==='GetDownloadUrlForLayer'?{registryId:f.config.account}:{}),repositoryName:'mem9-on-aws/bootstrap',layerDigest:v.config.digest})).rejects.toThrow('CiFutureControlMetadataIncomplete');
 expect(f.http.length).toBe(before);await expect(a.beforeRead('GetCallerIdentity',{})).rejects.toThrow();
},60000);

it.each([false,true])('binds real opaque proof/source/completion and retains owned CONTROL resources through LOCAL replay; aliases=%s',async aliases=>{
 const {f,w,build,records}=await realControlSetup();let allocation,loaded=false;
 const docker=vi.fn(async args=>{if(args[1]==='rm'){loaded=false;return {status:0,stdout:'Untagged',stderr:''};}return loaded?{status:0,stdout:JSON.stringify([{Id:build.capture.outputDigest,Descriptor:{digest:build.capture.outputDigest},RepoTags:[allocation.tag],Os:'linux',Architecture:'arm64'}]),stderr:''}:{status:1,stdout:'',stderr:'No such image: '+args[2]};});
 const a=await openFutureCiSmokeAcquisition(f.input,{...f.seams,controlResourceDocker:docker});await f.readRequired(a);
 const linked=await a.bindControlBuild({context:w.authorization,records,build});expect(linked.rootDigest).toBe(build.capture.outputDigest);
 const v=w.d.controlVerification;
 const completeManifest=async(d,artifact)=>{const request={registryId:f.config.account,repositoryName:'mem9-on-aws/bootstrap',imageIds:[{imageDigest:d.digest}]},r=await a.beforeRead('BatchGetImage',request);r.finalGuard();const value={images:[{registryId:f.config.account,repositoryName:request.repositoryName,imageId:request.imageIds[0],imageManifest:v.blobs.get(d.digest).toString(),imageManifestMediaType:d.mediaType}],failures:[]},response=aliases?digestAliases(value):value;r.charge(Buffer.byteLength(JSON.stringify(response)));await r.complete(response,sha(JSON.stringify(response)));};
 await completeManifest(v.root,'root');await completeManifest(v.child,'arm64');await completeManifest(v.attestation,'manifest');
 for(const d of [v.config,v.empty,v.layer,v.payload]){const request={repositoryName:'mem9-on-aws/bootstrap',layerDigest:d.digest},r=await a.beforeRead('S3BlobGet',request);r.finalGuard();r.charge(d.size);await r.complete({...request,size:d.size},d.digest.slice(7));}
 allocation=await a.allocateControlResources();const download=await mkdtemp(join(allocation.tempRoot,'mem9-control-download-')),cacheDirectory=join(download,'blobs');await mkdir(cacheDirectory,{mode:0o700});
 for(const d of v.graph.inventory.nodes)await writeFile(join(cacheDirectory,d.digest.slice(7)),v.blobs.get(d.digest),{mode:0o600});
 await registerControlCache(allocation.handle,{graph:v.graph,cacheDirectory,startedMs:Date.now(),completedMs:Date.now()});const loaderDirectory=await mkdtemp(join(allocation.tempRoot,'mem9-control-docker-'));
 for(const name of ['index.json','oci-layout','image.tar'])await writeFile(join(loaderDirectory,name),name,{mode:0o600});await beginControlImageLoad(allocation.handle,{loaderDirectory});loaded=true;await recordControlImageLoad(allocation.handle,{outcome:'loaded',completedMs:Date.now()});
 let bundleRef=await f.bundle();const b=JSON.parse(await readFile(bundleRef.path));b.controlCache={directory:cacheDirectory,inventory:v.graph.inventory};bundleRef=await f.save('bundle.json',b);
 const resourceReceiptRef=await a.sealControlResources({bundleRef}),done=await a.finish({bundleRef,resourceReceiptRef}),local=await openCiSmokeDeploymentLocalReplay({env:f.env,completionRef:done.receiptRef,bundleRef,knownParameter:f.parameter});await local.finish();
 const receipt=JSON.parse(await readFile(done.receiptRef.path));expect(receipt.version).toBe(2);expect(receipt.resourceReceiptRef).toEqual(resourceReceiptRef);expect(receipt.controlBuildRef).not.toBeNull();expect(receipt.reads).toHaveLength(9);expect(loaded).toBe(true);expect((await readdir(cacheDirectory)).length).toBe(v.graph.inventory.nodes.length);
 await cleanupCiSmokeControlResources({env:f.env},{docker});expect(loaded).toBe(false);
},60000);
it('never accepts a JSON success flag as a CONTROL proof context',async()=>{
 const {f,build,records}=await realControlSetup(),a=await openFutureCiSmokeAcquisition(f.input,f.seams);await f.readRequired(a);
 await expect(a.bindControlBuild({context:{valid:true},records,build})).rejects.toThrow();await expect(a.beforeRead('BatchGetImage',{registryId:account,repositoryName:'mem9-on-aws/bootstrap',imageIds:[{imageDigest:build.capture.outputDigest}]})).rejects.toThrow();
},60000);
it.each(['top','image','id'])('TARGET rejects alias %s before projection/descendant binding',async defect=>{
 const {f,w,build,records}=await realControlSetup(),a=await openFutureCiSmokeAcquisition(f.input,f.seams);await f.readRequired(a);await a.bindControlBuild({context:w.authorization,records,build});
 const d=w.d.controlVerification.root,q={registryId:f.config.account,repositoryName:'mem9-on-aws/bootstrap',imageIds:[{imageDigest:d.digest}]},slot=await a.beforeRead('BatchGetImage',q);slot.finalGuard();
 const response=digestAliases({images:[{registryId:q.registryId,repositoryName:q.repositoryName,imageId:q.imageIds[0],imageManifest:w.d.controlVerification.blobs.get(d.digest).toString(),imageManifestMediaType:d.mediaType}],failures:[]},defect);
 slot.charge(Buffer.byteLength(JSON.stringify(response)));await expect(slot.complete(response,sha(JSON.stringify(response)))).rejects.toThrow();
 await expect(a.beforeRead('BatchGetImage',q)).rejects.toThrow();
},60000);
it.each([false,true])('scan findings are returned intact; a nextToken holds the slot (pagination=%s)',async paginated=>{
 const imageDigest='sha256:'+'a'.repeat(64),request={registryId:account,repositoryName:'mem9-on-aws/bootstrap',imageId:{imageDigest}},f=await setup({profiles:[profile('scan','DescribeImageScanFindings',request,{ecr:true})]}),base=f.handler.handle;
 const result={registryId:account,repositoryName:request.repositoryName,imageId:{imageDigest},imageScanStatus:{status:'COMPLETE'},imageScanFindings:{findings:[{name:'synthetic-finding',severity:'HIGH'}]},...(paginated?{nextToken:'synthetic-next-page'}:{})};
 f.handler.handle=vi.fn(async r=>{if(!r.headers['x-amz-target']?.endsWith('.DescribeImageScanFindings'))return base(r);const raw=Buffer.from(JSON.stringify(result));return {response:{statusCode:200,headers:{'content-type':'application/x-amz-json-1.1','content-length':String(raw.length)},body:Readable.from([raw])}};});
 const a=await openFutureCiSmokeAcquisition(f.input,f.seams);await f.readRequired(a);const transport=createNonrootBudgetedReads({region,env:f.env,metadataReads:a,requestHandler:f.handler});
 try{if(paginated){await expect(transport.readJson('ecr','DescribeImageScanFindings',request)).rejects.toThrow();await expect(a.finish({bundleRef:await f.bundle()})).rejects.toThrow();}
  else{expect((await transport.readJson('ecr','DescribeImageScanFindings',request)).imageScanFindings.findings).toEqual(result.imageScanFindings.findings);await a.finish({bundleRef:await f.bundle()});}
 }finally{transport.close();}
});

it('duplicate artifact-name uploads both succeed, but only the selected TARGET process may reach AWS',async()=>{
 const f=await setup(),name='mem9-start-'+hash({grantSetId:f.config.startup.grantSetId,checkpoint:f.scope.checkpoint}),seed=join(f.root,'other-process.json');
 await writeFile(seed,JSON.stringify({nonce:'a'.repeat(64),scopeHash:hash({bindingHash:hash(f.binding),scope:f.scope})}),{mode:0o600});
 const first=await f.artifactClient.uploadArtifact(name,[seed]);
 await expect(openFutureCiSmokeAcquisition(f.input,f.seams)).rejects.toThrow();
 expect(first.id).toBe(123);expect(f.artifact.id).toBe(124);expect(f.artifact.digest).not.toBe('sha256:'+first.digest);expect(f.artifact.name).toBe(name);expect(f.http).toEqual([]);
});
