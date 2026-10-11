import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,open,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {execFileSync} from 'node:child_process';
import {Readable} from 'node:stream';
import {GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import {GetParametersCommand} from '@aws-sdk/client-ssm';
import {GetObjectCommand} from '@aws-sdk/client-s3';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {zero,sha} from './lib/ci-smoke-acquisition-format.mjs';
import {NONROOT_REMAINING_WORK_LIMITS_HASH_V2,NONROOT_REMAINING_WORK_CAPS_V2} from './lib/production-nonroot-budget-revision.mjs';
import {FUTURE_CONTROL_CAPACITY} from './lib/production-control-capacity.mjs';
import {createProspectiveCiRootRequestPolicy} from './lib/ci-smoke-root-request-cost.mjs';
import {ciRootReadyStatus} from './lib/ci-smoke-root-request.mjs';
import {createFutureOwnerDeliveryTemplate} from './lib/ci-smoke-owner-delivery.mjs';
import {createFutureFundingPlan,inspectFutureFundingPlan,FUTURE_OWNER_PUBLICATION} from './lib/ci-smoke-grants.mjs';
import {makeCiStartupRunBinding,ciStartupCheckpointSelection} from './lib/ci-smoke-startup.mjs';
import {openFutureCiSmokeAcquisition} from './lib/ci-smoke-future-acquisition.mjs';
import {createNonrootBudgetedReads} from './lib/production-nonroot-budget-transport.mjs';
import {captureNonrootControlBuildAction,completeNonrootControlBuildAction} from './lib/production-nonroot-control-build.mjs';
import {encodeControlBuildCapture} from './lib/production-control-capture-archive.mjs';
import {nonrootArchiveResolvers} from './lib/production-nonroot-archive.mjs';
import {imageGraphState} from './lib/production-image-graph.mjs';
import {controlSourcePaths,readControlSourceFile} from './lib/production-control-source.mjs';
import {registerControlCache,beginControlImageLoad,recordControlImageLoad,cleanupCiSmokeControlResources} from './lib/ci-smoke-control-resources.mjs';
import {bindNonrootDeploymentContext} from './lib/production-nonroot-proof.mjs';
import {createNonrootDeploymentBundle} from './lib/production-image-deployment-bundle.mjs';

const profile=(id,action,request,extra={})=>({version:1,id,kind:'EXACT',action,request,requestBytes:4096,responseBytes:16384,count:1,ecr:false,...extra});

/** Raw service fixtures plus the existing native funding/acquisition producers.
 * The caller supplies real proof/graph/runtime handles. No restore, replay,
 * validator, or completion result is replaced by this helper. */
export async function prospectiveDeploymentReplayFixture({wrapper:w,records,evidence,phase}){
 assert(['preconfigure','presst'].includes(phase));
 const root=await mkdtemp(join(tmpdir(),'nonroot-root-replay-')),repo=join(root,'repo'),tick=w.f.now,data=w.current,source=w.d.source;
 let acquisition,transport,allocation,env,loaded=false;
 const httpCalls=[],events=[],scope={kind:'target',jobKey:'deploy-prod',route:'deploy-prod',phase,checkpoint:phase==='presst'?'deploy-prod/19':'deploy-prod/17'};
 const resourceDocker=async args=>{
  if(args[1]==='rm'){loaded=false;return {status:0,stdout:'Untagged',stderr:''};}
  return loaded?{status:0,stdout:JSON.stringify([{Id:w.d.build.image.rootDigest,Descriptor:{digest:w.d.build.image.rootDigest},RepoTags:[allocation.tag],Os:'linux',Architecture:'arm64'}]),stderr:''}:{status:1,stdout:'',stderr:'No such image: '+args[2]};
 };
 const close=async()=>{transport?.close();try{if(allocation)await cleanupCiSmokeControlResources({env},{docker:resourceDocker});}finally{await rm(root,{recursive:true,force:true});}};
 const save=async(name,value)=>{const path=join(root,name),raw=Buffer.from(JSON.stringify(value));await writeFile(path,raw,{mode:0o600});return {path,sha256:sha(raw)};};
 try{
 const consumers=[[9,'preupdate'],[17,'preconfigure'],[19,'presst'],[21,'preupdate'],[23,'prereadiness']].map(([n,phase])=>({...scope,phase,checkpoint:'deploy-prod/'+n}));
 const startup={version:1,kind:'owner-prepaid-startup-config',grantSetId:hash({root,scope}),descriptorHash:hash(data),proofHash:w.built.proofHash,
  source:{repository:source.repository,prNumber:w.d.main.prNumber,candidateRevision:w.d.main.candidateRevision,candidateTree:w.d.main.candidateTree,baseRevision:w.d.main.baseRevision},consumers,ownerGithubActorId:42,notAfter:tick+240000};
 const storage={bucket:'example-ci-reader',kmsKeyArn:`arn:aws:kms:${data.region}:${data.account}:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee`,bucketKeyEnabled:true};
 const revision={version:2,limitsHash:NONROOT_REMAINING_WORK_LIMITS_HASH_V2,envelopeHash:hash('synthetic-capacity-envelope'),historyHeadHash:hash('synthetic-capacity-history')};
 const config={version:3,kind:'owner-ci-acquisition-config',budgetRevision:revision,compiledCeiling:NONROOT_REMAINING_WORK_CAPS_V2,startup,target:{kind:'production-data-release',descriptor:data,parameterVersion:w.parameter.Version},account:data.account,region:data.region,
  ownerRoot:{runtimeNonce:data.runtimeNonce,authorizationId:data.authorizationId},storage,bootstrap:consumers.map(s=>({checkpoint:s.checkpoint,responseBytes:1048576}))};
 const ledgerBinding={owner:'a'.repeat(32),executionId:'b'.repeat(32),planHash:'c'.repeat(64),publicationHash:'d'.repeat(64)};
 const late=(id,action,artifact,field,count,responseBytes)=>profile(id,action,action==='GetObject'?{Bucket:storage.bucket,ExpectedBucketOwner:data.account}:{...(action==='S3BlobGet'?{}:{registryId:data.account}),repositoryName:'mem9-on-aws/bootstrap'},
  {kind:'CONTROL_ARTIFACT_FROM_AUTHENTICATED_BUILD',late:{field,buildContractKey:'deployed-bootstrap',artifact},count,responseBytes,requestBytes:action==='S3BlobGet'?0:16384,ecr:!['GetObject','S3BlobGet'].includes(action)});
 const profiles=[profile('identity','GetCallerIdentity',{}),profile('descriptor','GetParameters',{Names:[w.parameter.Name],WithDecryption:true}),late('capsule','GetObject','private-capsule','Key',1,1048576),
  late('root','BatchGetImage','root','imageIds',1,8388608),late('manifests','BatchGetImage','manifest','imageIds',2,8388608),late('config-urls','GetDownloadUrlForLayer','config','layerDigest',2,16384),late('layer-urls','GetDownloadUrlForLayer','layer','layerDigest',64,16384),
  late('configs','S3BlobGet','config','layerDigest',2,FUTURE_CONTROL_CAPACITY.graphBytes),late('layers','S3BlobGet','layer','layerDigest',64,FUTURE_CONTROL_CAPACITY.graphBytes),late('scan','DescribeImageScanFindings','arm64','imageId',1,8388608)];
 const rootTemplate={version:1,kind:'future-owner-root-template',rootBindingHash:'b'.repeat(64),carrierTemplateHash:'c'.repeat(64),carrierSlot:{owner:ledgerBinding.owner,executionId:ledgerBinding.executionId,slotNonce:'e'.repeat(32)},source:startup.source};
 const catalog={version:2,kind:'future-ci-profile-catalog',cumulativeLimitsHash:NONROOT_REMAINING_WORK_LIMITS_HASH_V2,source:startup.source,ledgerBinding,
  consumers:consumers.map(scope=>({scope,profiles:[...profiles,{...profile('root-audit','GetObject',{Bucket:storage.bucket,ExpectedBucketOwner:data.account},{requestBytes:0,responseBytes:33554432}),kind:'OWNER_ROOT_ARTIFACT_FROM_FUNDED_CHECKPOINT',late:{field:'Key',checkpoint:scope.checkpoint}}],
   localBudget:{...zero(),logicalBytes:3*1024**3,uncompressedBytes:4*1024**3,processedEntries:100000},handshake:{terminalResponseBytes:1048576},controlCapacity:FUTURE_CONTROL_CAPACITY,rootRequest:createProspectiveCiRootRequestPolicy(scope.checkpoint)})),
  owner:{publication:FUTURE_OWNER_PUBLICATION,localBudget:zero(),roots:rootTemplate,delivery:createFutureOwnerDeliveryTemplate({source:{profile:'default',provider:'instance-metadata',configFile:'/synthetic/config',credentialsFile:'/synthetic/credentials',configHash:'a'.repeat(64),credentialsHash:null},storage})},
  finalization:{profiles:[profile('final-identity','GetCallerIdentity',{})],localBudget:zero()},localBudget:zero()};
 const reserve={ecrRequests:20000,logicalBytes:32*1024**3,httpBodyBytes:16*1024**3,uncompressedBytes:32*1024**3,processedEntries:1000000};
 const start={version:2,budgetRevision:revision,kind:'custody-ledger-start',binding:ledgerBinding,startingCounters:zero(),reserve,deadlineMs:tick+2700000,mode:'adoption'},startRaw=Buffer.from(JSON.stringify(start));
 const plan=createFutureFundingPlan({budgetRevision:revision,compiledCeiling:config.compiledCeiling,rootCarrier:{...rootTemplate,kind:'future-owner-root-carrier',carrierBuildHash:'f'.repeat(64),image:{account:data.account,region:data.region,repositoryName:'mem9-on-aws/preview/bootstrap',rootDigest:'sha256:'+'a'.repeat(64),arm64Digest:'sha256:'+'b'.repeat(64),configDigest:'sha256:'+'c'.repeat(64)}},
  binding:{grantSetId:startup.grantSetId,source:startup.source,anchors:{predecessorParameterHash:'a'.repeat(64),rootBindingHash:'b'.repeat(64),copyCheckpointHash:'c'.repeat(64),authorizationId:data.authorizationId,nextParameterVersion:w.parameter.Version}},catalogRaw:Buffer.from(JSON.stringify(catalog)).toString('base64'),ledgerStartHash:sha(startRaw),ownerGithubActorId:42,ownerStateDirectory:join(root,'grant-'+startup.grantSetId),issuedMs:tick-1000});
 const funding=inspectFutureFundingPlan(plan),spent=plan.budget,remaining=Object.fromEntries(Object.entries(reserve).map(([k,v])=>[k,v-spent[k]]));
 const event={version:2,budgetRevision:revision,sequence:1,...ledgerBinding,previousHash:null,type:'prepayment',data:{allocationId:funding.planHash,planHash:funding.planHash,scopeHash:funding.scopeHash,charge:spent,reserveDebit:spent},spent,remaining};
 const grantSet={...plan,version:3,kind:'owner-prepaid-future-grant-set',authority:false,planHash:funding.planHash,allocationId:funding.planHash,debit:{start,startRaw:startRaw.toString('base64'),events:[event],checkpoint:{binding:ledgerBinding,startingCounters:zero(),counters:spent,remainingReservation:remaining,eventCount:1,lastEventHash:hash(event),active:0,sealed:false,budgetRevision:revision}}};
 Object.assign(startup,{grantHash:hash(grantSet),ledgerStartHash:plan.ledgerStartHash,catalogHash:plan.catalogHash});
 const binding=makeCiStartupRunBinding(startup,source);
 env={PATH:process.env.PATH,HOME:root,LANG:'C.UTF-8',GITHUB_ACTIONS:'true',GITHUB_SERVER_URL:'https://github.com',GITHUB_REPOSITORY:source.repository,GITHUB_RUN_ID:String(source.run.id),GITHUB_RUN_ATTEMPT:String(source.run.attempt),GITHUB_JOB:scope.jobKey,GITHUB_SHA:source.checkout.sha,GITHUB_WORKFLOW_SHA:source.run.workflowSha,GITHUB_WORKSPACE:repo,GITHUB_EVENT_NAME:'push',GITHUB_REF:'refs/heads/main',STAGE:'prod',RUNNER_TEMP:root,AWS_REGION:data.region,
  AWS_ACCESS_KEY_ID:'ASIASYNTHETIC',AWS_SECRET_ACCESS_KEY:'synthetic-secret',AWS_SESSION_TOKEN:'synthetic-token',GH_TOKEN:'synthetic-root-reader',MEM9_DEPLOY_ROLE_ARN:`arn:aws:iam::${data.account}:role/github-actions-mem9-on-aws-prod`,MEM9_CI_ACQUISITION_CONFIG:JSON.stringify(config)};
  await mkdir(repo,{mode:0o700});
  for(const path of controlSourcePaths(w.d.sourceContext)){const target=join(repo,path);await mkdir(dirname(target),{recursive:true});await writeFile(target,(await readControlSourceFile(w.d.sourceContext,path)).bytes,{mode:0o644});}
  const git=args=>execFileSync('git',args,{cwd:repo,encoding:'utf8',stdio:['ignore','pipe','pipe']});git(['init','--quiet']);git(['add','.']);git(['-c','user.name=Fixture','-c','user.email=user@example.com','commit','-qm','test: synthetic replay source']);assert.equal(git(['rev-parse','HEAD^{tree}']).trim(),source.checkout.tree);
  await mkdir(join(root,'mem9-ci-smoke-source'),{mode:0o700});
  const sourceReceipt={version:1,kind:'ci-smoke-source-receipt',current:{repository:source.repository,runId:source.run.id,runAttempt:source.run.attempt,job:scope.jobKey,revision:source.checkout.sha},checkout:{revision:source.checkout.sha,tree:source.checkout.tree},observedMs:tick,expiresMs:startup.notAfter};
  const sourceRef=await save('mem9-ci-smoke-source/receipt.json',sourceReceipt);Object.assign(env,{MEM9_CI_SMOKE_SOURCE_RECEIPT:sourceRef.path,MEM9_CI_SMOKE_SOURCE_RECEIPT_HASH:sourceRef.sha256});
  const run={...w.d.rawRun,status:'in_progress',head_repository:{full_name:source.repository}},job={...w.d.rawJob,status:'in_progress',conclusion:null,started_at:new Date(tick-10000).toISOString(),completed_at:null,steps:[{name:w.d.job.steps[0].name,status:'completed',conclusion:'success',started_at:new Date(tick-9000).toISOString(),completed_at:new Date(tick-5000).toISOString()}]};
  const buildRecords={proof:w.built.proof,proofArchive:w.f.evidence.archive};
  const capture=await captureNonrootControlBuildAction({contract:w.d.contract,source,run,job,metadata:JSON.stringify({'containerimage.digest':w.d.build.image.rootDigest,'containerimage.config.digest':w.d.build.image.configDigest}),outputDigest:w.d.build.image.rootDigest,observedMs:tick-4000},{...nonrootArchiveResolvers(buildRecords.proofArchive),expected:{sourceContext:w.d.sourceContext}});
  const buildLog=Buffer.from(`#7 exporting manifest list ${capture.outputDigest}\n#7 exporting config ${w.d.build.image.configDigest}\n#7 DONE 1.0s\n`),completedJob={...job,status:'completed',conclusion:'success',completed_at:new Date(tick-3000).toISOString()};
  const completion=completeNonrootControlBuildAction(capture,{contract:w.d.contract,run,job:completedJob,buildLog,now:tick-2000});
  const prepared={version:1,kind:'control-build-prepared',identity:{repository:source.repository,revision:source.checkout.sha,runId:source.run.id,attempt:source.run.attempt},bundleHash:hash('synthetic-source-bundle'),contractHash:hash(w.d.contract),fingerprint:w.d.checkoutFingerprint,preparedMs:tick-11000};
  const encoded=encodeControlBuildCapture({prepared,capture}),build={prepared,capture,commitment:encoded.commitment,contract:w.d.contract,completion,buildLog,sourceContext:w.d.sourceContext};
  let artifact,winner,request;
  const artifactClient={async uploadArtifact(name,files){events.push('artifact');const payload=JSON.parse(await readFile(files[0]));winner={...payload,artifactId:123,artifactDigest:'e'.repeat(64)};artifact={id:123,name,size_in_bytes:256,digest:'sha256:'+winner.artifactDigest,expired:false,created_at:new Date(tick).toISOString(),expires_at:new Date(tick+86400000).toISOString(),workflow_run:{id:source.run.id,head_sha:source.checkout.sha,head_branch:'main'}};return {id:123,size:256,digest:winner.artifactDigest};}};
  const host={env,cwd:repo,checkout:async()=>sourceReceipt.checkout,run:async(file,args)=>{assert.equal(file,'git');if(args[0]==='diff')return '';if(args[1]==='HEAD:.github/workflows/infra-ci.yml')return JSON.stringify({jobs:{'build-image-transition-control':w.d.job}});assert.equal(args[0],'show');return [source.checkout.sha,source.checkout.tree,source.checkout.parents.join(' ')].join('\n');},readLog:async()=>`MEM9_CONTROL_BUILD_COMMITMENT ${JSON.stringify(encoded.commitment)}\n`,api:async path=>{
   if(path==='commits/main'||path==='commits/'+source.checkout.sha)return {sha:source.checkout.sha,commit:{tree:{sha:source.checkout.tree}},parents:source.checkout.parents.map(sha=>({sha}))};
   if(path==='pulls/'+source.pullRequest.number)return {number:source.pullRequest.number,state:'closed',merged:true,head:{sha:source.pullRequest.headSha,repo:{full_name:source.repository}},base:{ref:'main'},merge_commit_sha:source.checkout.sha};
   if(path.includes('/jobs?'))return {total_count:1,jobs:[completedJob]};if(path.startsWith('actions/runs/'))return run;
   if(path.startsWith('commits/')&&path.includes('/statuses?')){const base={id:1,url:`https://api.github.com/repos/${source.repository}/statuses/${source.checkout.sha}`,creator:{id:42}},rows=[{...base,context:'mem9/prepaid/'+startup.grantSetId,state:'success',description:'binding:'+hash(binding),target_url:`https://github.com/${source.repository}/actions/runs/${source.run.id}`}];if(winner)rows.unshift({...base,id:2,...ciStartupCheckpointSelection(startup,binding,scope,winner).announcement.payload});return rows;}
   if(path==='actions/artifacts/'+artifact?.id)return artifact;throw Error('UnexpectedReplayGitHub:'+path);
  }};
  const phaseEvidence={...w.phaseEvidence,phase},rootBytes=Buffer.from(JSON.stringify(phaseEvidence));
  const handler={destroy(){},async handle(q){
   httpCalls.push({method:q.method,path:q.path,hostname:q.hostname});let raw,headers={'content-type':'application/json'};
   if(q.hostname.startsWith('s3.')){
    headers={...headers,'x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':storage.kmsKeyArn,'x-amz-server-side-encryption-bucket-key-enabled':'true'};
    if(q.method==='PUT'){assert.equal(q.headers['if-none-match'],'*');events.push(q.path.endsWith('/root-request.json')?'root-put':'put');if(q.path.endsWith('/request.json'))request=JSON.parse(Buffer.from(q.body));headers.etag='"synthetic-etag"';raw=Buffer.alloc(0);}
    else if(q.path.endsWith('/root-audit.json')){events.push('root-get');raw=rootBytes;}
    else{events.push('get');raw=Buffer.from(JSON.stringify({version:1,kind:'owner-ci-allowance-response',runBinding:binding,scope,nonce:request.nonce,artifactId:123,requestHash:hash(request),grantSet,expiresMs:startup.notAfter}));}
   }else if(q.hostname.startsWith('sts.')){headers={'content-type':'text/xml'};raw=Buffer.from(`<GetCallerIdentityResponse><GetCallerIdentityResult><Account>${data.account}</Account><Arn>arn:aws:sts::${data.account}:assumed-role/github-actions-mem9-on-aws-prod/synthetic</Arn><UserId>AROASYNTHETIC:synthetic</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`);}
   else{assert(q.hostname.startsWith('ssm.'));raw=Buffer.from(JSON.stringify({Parameters:[w.parameter],InvalidParameters:[]}));}
   return {response:{statusCode:200,headers:{...headers,'content-length':String(raw.length)},body:Readable.from([raw],{objectMode:false})}};
  }};
  const rootGithubRequest=async()=>{events.push('root-ready');const raw=Buffer.from(JSON.stringify([{...ciRootReadyStatus(config,scope,sha(rootBytes)),creator:{id:42}}])),body=Readable.from([raw],{objectMode:false});body.statusCode=200;body.headers={'content-length':String(raw.length)};return body;};
  acquisition=await openFutureCiSmokeAcquisition({env,scope:{route:scope.route,phase,checkpoint:scope.checkpoint},sourceReceipt,host},{now:()=>Date.now(),artifactClient,requestHandler:handler,controlResourceDocker:resourceDocker,rootGithubRequest,sleep:async()=>{throw Error('UnexpectedReplayPoll');}});
  transport=createNonrootBudgetedReads({region:data.region,env,metadataReads:acquisition,requestHandler:handler});
  await transport.clients.sts.send(new GetCallerIdentityCommand({}));await transport.clients.ssm.send(new GetParametersCommand({Names:[w.parameter.Name],WithDecryption:true}));
  await acquisition.bindControlBuild({context:w.authorization,records:buildRecords,build});allocation=await acquisition.allocateControlResources();
  const graph=w.d.controlVerification.graph,state=imageGraphState(graph),download=await mkdtemp(join(allocation.tempRoot,'mem9-control-download-')),cache=join(download,'blobs');await mkdir(cache,{mode:0o700});
  // Copy the actual graph bytes and settle their original native read slots.
  const manifests=graph.inventory.nodes.filter(d=>/manifest|index/.test(d.mediaType));manifests.sort((a,b)=>Number(b.digest===build.capture.outputDigest)-Number(a.digest===build.capture.outputDigest));
  for(const d of manifests){const chunks=[];for await(const chunk of state.store.open(d))chunks.push(chunk);const raw=Buffer.concat(chunks),request={registryId:data.account,repositoryName:'mem9-on-aws/bootstrap',imageIds:[{imageDigest:d.digest}]};
   const value={images:[{registryId:data.account,repositoryName:request.repositoryName,imageId:request.imageIds[0],imageManifest:raw.toString(),imageManifestMediaType:d.mediaType}],failures:[]},slot=await acquisition.beforeRead('BatchGetImage',request);slot.finalGuard();slot.charge(Buffer.byteLength(JSON.stringify(value)));await slot.complete(value,sha(JSON.stringify(value)));await writeFile(join(cache,d.digest.slice(7)),raw,{mode:0o600});
  }
  for(const d of graph.inventory.nodes.filter(d=>!manifests.includes(d))){const request={repositoryName:'mem9-on-aws/bootstrap',layerDigest:d.digest},slot=await acquisition.beforeRead('S3BlobGet',request);slot.finalGuard();const fd=await open(join(cache,d.digest.slice(7)),'wx',0o600);try{for await(const chunk of state.store.open(d)){slot.charge(chunk.length);await fd.write(chunk);}}finally{await fd.close();}await slot.complete({...request,size:d.size},d.digest.slice(7));}
  await registerControlCache(allocation.handle,{graph,cacheDirectory:cache,startedMs:tick,completedMs:tick});
  const loaderDirectory=await mkdtemp(join(allocation.tempRoot,'mem9-control-docker-'));for(const name of ['index.json','oci-layout','image.tar'])await writeFile(join(loaderDirectory,name),name,{mode:0o600});await beginControlImageLoad(allocation.handle,{loaderDirectory});loaded=true;await recordControlImageLoad(allocation.handle,{outcome:'loaded',completedMs:tick});
  const checked=await bindNonrootDeploymentContext(w.authorization,{parameter:w.parameter,deploymentSource:w.deploymentSource,phaseEvidence,evidence,now:tick});
  const bundle=await createNonrootDeploymentBundle({...records,context:checked,evidence:{...evidence,controlCache:{directory:cache,inventory:graph.inventory}},deploymentSource:w.deploymentSource,phaseEvidence,targetObservation:w.targetObservation},source,w.parameter,{phase:'deployment',sourceReceiptHash:sourceRef.sha256,now:tick});
  const bundleRef=await save('bundle.json',bundle);
  await acquisition.requestRootAudit({context:w.authorization,records:buildRecords,parameter:w.parameter,source,phase,deploymentSource:w.deploymentSource,targetObservation:{...w.targetObservation,serviceObservation:w.serviceObservation}});
  const Key=`data-authorizations/${data.runtimeNonce}/${data.authorizationId}/ci-grants/${startup.grantSetId}/${hash(scope.checkpoint)}/root-audit.json`;
  const response=await transport.clients.s3.send(new GetObjectCommand({Bucket:storage.bucket,Key,ExpectedBucketOwner:data.account}));assert.deepEqual(Buffer.from(await response.Body.transformToByteArray()),rootBytes);
  const resourceReceiptRef=await acquisition.sealControlResources({bundleRef}),done=await acquisition.finish({bundleRef,resourceReceiptRef});transport.close();transport=undefined;
  Object.assign(env,{MEM9_CI_ACQUISITION_COMPLETION_FILE:done.receiptRef.path,MEM9_CI_ACQUISITION_COMPLETION_HASH:done.receiptRef.sha256,MEM9_IMAGE_TRANSITION_BUNDLE_FILE:bundleRef.path,MEM9_IMAGE_TRANSITION_BUNDLE_HASH:bundleRef.sha256});
  return {root,env,scope,config,grantSet,bundle,completionRef:done.receiptRef,httpCalls,events,close};
 }catch(error){try{await acquisition?.hold();}finally{await close();}throw error;}
}
