import {describe,it,expect,beforeAll,afterAll,vi} from 'vitest';
import {mkdir,writeFile,readFile,readdir,lstat} from 'node:fs/promises';
import {join} from 'node:path';
import {Readable} from 'node:stream';
import {loadNonrootProductionEvidence} from './lib/production-nonroot-deployment-provider.mjs';
import {controlPrefixFixture} from './production-nonroot-control-prefix.fixture.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {sha} from './lib/ci-smoke-acquisition-format.mjs';
import {createNonrootBudgetedReads} from './lib/production-nonroot-budget-transport.mjs';
import {imageGraphState,controlImageGraphBinding} from './lib/production-image-graph.mjs';
import {inspectNonrootControlPrerequisites} from './lib/production-nonroot-control-prerequisites.mjs';
import {inspectNonrootControlGuardTests} from './lib/production-nonroot-control-guard.mjs';
import {allocateCiSmokeControlResources,sealControlResources,linkControlResourceCompletion,verifyControlResources,cleanupCiSmokeControlResources} from './lib/ci-smoke-control-resources.mjs';
import {verifyOwnedNonrootControlCache} from './lib/production-nonroot-control-cache.mjs';

// Synthetic evidence is issued relative to the actual container clock. The
// real dispatcher rejects future deadlines; never replace that check.
const fixtureTime=vi.hoisted(()=>Date.now()-7200000-5000);
vi.mock('./production-canary-transition.fixture.mjs',async original=>{const module=await original();return {...module,transitionFixture:()=>module.transitionFixture({now:fixtureTime})};});
const wireDates=value=>Array.isArray(value)?value.map(wireDates):value&&typeof value==='object'?Object.fromEntries(Object.entries(value).map(([key,item])=>[key,typeof item==='string'&&key.endsWith('At')&&/^\d{4}-\d\d-\d\dT/.test(item)?Date.parse(item)/1000:wireDates(item)])):value;

import {verifyImageSecurityDeployment} from './verify-image-security-deployment.mjs';
import {nonrootBundleRecords} from './production-nonroot-bundle.fixture.mjs';
import {exportNonrootArchive} from './lib/production-nonroot-archive.mjs';
import {getNonrootTargetRegistration,nonrootAuthorizationBindings} from './lib/production-nonroot-proof.mjs';
import {nonrootDeploymentWrapperFixture} from './production-nonroot-deployment.fixture.mjs';

it('the default verifier reports missing root acquisition instead of adopting the source-only material',async()=>{
 const f=await nonrootDeploymentWrapperFixture(),source=f.d.source,calls=[],hold=vi.fn();
 const env={GITHUB_ACTIONS:'true',STAGE:'prod',AWS_REGION:f.f.region,GITHUB_JOB:'deploy-prod',GITHUB_REPOSITORY:source.repository,GITHUB_SHA:source.checkout.sha,GITHUB_WORKFLOW_SHA:source.checkout.sha,GITHUB_EVENT_NAME:'push',GITHUB_REF:'refs/heads/main',GITHUB_RUN_ID:String(source.run.id),GITHUB_RUN_ATTEMPT:String(source.run.attempt),MEM9_DEPLOY_ROLE_ARN:`arn:aws:iam::${f.f.account}:role/example`};
 const api=async path=>{
  if(path==='commits/main'||path==='commits/'+source.checkout.sha)return {sha:source.checkout.sha,commit:{tree:{sha:source.checkout.tree}},parents:source.checkout.parents.map(sha=>({sha}))};
  if(path==='pulls/'+source.pullRequest.number)return {number:source.pullRequest.number,state:'closed',merged:true,head:{sha:source.pullRequest.headSha,repo:{full_name:source.repository}},base:{ref:'main'},merge_commit_sha:source.checkout.sha};
  if(path==='actions/runs/'+source.run.id+'/attempts/'+source.run.attempt)return {...f.d.rawRun,head_repository:{full_name:source.repository}};
  throw Error('UnexpectedSyntheticSourceRead');
 };
 const clients={sts:{async send(){calls.push('identity');return {Account:f.f.account,Arn:`arn:aws:sts::${f.f.account}:assumed-role/example/synthetic`};}},ssm:{async send(){calls.push('parameter');return {Parameters:[f.parameter]};}}};
 const deps={clients,api,git:async args=>args[0]==='diff'?'':source.checkout.sha+'\n'+source.checkout.tree+'\n'+source.checkout.parents.join(' '),clock:()=>f.f.now,metadataReads:{hold},loadAuthority:async()=>({context:f.authorization,records:{proof:f.built.proof,proofArchive:f.evidence.archive}})};
 await expect(verifyImageSecurityDeployment(deps,{env,region:f.f.region,phase:'preconfigure',sourceReceiptHash:'a'.repeat(64)})).rejects.toThrow('NonrootRootAuditProducerRequired');
 expect(calls).toEqual(['identity','parameter']);expect(hold).toHaveBeenCalledOnce();
});
describe.skipIf(process.env.MEM9_NONROOT_CONTAINER_TEST!=='1')('default production provider with actual local CONTROL collectors',()=>{
 let fixture,budgetedReads,result,allocation,claimRef,bundleRef,env,metadataReads,publication,held=false,bound=false;
 const events=[],reads=[],totals={ecrRequests:0,httpBodyBytes:0,logicalBytes:0,uncompressedBytes:0,processedEntries:0};
 const charge=value=>{for(const [k,v]of Object.entries(value)){expect(Number.isSafeInteger(v)&&v>=0).toBe(true);totals[k]+=v;}expect(totals.ecrRequests).toBeLessThanOrEqual(64);expect(totals.httpBodyBytes).toBeLessThan(256*1024*1024);expect(totals.logicalBytes).toBeLessThan(2*1024*1024*1024);expect(totals.uncompressedBytes).toBeLessThan(2*1024*1024*1024);};
 beforeAll(async()=>{
  fixture=await controlPrefixFixture();publication=await nonrootBundleRecords(fixture);const {d,root,contract,encoded}=fixture,scope=contract.output;const archiveWire=await exportNonrootArchive(publication.proofArchive);
  env={STAGE:'prod',GITHUB_WORKFLOW_SHA:d.source.checkout.sha,GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:d.source.repository,GITHUB_RUN_ID:String(d.source.run.id),GITHUB_RUN_ATTEMPT:String(d.source.run.attempt),GITHUB_SHA:d.source.checkout.sha,GITHUB_JOB:'deploy-prod',GITHUB_EVENT_NAME:'push',GITHUB_REF:'refs/heads/main',AWS_REGION:scope.region,RUNNER_TEMP:root,
   MEM9_CI_ACQUISITION_CONFIG:'{"synthetic":"control-prefix"}',MEM9_DECISION_ARTIFACT_BUCKET:'example-ci-reader',MEM9_DEPLOY_ROLE_ARN:`arn:aws:iam::${scope.account}:role/github-actions-mem9-on-aws-prod`,MEM9_CI_EVIDENCE_KMS_KEY_ARN:`arn:aws:kms:${scope.region}:${scope.account}:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee`,AWS_ACCESS_KEY_ID:'synthetic',AWS_SECRET_ACCESS_KEY:'synthetic',AWS_SESSION_TOKEN:'synthetic'};
  metadataReads={
   async beforeRead(action,request){expect(held).toBe(false);expect(['GetCallerIdentity','GetParameters','GetObject','BatchGetImage','GetDownloadUrlForLayer','S3BlobGet','DescribeImageScanFindings','DescribeServices','ListTasks','DescribeTasks','DescribeTaskDefinition']).toContain(action);const index=reads.length;reads.push({action,request});events.push(action);
    if(['BatchGetImage','GetDownloadUrlForLayer','S3BlobGet','DescribeImageScanFindings'].includes(action)){expect(bound).toBe(true);expect(['mem9-on-aws/bootstrap','mem9-on-aws/llm-proxy','mem9-on-aws/mnemo-server','mem9-on-aws/qwen3-embed']).toContain(request.repositoryName);if(request.registryId)expect(request.registryId).toBe(scope.account);}
    charge({ecrRequests:['BatchGetImage','GetDownloadUrlForLayer','DescribeImageScanFindings'].includes(action)?1:0});let dispatched=false,settled=false;
    return {caps:{requestBytes:16384,responseBytes:action==='S3BlobGet'?128*1024*1024:8388608},finalGuard(){expect(dispatched||settled||held).toBe(false);dispatched=true;},charge(bytes){expect(dispatched).toBe(true);charge({httpBodyBytes:bytes});},async complete(response,responseHash){expect(settled).toBe(false);expect(responseHash).toMatch(/^[a-f0-9]{64}$/);if(action==='S3BlobGet')expect(response).toEqual({...request,size:fixture.d.controlVerification.graph.inventory.nodes.find(n=>n.digest===request.layerDigest).size});reads[index].responseHash=responseHash;settled=true;},async unknown(){held=true;events.push('unknown');}};
   },reserveLocal:charge,finish(){throw Error('CallerOwnsCompletion');},async hold(){held=true;events.push('hold');},
   async bindControlBuild(value){expect(nonrootAuthorizationBindings(value.context).proofHash).toBe(fixture.built.proofHash);expect(value.build.capture).toEqual(fixture.capture);expect(value.build.completion.captureHash).toBe(hash(fixture.capture));expect(reads.filter(r=>r.action==='BatchGetImage')).toEqual([]);bound=true;events.push('bind');return {...scope,rootDigest:fixture.capture.outputDigest};},
   async allocateControlResources(){expect(bound).toBe(true);events.push('allocate');
    const acquisitionScope={kind:'target',jobKey:env.GITHUB_JOB,route:env.GITHUB_JOB,phase:'preconfigure',checkpoint:'deploy-prod/19'},binding={source:d.source},bindingHash=hash(binding);
    const sourceReceiptRef={path:join(root,'source.json'),sha256:sha(JSON.stringify(d.source))};await writeFile(sourceReceiptRef.path,JSON.stringify(d.source),{mode:0o600,flag:'wx'});
    const directory=join(root,'mem9-ci-future-acquisitions');await mkdir(directory,{mode:0o700});
    const claim={version:1,kind:'ci-future-acquisition-claim',scope:acquisitionScope,binding,sourceReceiptRef,configHash:sha(env.MEM9_CI_ACQUISITION_CONFIG),openedMs:Date.now(),expiresMs:Date.now()+300000,ownerRefund:0};
    claimRef={path:join(directory,'target-'+hash({bindingHash,scope:acquisitionScope})+'-claim.json'),sha256:sha(JSON.stringify(claim))};await writeFile(claimRef.path,JSON.stringify(claim),{mode:0o600,flag:'wx'});
    allocation=await allocateCiSmokeControlResources({env,expected:{claimRef,scope:acquisitionScope,bindingHash,sourceReceiptRef,configHash:claim.configHash,run:{repository:env.GITHUB_REPOSITORY,runId:d.source.run.id,runAttempt:d.source.run.attempt,jobKey:env.GITHUB_JOB,revision:env.GITHUB_SHA},rootDigest:d.build.image.rootDigest,configDigest:d.build.image.configDigest}});return allocation;
   }};
  const state=imageGraphState(d.controlVerification.graph),nodes=new Map(d.controlVerification.graph.inventory.nodes.map(n=>[n.digest,n]));
  const raw=async digest=>{const chunks=[];for await(const b of state.store.open(nodes.get(digest)))chunks.push(b);return Buffer.concat(chunks);};
  const handler={async handle(request){
   if(request.hostname==='sts.'+scope.region+'.amazonaws.com'){
    const text=`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Account>${scope.account}</Account><Arn>arn:aws:sts::${scope.account}:assumed-role/github-actions-mem9-on-aws-prod/synthetic</Arn><UserId>synthetic</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`;
    return {response:{statusCode:200,headers:{'content-type':'text/xml'},body:Readable.from([Buffer.from(text)])}};
   }
   if(request.hostname==='ssm.'+scope.region+'.amazonaws.com')return {response:{statusCode:200,headers:{},body:Readable.from([Buffer.from(JSON.stringify({Parameters:[fixture.parameter],InvalidParameters:[]}))])}};
   if(request.hostname==='s3.'+scope.region+'.amazonaws.com'){
    expect(request.method).toBe('GET');let bytes;
    if(request.path.endsWith('/operation.json'))bytes=Buffer.from(JSON.stringify(publication.operation));
    else if(request.path.endsWith('/nonroot-proof-archive.json'))bytes=Buffer.from(JSON.stringify(archiveWire));
    else {expect(request.path).toBe('/'+env.MEM9_DECISION_ARTIFACT_BUCKET+'/decisions/prod/control-build/'+d.source.run.id+'/'+d.source.run.attempt+'/'+encoded.commitment.envelopeSha256+'.json');bytes=encoded.bytes;}
    return {response:{statusCode:200,headers:{etag:'"synthetic"','content-length':String(bytes.length),'x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':env.MEM9_CI_EVIDENCE_KMS_KEY_ARN,'x-amz-server-side-encryption-bucket-key-enabled':'true'},body:Readable.from([bytes])}};
   }
   if(request.hostname==='ecs.'+scope.region+'.amazonaws.com'){
    const action=request.headers['x-amz-target'].split('.').at(-1),query=JSON.parse(Buffer.from(request.body).toString()),task={...structuredClone(fixture.f.f.legacy.current.backendTask),clusterArn:fixture.f.cluster,group:'service:Mem9Server',desiredStatus:'RUNNING',lastStatus:'RUNNING'};
    const service={...structuredClone(fixture.f.before.service),serviceArn:`arn:aws:ecs:${scope.region}:${scope.account}:service/${fixture.f.cluster.split('/').at(-1)}/Mem9Server`,serviceName:'Mem9Server',clusterArn:fixture.f.cluster,status:'ACTIVE',runningCount:1,pendingCount:0,taskDefinition:task.taskDefinitionArn,deployments:[{status:'PRIMARY',rolloutState:'COMPLETED',taskDefinition:task.taskDefinitionArn}]};
    const response=action==='DescribeServices'?{services:[service],failures:[]}:action==='ListTasks'?{taskArns:[task.taskArn]}:action==='DescribeTasks'?{tasks:[task],failures:[]}:{taskDefinition:{...structuredClone(fixture.f.before.backend),taskDefinitionArn:task.taskDefinitionArn,status:'ACTIVE'},tags:[]};
    expect(query).toBeDefined();return {response:{statusCode:200,headers:{},body:Readable.from([Buffer.from(JSON.stringify(wireDates(response)))])}};
   }
   if(request.hostname==='api.ecr.'+scope.region+'.amazonaws.com'){
    const query=JSON.parse(request.body),action=request.headers['x-amz-target'].split('.').at(-1);let response;
    if(action==='BatchGetImage'&&query.repositoryName!=='mem9-on-aws/bootstrap'){const component=query.repositoryName.split('/').at(-1),image=fixture.current.images[component];response=JSON.parse(fixture.f.f.input.artifacts[component][query.imageIds[0].imageDigest===image.rootDigest?'root':'child']);}
    else if(action==='DescribeImageScanFindings'){response={registryId:scope.account,repositoryName:scope.repositoryName,imageId:{imageDigest:d.build.image.arm64Digest},imageScanStatus:{status:'COMPLETE'},imageScanFindings:{imageScanCompletedAt:Math.floor(Date.now()/1000)-1,findingSeverityCounts:{},findings:[]}};}
    else if(action==='BatchGetImage'){const digest=query.imageIds[0].imageDigest,bytes=await raw(digest);response={images:[{registryId:scope.account,repositoryName:scope.repositoryName,imageId:{imageDigest:digest},imageManifest:bytes.toString(),imageManifestMediaType:JSON.parse(bytes).mediaType}],failures:[]};}
    else {expect(action).toBe('GetDownloadUrlForLayer');const date=new Date(Date.now()).toISOString().replace(/[-:]/g,'').replace(/\.\d{3}/,'');
     const url=new URL(`https://prod-${scope.region}-starport-layer-bucket.s3.${scope.region}.amazonaws.com/${query.layerDigest.slice(7)}`);
     for(const [k,v]of Object.entries({'X-Amz-Algorithm':'AWS4-HMAC-SHA256','X-Amz-Date':date,'X-Amz-Expires':'300','X-Amz-Credential':`synthetic/${date.slice(0,8)}/${scope.region}/s3/aws4_request`,'X-Amz-SignedHeaders':'host','X-Amz-Signature':'a'.repeat(64)}))url.searchParams.set(k,v);
     response={layerDigest:query.layerDigest,downloadUrl:url.href};}
    return {response:{statusCode:200,headers:{},body:Readable.from([Buffer.from(JSON.stringify(response))])}};
   }
   expect(request.hostname).toBe(`prod-${scope.region}-starport-layer-bucket.s3.${scope.region}.amazonaws.com`);expect(request.headers.authorization).toBeUndefined();const descriptor=nodes.get('sha256:'+request.path.slice(1));expect(descriptor).toBeDefined();
   return {response:{statusCode:200,headers:{'content-length':String(descriptor.size)},body:Readable.from(state.store.open(descriptor))}};
  },destroy(){}};
  budgetedReads=createNonrootBudgetedReads({region:scope.region,env,metadataReads,requestHandler:handler});
  const host={env,cwd:root,async api(path){if(path.endsWith('/jobs?per_page=100'))return {total_count:1,jobs:[fixture.completedJob]};if(path==='actions/jobs/'+d.rawJob.id)return fixture.completedJob;if(path==='actions/runs/'+d.source.run.id+'/attempts/'+d.source.run.attempt)return {...d.rawRun,head_repository:{full_name:d.source.repository}};if(path==='commits/main'||path==='commits/'+d.source.checkout.sha)return {sha:d.source.checkout.sha,commit:{tree:{sha:d.source.checkout.tree}},parents:d.source.checkout.parents.map(sha=>({sha}))};if(path==='pulls/'+d.source.pullRequest.number)return {number:d.source.pullRequest.number,state:'closed',merged:true,head:{sha:d.source.pullRequest.headSha,repo:{full_name:d.source.repository}},base:{ref:'main'},merge_commit_sha:d.source.checkout.sha};throw Error('UnallocatedGithubFixtureRead');},async readLog(id){expect(id).toBe(d.rawJob.id);return fixture.log;}};
  fixture.input={env,host,context:fixture.context,records:publication,parameter:fixture.parameter,source:d.source,metadataReads,budgetedReads,phase:'preconfigure',sourceContext:d.sourceContext};fixture.deps={clients:budgetedReads.clients,git:async args=>args[0]==='diff'?'':d.source.checkout.sha+'\n'+d.source.checkout.tree+'\n'+d.source.checkout.parents.join(' '),api:host.api,readEcr:(operation,request)=>budgetedReads.readEcr(operation,request,{account:scope.account}),metadataReads,budgetedReads,host,controlSourceContext:d.sourceContext};fixture.options={env,region:scope.region,phase:'preconfigure',sourceReceiptHash:publication.sourceReceiptHash};
 },180000);
 afterAll(async()=>{try{if(allocation)try{fixture.run(['image','rm',allocation.tag]);}catch{}}finally{budgetedReads?.close();fixture?.close();}},120000);
 it('default verification holds on the missing real root producer before any CONTROL reads',async()=>{
  await expect(loadNonrootProductionEvidence(fixture.input)).rejects.toThrow('NonrootRootAuditProducerRequired');
  expect(reads.filter(r=>['BatchGetImage','GetDownloadUrlForLayer','S3BlobGet'].includes(r.action))).toEqual([]);expect(allocation).toBeUndefined();
  expect(events).toEqual([]);expect(reads).toEqual([]);expect(held).toBe(false);
 });
 it('holds before CONTROL acquisition when the original local budget rejects the prefix',async()=>{
  const hold=vi.fn(),limited={...metadataReads,reserveLocal(){throw Error('SyntheticOriginalBudgetExhausted');},hold};
  await expect(loadNonrootProductionEvidence({...fixture.input,metadataReads:limited,collectRootAudit:()=>{throw Error('UnreachableRootProducer');}})).rejects.toThrow('SyntheticOriginalBudgetExhausted');
  expect(hold).toHaveBeenCalledOnce();expect(events).toEqual([]);expect(reads).toEqual([]);expect(allocation).toBeUndefined();
 });
 it('runs the default provider, actual scan rule, assembler, target and final binder without a replacement loader',async()=>{
  const rootAudit=async input=>{
   expect(input.phase).toBe('preconfigure');expect(input.deploymentSource.deployedControlBuild.image.rootDigest).toBe(fixture.capture.outputDigest);expect(input.targetObservation.serviceObservation.task.lastStatus).toBe('RUNNING');
   const audit=fixture.f.predeploymentAudit,auditRef=fixture.f.a.json(audit,'root-audit');return {audit,auditRef,objects:[]};
  };
  result=await verifyImageSecurityDeployment({...fixture.deps,collectRootAudit:rootAudit},fixture.options);
  expect(result.phase).toBe('nonroot-deployment-phase-verified');expect(result.bundle.controlCache.inventory.kind).toBe('readonly-control-image-graph');
  expect(getNonrootTargetRegistration(result.context,'backend')).toBeDefined();expect(reads.filter(r=>r.action==='DescribeImageScanFindings')).toHaveLength(1);
  expect(reads.filter(r=>r.action==='DescribeServices')).toHaveLength(2);expect(reads.filter(r=>r.action==='GetParameters')).toHaveLength(2);expect(reads.every(r=>r.responseHash)).toBe(true);
  expect((await readdir(result.bundle.controlCache.directory)).length).toBe(result.bundle.controlCache.inventory.nodes.length);
 },180000);
});
