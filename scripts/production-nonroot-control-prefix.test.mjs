import {describe,it,expect,beforeAll,afterAll,vi} from 'vitest';
import {mkdir,writeFile,readFile,readdir,lstat} from 'node:fs/promises';
import {join} from 'node:path';
import {Readable} from 'node:stream';
import {prepareNonrootProductionControl} from './lib/production-nonroot-deployment-provider.mjs';
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

function missingInput(){
 return {env:{},host:{api:vi.fn(),readLog:vi.fn()},context:{},records:{},parameter:{},source:{},guardImportAudit:{},
  metadataReads:Object.fromEntries(['beforeRead','reserveLocal','finish','hold','bindControlBuild','allocateControlResources'].map(k=>[k,vi.fn()])),
  budgetedReads:{readJson:vi.fn(),readBlob:vi.fn(),clients:{s3:{send:vi.fn()}}}};
}
it.each(['beforeRead','reserveLocal','finish','hold','bindControlBuild','allocateControlResources'])('rejects missing %s before any acquisition or native action',async key=>{
 const input=missingInput();delete input.metadataReads[key];await expect(prepareNonrootProductionControl(input)).rejects.toThrow('NonrootProductionControlAcquisition');
 expect(input.host.api).not.toHaveBeenCalled();expect(input.budgetedReads.clients.s3.send).not.toHaveBeenCalled();expect(input.budgetedReads.readJson).not.toHaveBeenCalled();
});
it('rejects missing metered transport and open input fields before any read',async()=>{
 const input=missingInput();delete input.budgetedReads.readBlob;await expect(prepareNonrootProductionControl(input)).rejects.toThrow('NonrootProductionControlTransport');
 await expect(prepareNonrootProductionControl({...input,loadImage:()=>({passed:true})})).rejects.toThrow('NonrootProductionControlFields');expect(input.host.api).not.toHaveBeenCalled();
});

describe.skipIf(process.env.MEM9_NONROOT_CONTAINER_TEST!=='1')('actual CONTROL producer prefix with metered SDK and local Docker',()=>{
 let fixture,budgetedReads,result,allocation,claimRef,bundleRef,env,metadataReads,held=false,bound=false;
 const events=[],reads=[],totals={ecrRequests:0,httpBodyBytes:0,logicalBytes:0,uncompressedBytes:0,processedEntries:0};
 const charge=value=>{for(const [k,v]of Object.entries(value)){expect(Number.isSafeInteger(v)&&v>=0).toBe(true);totals[k]+=v;}expect(totals.ecrRequests).toBeLessThanOrEqual(64);expect(totals.httpBodyBytes).toBeLessThan(256*1024*1024);expect(totals.logicalBytes).toBeLessThan(2*1024*1024*1024);expect(totals.uncompressedBytes).toBeLessThan(2*1024*1024*1024);};
 beforeAll(async()=>{
  fixture=await controlPrefixFixture();const {d,root,contract,encoded}=fixture,scope=contract.output;
  env={GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:d.source.repository,GITHUB_RUN_ID:String(d.source.run.id),GITHUB_RUN_ATTEMPT:String(d.source.run.attempt),GITHUB_SHA:d.source.checkout.sha,GITHUB_JOB:'deploy-prod',GITHUB_EVENT_NAME:'push',GITHUB_REF:'refs/heads/main',AWS_REGION:scope.region,RUNNER_TEMP:root,
   MEM9_CI_ACQUISITION_CONFIG:'{"synthetic":"control-prefix"}',MEM9_DECISION_ARTIFACT_BUCKET:'example-ci-reader',MEM9_DEPLOY_ROLE_ARN:`arn:aws:iam::${scope.account}:role/github-actions-mem9-on-aws-prod`,MEM9_CI_EVIDENCE_KMS_KEY_ARN:`arn:aws:kms:${scope.region}:${scope.account}:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee`,AWS_ACCESS_KEY_ID:'synthetic',AWS_SECRET_ACCESS_KEY:'synthetic',AWS_SESSION_TOKEN:'synthetic'};
  metadataReads={
   async beforeRead(action,request){expect(held).toBe(false);expect(['GetObject','BatchGetImage','GetDownloadUrlForLayer','S3BlobGet']).toContain(action);const index=reads.length;reads.push({action,request});events.push(action);
    if(action!=='GetObject'){expect(bound).toBe(true);expect(request.repositoryName).toBe(scope.repositoryName);if(request.registryId)expect(request.registryId).toBe(scope.account);}
    charge({ecrRequests:['BatchGetImage','GetDownloadUrlForLayer'].includes(action)?1:0});let dispatched=false,settled=false;
    return {caps:{requestBytes:16384,responseBytes:action==='S3BlobGet'?128*1024*1024:8388608},finalGuard(){expect(dispatched||settled||held).toBe(false);dispatched=true;},charge(bytes){expect(dispatched).toBe(true);charge({httpBodyBytes:bytes});},async complete(response,responseHash){expect(settled).toBe(false);expect(responseHash).toMatch(/^[a-f0-9]{64}$/);if(action==='S3BlobGet')expect(response).toEqual({...request,size:fixture.d.controlVerification.graph.inventory.nodes.find(n=>n.digest===request.layerDigest).size});reads[index].responseHash=responseHash;settled=true;},async unknown(){held=true;events.push('unknown');}};
   },reserveLocal:charge,finish(){throw Error('CallerOwnsCompletion');},async hold(){held=true;events.push('hold');},
   async bindControlBuild(value){expect(value.context).toBe(fixture.context);expect(value.build.capture).toEqual(fixture.capture);expect(value.build.completion.captureHash).toBe(hash(fixture.capture));expect(reads.map(r=>r.action)).toEqual(['GetObject']);bound=true;events.push('bind');return {...scope,rootDigest:fixture.capture.outputDigest};},
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
   if(request.hostname==='s3.'+scope.region+'.amazonaws.com'){
    expect(request.method).toBe('GET');expect(request.path).toBe('/'+env.MEM9_DECISION_ARTIFACT_BUCKET+'/decisions/prod/control-build/'+d.source.run.id+'/'+d.source.run.attempt+'/'+encoded.commitment.envelopeSha256+'.json');
    return {response:{statusCode:200,headers:{'content-length':String(encoded.bytes.length),'x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':env.MEM9_CI_EVIDENCE_KMS_KEY_ARN,'x-amz-server-side-encryption-bucket-key-enabled':'true'},body:Readable.from([encoded.bytes])}};
   }
   if(request.hostname==='api.ecr.'+scope.region+'.amazonaws.com'){
    const query=JSON.parse(request.body),action=request.headers['x-amz-target'].split('.').at(-1);let response;
    if(action==='BatchGetImage'){const digest=query.imageIds[0].imageDigest,bytes=await raw(digest);response={images:[{registryId:scope.account,repositoryName:scope.repositoryName,imageId:{imageDigest:digest},imageManifest:bytes.toString(),imageManifestMediaType:JSON.parse(bytes).mediaType}],failures:[]};}
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
  const host={env,cwd:root,async api(path){if(path.endsWith('/jobs?per_page=100'))return {total_count:1,jobs:[fixture.completedJob]};if(path==='actions/jobs/'+d.rawJob.id)return fixture.completedJob;if(path==='actions/runs/'+d.source.run.id+'/attempts/'+d.source.run.attempt)return d.rawRun;throw Error('UnallocatedGithubFixtureRead');},async readLog(id){expect(id).toBe(d.rawJob.id);return fixture.log;}};
  fixture.input={env,host,context:fixture.context,records:fixture.records,parameter:fixture.parameter,source:d.source,metadataReads,budgetedReads,guardImportAudit:fixture.guardImportAudit,sourceContext:d.sourceContext};
 },180000);
 afterAll(async()=>{try{await result?.close();if(allocation)try{fixture.run(['image','rm',allocation.tag]);}catch{}}finally{budgetedReads?.close();fixture?.close();}},120000);
 it.each(['copied-context','foreign-run','expired'])('rejects %s before the first capsule or graph acquisition',async defect=>{
  const input={...fixture.input};
  if(defect==='copied-context')input.context=structuredClone(input.context);
  if(defect==='foreign-run')input.source={...input.source,run:{...input.source.run,id:input.source.run.id+1}};
  if(defect==='expired')input.deadlineMs=Date.now()-1;
  await expect(prepareNonrootProductionControl(input)).rejects.toThrow();expect(events).toEqual([]);expect(reads).toEqual([]);expect(allocation).toBeUndefined();
 });
 it('runs completed capture -> binding -> owned download/load -> real prerequisites -> launches -> actual guard',async()=>{
  result=await prepareNonrootProductionControl(fixture.input);
  expect(events.slice(0,4)).toEqual(['GetObject','bind','allocate','BatchGetImage']);expect(events).not.toContain('unknown');expect(held).toBe(false);
  expect(result.authority).toBe(false);for(const key of ['scan','oldRoot','deploymentSource','phaseEvidence'])expect(result).not.toHaveProperty(key);
  expect(result.resources.allocation.handle).toBe(allocation.handle);expect(result.resources.loaded.tag).toBe(allocation.tag);
  const verification=result.base.controlVerification,sourceContext=result.base.sourceContext;
  expect(inspectNonrootControlPrerequisites(result.base.prerequisites,{controlVerification:verification,sourceContext}).record.cleanupConfirmed).toBe(true);
  const guard=inspectNonrootControlGuardTests(result.guardTests,{controlVerification:verification,sourceContext});expect(guard.record.cases).toHaveLength(5);
  expect(guard.record.cases.every(c=>c.cleanup.confirmed&&c.exitCode===1&&!c.credentialAccessBeforeGuard)).toBe(true);
  expect(()=>inspectNonrootControlGuardTests({...result.guardTests},{controlVerification:verification,sourceContext})).toThrow('NonrootGuardCaptureContextRequired');
  expect(reads.every(r=>r.responseHash)).toBe(true);expect(reads.filter(r=>r.action==='S3BlobGet').length).toBeGreaterThan(0);expect(totals.logicalBytes).toBeGreaterThan(0);expect(totals.uncompressedBytes).toBeGreaterThan(0);
 },180000);
 it('seals real ownership, retains it on close for LOCAL replay, then performs exact final cleanup',async()=>{
  expect(result).toBeDefined();const bundle={controlCache:result.controlCache};bundleRef={path:join(fixture.root,'bundle.json'),sha256:sha(JSON.stringify(bundle))};await writeFile(bundleRef.path,JSON.stringify(bundle),{mode:0o600,flag:'wx'});
  const resourceReceiptRef=await sealControlResources(allocation.handle,{bundleRef}),completion={version:2,kind:'ci-future-acquisition-complete',claimRef,bundleRef,resourceReceiptRef,ownerRefund:0,completedMs:Date.now()},completionRef={path:claimRef.path.replace('-claim.json','-complete.json'),sha256:sha(JSON.stringify(completion))};await writeFile(completionRef.path,JSON.stringify(completion),{mode:0o600,flag:'wx'});
  await linkControlResourceCompletion({env,resourceReceiptRef,completionRef});await result.close();expect((await readdir(result.controlCache.directory)).length).toBe(result.controlCache.inventory.nodes.length);
  const checked=await verifyControlResources({env,resourceReceiptRef,completionRef});expect(checked.docker.tag).toBe(allocation.tag);
  const before=reads.length,replay=await verifyOwnedNonrootControlCache({directory:result.controlCache.directory,binding:result.resources.download.binding,inventory:result.controlCache.inventory,metadataReads});
  try{expect(controlImageGraphBinding(replay.graph).rootDigest).toBe(fixture.capture.outputDigest);}finally{await replay.close();}expect(reads).toHaveLength(before);
  await cleanupCiSmokeControlResources({env});await expect(lstat(result.controlCache.directory)).rejects.toMatchObject({code:'ENOENT'});expect(JSON.parse(await readFile(join(allocation.root,'cleanup-complete.json'),'utf8')).kind).toBe('ci-control-cleanup-complete');
 },120000);
});
