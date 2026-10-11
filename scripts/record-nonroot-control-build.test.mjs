import {beforeAll,it,expect,vi} from 'vitest';
import {mkdtemp,mkdir,readFile,rm,chmod,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {execFileSync} from 'node:child_process';
import {Readable} from 'node:stream';
import {nonrootDeploymentFixture} from './production-nonroot-provenance.fixture.mjs';
import {captureControlRecorderJob,completeControlRecorderJob,main} from './record-nonroot-control-build.mjs';
import {nonrootDeploymentWrapperFixture} from './production-nonroot-deployment.fixture.mjs';
import {nonrootBundleRecords} from './production-nonroot-bundle.fixture.mjs';
import {createNonrootDeploymentBundle} from './lib/production-image-deployment-bundle.mjs';
import {smokePrivateWrite} from './lib/ci-smoke-host.mjs';
import {controlSourcePaths,readControlSourceFile} from './lib/production-control-source.mjs';
import {readCompletedControlBuildCapture} from './lib/production-nonroot-deployment-provider.mjs';

let f;
beforeAll(async()=>{f=await nonrootDeploymentFixture();});
function fixture(){
 const run={...f.rawRun,status:'in_progress',conclusion:null};
 const job={...structuredClone(f.rawJob),status:'in_progress',conclusion:null,started_at:new Date(f.now-10000).toISOString(),completed_at:null,
  steps:[{number:1,name:f.job.steps[0].name,status:'completed',conclusion:'success',started_at:new Date(f.now-9000).toISOString(),completed_at:new Date(f.now-2000).toISOString()}]};
 const jobs={jobs:[job],total_count:1},calls=[];
 const log=`#9 exporting manifest list ${f.build.image.rootDigest}\n#9 exporting config ${f.build.image.configDigest}\n#9 DONE 1.0s\n`;
 const host={api:async path=>{calls.push(path);return path.includes('?per_page=100')?jobs:path.startsWith('actions/jobs/')?job:run;},readLog:async id=>{calls.push('logs/'+id);return log;}};
 const material={contract:f.contract,source:f.source,options:f.options()};
 const inputs={metadata:JSON.stringify({'containerimage.digest':f.build.image.rootDigest,'containerimage.config.digest':f.build.image.configDigest}),outputDigest:f.build.image.rootDigest,now:f.now};
 return {run,job,jobs,calls,host,material,inputs,log};
}
it('uses the named actual running job and preserves the action metadata bytes',async()=>{
 const x=fixture(),capture=await captureControlRecorderJob(x.host,x.material,x.inputs);
 expect(capture.job.id).toBe(f.rawJob.id);expect(capture.job.status).toBe('in_progress');
 expect(capture.metadata).toBe(x.inputs.metadata);
 expect(x.calls).toEqual(['actions/runs/201/attempts/1','actions/runs/201/attempts/1/jobs?per_page=100']);
});
it.each(['truncated','duplicate','missing','failed-action','wrong-attempt','wrong-digest'])('refuses %s without producing a capture',async defect=>{
 const x=fixture();
 if(defect==='truncated')x.jobs.total_count=2;
 if(defect==='duplicate'){x.jobs.jobs.push({...x.job});x.jobs.total_count=2;}
 if(defect==='missing')x.job.name='Other build';
 if(defect==='failed-action')x.job.steps[0].conclusion='failure';
 if(defect==='wrong-attempt')x.job.run_attempt++;
 if(defect==='wrong-digest')x.inputs.outputDigest='sha256:'+'f'.repeat(64);
 await expect(captureControlRecorderJob(x.host,x.material,x.inputs)).rejects.toThrow();
});
it('appends completed metadata from the captured job ID, without changing the earlier observation',async()=>{
 const x=fixture(),capture=await captureControlRecorderJob(x.host,x.material,x.inputs),original=JSON.stringify(capture);
 Object.assign(x.job,{status:'completed',conclusion:'success',completed_at:new Date(f.now+1000).toISOString()});
 const result=await completeControlRecorderJob(x.host,x.material,capture,{now:()=>f.now+2000});
 expect(result.buildLog.toString()).toBe(x.log);expect(result.completion.job.status).toBe('completed');
 expect(x.calls.slice(-3)).toEqual(['actions/runs/201/attempts/1','actions/jobs/202','logs/202']);
 expect(JSON.stringify(capture)).toBe(original);
});
it('rejects a different contract before any completion read',async()=>{
 const x=fixture(),capture=await captureControlRecorderJob(x.host,x.material,x.inputs);x.calls.length=0;
 await expect(completeControlRecorderJob(x.host,{...x.material,contract:{...x.material.contract,prNumber:999}},capture)).rejects.toThrow('NonrootControlRecorderContractChanged');
 expect(x.calls).toEqual([]);
});
it('validates the complete owned cleanup inventory before unlinking a capture',async()=>{
 const root=await mkdtemp(join(tmpdir(),'control-recorder-test-')),dir=join(root,'mem9-control-build');
 try{
  await mkdir(dir,{mode:0o700});await writeFile(join(dir,'capture.local.json'),'{}',{mode:0o600});await writeFile(join(dir,'foreign.json'),'{}',{mode:0o600});
  await expect(main({RUNNER_TEMP:root},['cleanup'])).rejects.toThrow('NonrootControlRecorderCleanupInventory');
  expect(await readFile(join(dir,'capture.local.json'),'utf8')).toBe('{}');
  await rm(join(dir,'foreign.json'));await chmod(join(dir,'capture.local.json'),0o644);
  await expect(main({RUNNER_TEMP:root},['cleanup'])).rejects.toThrow('CiSmokePrivateFile');
  await chmod(join(dir,'capture.local.json'),0o600);
  expect(await main({RUNNER_TEMP:root},['cleanup'])).toEqual({phase:'control-build-capture-removed'});
 }finally{await rm(root,{recursive:true,force:true});}
});
it('rejects unsupported CLI modes before host creation or any external read',async()=>{
 await expect(main({},['publish-raw'])).rejects.toThrow('NonrootControlRecorderArguments');
 await expect(main({},['complete'])).rejects.toThrow('NonrootControlRecorderArguments');
 await expect(main({},['capture','--skip-checks'])).rejects.toThrow('NonrootControlRecorderArguments');
});
it('publishes in one job and completes from private storage in a different job directory',async()=>{
 const g=await nonrootDeploymentWrapperFixture(),records=await nonrootBundleRecords(g);
 const root=await mkdtemp(join(tmpdir(),'control-recorder-flow-')),repo=join(root,'repo');let outputSpy;
 vi.useFakeTimers({toFake:['Date']});vi.setSystemTime(g.f.now);
 try{
  await mkdir(repo,{mode:0o700});
  for(const path of controlSourcePaths(g.d.sourceContext)){
   const target=join(repo,path);await mkdir(dirname(target),{recursive:true});
   await writeFile(target,(await readControlSourceFile(g.d.sourceContext,path)).bytes,{mode:0o644});
  }
  const git=args=>execFileSync('git',args,{cwd:repo,encoding:'utf8',stdio:['ignore','pipe','pipe']});
  git(['init','--quiet']);git(['add','.']);git(['-c','user.name=Fixture','-c','user.email=user@example.com','commit','--quiet','-m','test: synthetic source']);
  const bundle=await createNonrootDeploymentBundle({...records,context:g.authorization},g.d.source,g.parameter,{phase:'source',sourceReceiptHash:records.sourceReceiptHash,now:g.f.now});
  const file=join(root,'bundle.local.json'),digest=await smokePrivateWrite(file,bundle),source=g.d.source;
  const env={RUNNER_TEMP:root,STAGE:'prod',GITHUB_ACTIONS:'true',GITHUB_JOB:'build-image-transition-control',GITHUB_REPOSITORY:source.repository,
   GITHUB_SHA:source.checkout.sha,GITHUB_WORKFLOW_SHA:source.checkout.sha,GITHUB_EVENT_NAME:'push',GITHUB_REF:'refs/heads/main',GITHUB_RUN_ID:String(source.run.id),GITHUB_RUN_ATTEMPT:String(source.run.attempt),
   MEM9_IMAGE_TRANSITION_BUNDLE_FILE:file,MEM9_IMAGE_TRANSITION_BUNDLE_HASH:digest,MEM9_CI_SMOKE_SOURCE_RECEIPT_HASH:records.sourceReceiptHash};
  const job={...structuredClone(g.d.rawJob),status:'in_progress',conclusion:null,started_at:new Date(g.f.now-10000).toISOString(),completed_at:null,
   steps:[{number:1,name:g.d.job.steps[0].name,status:'completed',conclusion:'success',started_at:new Date(g.f.now+1000).toISOString(),completed_at:new Date(g.f.now+2000).toISOString()}]};
  const host={env,cwd:repo,run:async(_file,args)=>args[0]==='show'?[source.checkout.sha,source.checkout.tree,source.checkout.parents.join(' ')].join('\n'):git(args),api:async path=>{
   if(path.startsWith('commits/'))return {sha:source.checkout.sha,commit:{tree:{sha:source.checkout.tree}},parents:source.checkout.parents.map(sha=>({sha}))};
   if(path.startsWith('pulls/'))return {number:source.pullRequest.number,state:'closed',merged:true,head:{sha:source.pullRequest.headSha,repo:{full_name:source.repository}},base:{ref:'main'},merge_commit_sha:source.checkout.sha};
   if(path.endsWith('/jobs?per_page=100'))return {jobs:[job],total_count:1};
   return {...g.d.rawRun,head_repository:{full_name:source.repository}};
  }};
  expect(await main(env,['prepare'],{host})).toEqual({phase:'control-build-context-prepared'});
  vi.setSystemTime(g.f.now+3000);
  env.MEM9_CONTROL_BUILD_METADATA=JSON.stringify({'containerimage.digest':g.d.build.image.rootDigest,'containerimage.config.digest':g.d.build.image.configDigest});
  env.MEM9_EXPECTED_BOOTSTRAP_DIGEST=g.d.build.image.rootDigest;
  expect(await main(env,['capture'],{host})).toEqual({phase:'control-build-action-captured'});
  const captured=JSON.parse(await readFile(join(root,'mem9-control-build/capture.local.json'),'utf8'));
  expect(captured.job.status).toBe('in_progress');expect(captured.job.completed_at).toBeNull();expect(captured.outputDigest).toBe(g.d.build.image.rootDigest);
  await expect(main(env,['capture'],{host})).rejects.toThrow();
  const account=g.current.account,region=g.current.region,keyArn=`arn:aws:kms:${region}:${account}:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee`;
  Object.assign(env,{MEM9_DEPLOY_ROLE_ARN:`arn:aws:iam::${account}:role/github-actions-mem9-on-aws-prod`,MEM9_CI_EVIDENCE_KMS_KEY_ARN:keyArn,
   MEM9_CI_CREDENTIALS_EXPIRES:new Date(g.f.now+3600000).toISOString(),AWS_ACCESS_KEY_ID:'synthetic-access',AWS_SECRET_ACCESS_KEY:'synthetic-secret',AWS_SESSION_TOKEN:'synthetic-session',GITHUB_OUTPUT:join(root,'github-output')});
  const stored=new Map(),requestHandler={async handle(request){
   expect(request.method).toBe('PUT');expect(request.headers['if-none-match']).toBe('*');expect(request.headers['x-amz-expected-bucket-owner']).toBe(account);
   stored.set(request.path,Buffer.from(request.body));
   return {response:{statusCode:200,headers:{etag:'"synthetic-etag"','x-amz-checksum-sha256':request.headers['x-amz-checksum-sha256'],
    'x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':keyArn,'x-amz-server-side-encryption-bucket-key-enabled':'true'},body:Readable.from([])}};
  },destroy(){}};
  const printed=[];outputSpy=vi.spyOn(process.stdout,'write').mockImplementation(value=>{printed.push(String(value));return true;});
  expect(await main(env,['publish'],{host,requestHandler})).toEqual({phase:'control-build-capture-published'});
  outputSpy.mockRestore();outputSpy=undefined;
  expect(stored.size).toBe(1);const commitmentLine=printed.find(line=>line.startsWith('MEM9_CONTROL_BUILD_COMMITMENT '));expect(commitmentLine).toBeTruthy();
  expect(commitmentLine).not.toContain(account);expect(commitmentLine).not.toContain('arn:');
  expect(await main(env,['cleanup'])).toEqual({phase:'control-build-capture-removed'});
  await expect(readFile(join(root,'mem9-control-build/capture.local.json'))).rejects.toMatchObject({code:'ENOENT'});
  const consumer=join(root,'consumer');await mkdir(consumer,{mode:0o700});
  vi.setSystemTime(g.f.now+5000);Object.assign(job,{status:'completed',conclusion:'success',completed_at:new Date(g.f.now+4500).toISOString()});
  const consumerEnv={...env,RUNNER_TEMP:consumer,GITHUB_JOB:'deploy-prod'};
  const oldApi=host.api,consumerHost={...host,env:consumerEnv,api:async path=>path.startsWith('actions/jobs/')?job:oldApi(path),
   readLog:async()=>`#64 exporting manifest list ${g.d.build.image.rootDigest}\n#64 exporting manifest list ${g.d.build.image.rootDigest} 0.0s done\n#64 exporting config ${g.d.build.image.configDigest} 0.0s done\n#64 DONE 1.0s\n${commitmentLine}`};
  const read=vi.fn(async command=>{
   const {Bucket,Key,ExpectedBucketOwner}=command.input;expect(ExpectedBucketOwner).toBe(account);const bytes=stored.get('/'+Bucket+'/'+Key);expect(bytes).toBeTruthy();
   return {$metadata:{httpStatusCode:200},ContentLength:bytes.length,Body:Readable.from([bytes]),ServerSideEncryption:'aws:kms',SSEKMSKeyId:keyArn,BucketKeyEnabled:true};
  });
  const completed=await readCompletedControlBuildCapture({clients:{s3:{send:read}},env:consumerEnv,host:consumerHost,context:g.authorization,parameter:g.parameter,
   source:g.d.source,records,sourceContext:g.d.sourceContext});
  expect(read).toHaveBeenCalledTimes(1);expect(completed.capture).toEqual(captured);expect(completed.completion.job.status).toBe('completed');
  expect(completed.capture.job.completed_at).toBeNull();expect(completed.prepared.identity.runId).toBe(source.run.id);
 }finally{outputSpy?.mockRestore();vi.useRealTimers();await rm(root,{recursive:true,force:true});}
},30000);
