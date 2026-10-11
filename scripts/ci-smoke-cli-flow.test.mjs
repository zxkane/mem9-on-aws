import {describe,it,expect,beforeAll,beforeEach,afterEach,afterAll,vi} from 'vitest';
import {execFileSync} from 'node:child_process';
import {mkdtempSync,mkdirSync,readFileSync,writeFileSync,lstatSync,existsSync,rmSync,readdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {stringify,parse as yaml} from 'yaml';
import {EventEmitter} from 'node:events';
import {PassThrough,Readable} from 'node:stream';

// All CI identities, service responses and execution captures are synthetic.
// Git objects, filesystem operations, codecs and verifiers remain real.
const transport=vi.hoisted(()=>({current:null}));
vi.mock('./lib/ci-smoke-host.mjs',async importOriginal=>{
 const actual=await importOriginal();return {...actual,ciSmokeHost(env){
  const f=transport.current,h=actual.ciSmokeHost(env,f.repository);
  return {...h,run:async(file,args,options)=>file==='git'?h.run(file,args,options):f.external(file,args,options),api:path=>f.api(path),readLog:id=>f.log(id)};
 },smokeEnvironment:async(env,values)=>{transport.current.events.push('export-receipt');transport.current.atExport?.();return actual.smokeEnvironment(env,values);}};
});
vi.mock('node:child_process',async importOriginal=>{
 const actual=await importOriginal();return {...actual,spawnSync(file,args,options){if(file==='docker')return transport.current.dockerSync(args);return actual.spawnSync(file,args,options);},spawn(file,args,options){if(file==='docker')return transport.current.dockerSpawn(args);return actual.spawn(file,args,options);}};
});
vi.mock('./lib/ci-smoke-private-archive.mjs',async importOriginal=>{
 const actual=await importOriginal();return {...actual,putCiSmokeEnvelope:(encoded,options)=>actual.putCiSmokeEnvelope(encoded,{...options,requestHandler:transport.current.s3}),getCiSmokeEnvelope:(commitment,options)=>actual.getCiSmokeEnvelope(commitment,{...options,requestHandler:transport.current.s3})};
});
vi.mock('./lib/ci-smoke-session.mjs',async importOriginal=>{
 const actual=await importOriginal();return {...actual,withCiSmokeReadSession:(input,use)=>actual.withCiSmokeReadSession(input,async context=>{
  transport.current.credentials=context.credentials;transport.current.signal=context.signal;return use(context);
 },{now:()=>transport.current.clock,requestHandler:transport.current.reader})};
});

import {main} from './verify-ci-smoke-isolation.mjs';
import {CI_SMOKE_POLICY} from './lib/ci-smoke-policy.mjs';
import {buildCiSmokePromotionRoutes,buildCiSmokeImageJob,buildCiSmokeSourceJobs} from './lib/ci-smoke-isolation.mjs';
import {ciSmokeJobDefinition} from './lib/ci-smoke-job.mjs';
import {NONROOT_SMOKE_DATABASE_IMAGE} from './run-mnemo-nonroot-smoke.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';

const ROOT=fileURLToPath(new URL('..',import.meta.url)),BASE=1700000000000;
const sha=raw=>createHash('sha256').update(raw).digest('hex');
const account='123456789012',region='us-east-1',repoName='example/control-plane';
const workflowPath='.github/workflows/infra-ci.yml',modes=new Map(),blobCache=new Map();
let repository,fixtureRoot,origin,candidate,merge,files,workflow,stdout,clockSpy;
const git=(args,input)=>execFileSync('git',['-c','core.hooksPath=/dev/null',...args],{cwd:repository,input,env:{...process.env,GIT_CONFIG_GLOBAL:'/dev/null',GIT_CONFIG_NOSYSTEM:'1'},maxBuffer:32*1024*1024,stdio:['pipe','pipe','pipe']});
function commit(snapshot,parents=[]){
 git(['read-tree','--empty']);const rows=[];
 for(const [path,bytes]of snapshot){const digest=sha(bytes);let oid=blobCache.get(digest);if(!oid){oid=git(['hash-object','-w','--stdin'],bytes).toString().trim();blobCache.set(digest,oid);}rows.push((modes.get(path)??'100644')+' '+oid+'\t'+path+'\n');}
 git(['update-index','--index-info'],rows.join(''));const tree=git(['write-tree']).toString().trim();
 const revision=git(['-c','user.name=Synthetic fixture','-c','user.email=user@example.com','commit-tree',tree,...parents.flatMap(p=>['-p',p.revision]),'-m','Synthetic CI source fixture']).toString().trim();
 return {revision,tree,parents:parents.map(p=>({sha:p.revision}))};
}
function sourceRepo(){
 const fixed=JSON.parse(readFileSync(join(ROOT,'scripts/fixtures/ci-smoke-baseline.json')));files=new Map();
 const names=execFileSync('git',['ls-files','--cached','--others','--exclude-standard','-z'],{cwd:ROOT,maxBuffer:32*1024*1024}).toString().split('\0').filter(Boolean);
 for(const name of new Set(names)){if(name.includes('.local.')||name==='.local.json'||name==='.env')continue;const path=join(ROOT,name),stat=lstatSync(path);if(!stat.isFile())continue;files.set(name,readFileSync(path));modes.set(name,stat.mode&0o111?'100755':'100644');}
 const recovery=[...new Map(CI_SMOKE_POLICY.rows.filter(r=>r.rule.kind==='safe-recovery').flatMap(r=>r.rule.entryFiles).map(p=>[p.path,p])).values()];
 for(const pin of recovery){let bytes=files.get(pin.path);if(sha(bytes)!==pin.sha256||bytes.length!==pin.bytes)bytes=execFileSync('git',['show','HEAD:'+pin.path],{cwd:ROOT,maxBuffer:16*1024*1024});expect(sha(bytes)).toBe(pin.sha256);files.set(pin.path,bytes);}
 workflow={jobs:{...fixed.workflow.jobs}};const steps=[{uses:'docker/setup-qemu-action@'+'a'.repeat(40)},{uses:'docker/setup-buildx-action@'+'b'.repeat(40)}];
 for(const name of ['mnemo-server','qwen3-embed','llm-proxy']){
  files.set('docker/'+name+'/Dockerfile',Buffer.from('FROM node:24-alpine AS runtime\nCOPY docker/'+name+'/fixture.mjs /app/fixture.mjs\n'));files.set('docker/'+name+'/fixture.mjs',Buffer.from('export const fixture=true;\n'));
  steps.push({name:name==='mnemo-server'?'Build & push mnemo-server (arm64)':'Build '+name,uses:'docker/build-push-action@'+'c'.repeat(40),with:{context:'.',file:'docker/'+name+'/Dockerfile',platforms:'linux/arm64',pull:true,'no-cache-filters':name==='mnemo-server'?'builder,runtime':'runtime'}});
 }
 steps.push({name:'Smoke test mnemo-server EMF framing (non-TTY)',if:"steps.gate.outputs.skip != 'true'",run:'bash scripts/run-mnemo-emf-smoke.sh'});
 workflow.jobs['build-and-push-image']={if:fixed.workflow.jobs['build-and-push-image'].if,'runs-on':ciSmokeJobDefinition()['runs-on'],outputs:{},steps};files.set(workflowPath,Buffer.from(stringify(workflow)));
 for(const [path,action]of Object.entries(fixed.actions))if(!recovery.some(p=>p.path===path))files.set(path,Buffer.from(stringify(action)));
 origin=commit(files);
 const changed=buildCiSmokePromotionRoutes({workflow,actions:fixed.actions});Object.assign(workflow.jobs,changed.jobs,buildCiSmokeSourceJobs(workflow));workflow.jobs['mnemo-nonroot-smoke']=ciSmokeJobDefinition();
 workflow.jobs['build-and-push-image']=buildCiSmokeImageJob(workflow);
 files.set(workflowPath,Buffer.from(stringify(workflow)));files.set('.github/actions/runtime-cutover/action.yml',Buffer.from(stringify(changed.actions['.github/actions/runtime-cutover/action.yml'])));
 candidate=commit(files,[origin]);merge=commit(files,[origin,candidate]);git(['reset','--hard',merge.revision]);
}
function imageMetadata(role){
 const config=Buffer.from(JSON.stringify({architecture:'arm64',os:'linux',config:{Labels:{synthetic:role}}})+'\n');
 const manifest=Buffer.from(JSON.stringify({schemaVersion:2,mediaType:'application/vnd.oci.image.manifest.v1+json',config:{mediaType:'application/vnd.oci.image.config.v1+json',digest:'sha256:'+sha(config),size:config.length},layers:[]})+'\n');
 const root=Buffer.from(JSON.stringify({schemaVersion:2,mediaType:'application/vnd.oci.image.index.v1+json',manifests:[{mediaType:'application/vnd.oci.image.manifest.v1+json',digest:'sha256:'+sha(manifest),size:manifest.length,platform:{os:'linux',architecture:'arm64'}}]})+'\n');
 const rootDigest='sha256:'+sha(root);return {qualifiedImage:account+'.dkr.ecr.'+region+'.amazonaws.com/mem9-on-aws/preview/mnemo-server@'+rootDigest,rootDigest,arm64Digest:'sha256:'+sha(manifest),configDigest:'sha256:'+sha(config),bytes:{root,manifest,config}};
}
function setup(){
 const directory=mkdtempSync(join(tmpdir(),'ci-smoke-flow-run-')),server=imageMetadata('server');
 const env={PATH:process.env.PATH,GIT_CONFIG_GLOBAL:'/dev/null',GIT_CONFIG_NOSYSTEM:'1',GITHUB_ACTIONS:'true',GITHUB_SERVER_URL:'https://github.com',GITHUB_REPOSITORY:repoName,GITHUB_SHA:merge.revision,GITHUB_REF:'refs/pull/7/merge',GITHUB_RUN_ID:'100',GITHUB_RUN_ATTEMPT:'1',GITHUB_JOB:'mnemo-nonroot-smoke',STAGE:'pr-7',PR_NUMBER:'7',RUNNER_TEMP:directory,AWS_REGION:region,
  MNEMO_DIGEST:server.rootDigest,MEM9_DEPLOY_ROLE_ARN:'arn:aws:iam::'+account+':role/github-actions-mem9-on-aws-preview',MEM9_DECISION_ARTIFACT_BUCKET:'example-ci-smoke-evidence',MEM9_CI_EVIDENCE_KMS_KEY_ARN:'arn:aws:kms:'+region+':'+account+':key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',MEM9_CI_SMOKE_LINEAGE:JSON.stringify({originRevision:origin.revision,originTree:origin.tree,baselineRevision:origin.revision,baselineTree:origin.tree}),GITHUB_ENV:join(directory,'github-env'),GITHUB_OUTPUT:join(directory,'github-output'),
  ACTIONS_ID_TOKEN_REQUEST_URL:'https://pipelines.actions.githubusercontent.com/synthetic_scope/_apis/distributedtask/hubs/build/plans/00000000-0000-4000-8000-aaaaaaaaaaaa/jobs/00000000-0000-4000-8000-bbbbbbbbbbbb/idtoken?api-version=2.0',ACTIONS_ID_TOKEN_REQUEST_TOKEN:'synthetic-request-token'};
 writeFileSync(env.GITHUB_ENV,'',{mode:0o600});writeFileSync(env.GITHUB_OUTPUT,'',{mode:0o600});
 const success={status:'completed',conclusion:'success'},common={run_id:100,run_attempt:1,head_sha:candidate.revision};
 const f={repository,directory,server,env,events:[],clock:BASE-10,run:{id:100,run_attempt:1,path:workflowPath,event:'pull_request',head_sha:candidate.revision,head_repository:{full_name:repoName},status:'in_progress',conclusion:null},
  build:{...common,...success,id:101,name:'Build & push workload images',started_at:new Date(BASE-2000).toISOString(),completed_at:new Date(BASE-1000).toISOString(),steps:[{...success,name:'Build & push mnemo-server (arm64)'}]},
  smoke:{...common,id:102,name:'Mnemo nonroot smoke',status:'in_progress',conclusion:null,started_at:new Date(BASE-100).toISOString(),completed_at:null,steps:[]},
  deploy:{...common,id:103,name:workflow.jobs['deploy-preview'].name,status:'queued',conclusion:null,started_at:null,completed_at:null}};
 f.api=async path=>{f.events.push('github:'+path);if(path==='actions/runs/100/attempts/1')return structuredClone(f.run);if(path==='actions/runs/100/attempts/1/jobs?per_page=100')return structuredClone({total_count:3,jobs:[f.build,f.smoke,f.deploy]});if(path.startsWith('commits/')){const found=[origin,candidate,merge].find(c=>path==='commits/'+c.revision);if(found)return {sha:found.revision,commit:{tree:{sha:found.tree}},parents:found.parents};}throw Error('Unexpected synthetic GitHub read '+path);};
 f.log=async id=>{f.events.push('github-log:'+id);if(id===101)return '#12 pushing manifest for '+server.qualifiedImage.split('@')[0]+':pr-'+merge.revision.slice(0,7)+'@'+server.rootDigest+' 0.1s done\n';if(id===102)return f.publishLog;throw Error('Unexpected job log');};
 f.external=async(file,args)=>{f.events.push(file+':'+args[0]);if(file==='docker'&&args[0]==='pull')return '';throw Error('Unexpected external command');};
 f.dockerSync=()=>{throw Error('Docker fixture not installed');};f.dockerSpawn=()=>{throw Error('Docker fixture not installed');};
 return f;
}
beforeAll(()=>{fixtureRoot=mkdtempSync(join(tmpdir(),'ci-smoke-flow-git-'));repository=join(fixtureRoot,'repository');mkdirSync(repository);git(['init','--quiet']);sourceRepo();},60000);
beforeEach(()=>{transport.current=setup();clockSpy=vi.spyOn(Date,'now').mockImplementation(()=>transport.current.clock);stdout=vi.spyOn(process.stdout,'write').mockImplementation(()=>true);});
afterEach(()=>{stdout?.mockRestore();clockSpy?.mockRestore();if(transport.current)rmSync(transport.current.directory,{recursive:true,force:true});transport.current=null;});
afterAll(()=>{if(fixtureRoot)rmSync(fixtureRoot,{recursive:true,force:true});});

describe('actual CI smoke main with synthetic transports',()=>{
 it('prepares authentic Git-backed source snapshots before credentials or producer execution',async()=>{
  const f=transport.current;await expect(main(['prepare-smoke'],f.env)).resolves.toEqual({phase:'smoke-source-prepared'});
  const directory=join(f.directory,'mem9-ci-smoke-state'),precheck=JSON.parse(readFileSync(join(directory,'precheck.json'))),source=JSON.parse(readFileSync(join(directory,'source.json')));
  expect(precheck.checkout).toEqual({revision:merge.revision,tree:merge.tree});expect(source.isolation.candidate.revision).toBe(candidate.revision);expect(precheck.provenance.smokeJob.completed_at).toBeNull();expect(precheck.provenance.smokeJob.status).toBe('in_progress');
  expect(lstatSync(join(directory,'precheck.json')).mode&0o777).toBe(0o600);expect(lstatSync(directory).mode&0o777).toBe(0o700);expect(f.events.every(e=>e.startsWith('github'))).toBe(true);
 },60000);
});
