import {mkdir,readdir,unlink,rmdir,lstat,readFile,appendFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {parseDocument} from 'yaml';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {parseCiSmokeJson,inspectCiSmokeRecord,validateCiSmokeProducedEvidence} from './lib/ci-smoke-evidence.mjs';
import {CI_SMOKE_POLICY} from './lib/ci-smoke-policy.mjs';
import {CI_SMOKE_ROUTES,CI_SMOKE_JOB_NAME,verifyArchivedCiSmoke} from './lib/ci-smoke-isolation.mjs';
import {captureCiSmokeGithub} from './lib/ci-smoke-github.mjs';
import {ciSmokeHost,smokeHash as sha,smokeNeed as need,smokePrivateRead,smokePrivateWrite,smokeDirectory,removeSmokeDirectory,smokeEnvironment,captureSmokeTree} from './lib/ci-smoke-host.mjs';
import {CI_SMOKE_ARCHIVE_LIMITS,inspectCiSmokeCommitment,encodeCiSmokeEnvelope,decodeCiSmokeEnvelope,ciSmokeArchiveKey,ciSmokeArchiveLocation,putCiSmokeEnvelope,getCiSmokeEnvelope} from './lib/ci-smoke-private-archive.mjs';
import {NONROOT_SMOKE_DATABASE_IMAGE,createCiSmokeProducerInput,expectedCiSmokeCommandCatalog} from './run-mnemo-nonroot-smoke.mjs';
import {localImageMetadata} from './lib/mnemo-nonroot-smoke-helper.mjs';
import {assertPreviewPhaseOperation} from './lib/production-nonroot-preview-operations.mjs';

const modes=new Set(['prepare-smoke','acquire-smoke','publish-smoke','cleanup-smoke','source','source-precheck','guard','composite','target','cleanup-source']);
const extraSourceRoutes=['verify-production-image-transition','build-image-transition-control'];
const phases=['preupdate','preconfigure','presst','prereadiness'];
const git=v=>typeof v==='string'&&/^[a-f0-9]{40}$/.test(v),hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const identityKeys=['repository','runId','runAttempt','workflowPath','sourceRevision','sourceTree','buildJobId','smokeJobId','stepId','outputDigest','qualifiedImage','arm64Digest','configDigest'];
const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join(),'CiSmokeFields');
const parse=raw=>parseCiSmokeJson(Buffer.from(raw).toString('utf8'));
const readJson=async path=>parse(await smokePrivateRead(path));
const ownIdentity=env=>({repository:env.GITHUB_REPOSITORY,runId:Number(env.GITHUB_RUN_ID),runAttempt:Number(env.GITHUB_RUN_ATTEMPT),job:env.GITHUB_JOB,revision:env.GITHUB_SHA});

export function parseSmokeArguments(args){
 need(Array.isArray(args)&&modes.has(args[0]),'CiSmokeArguments');const result={mode:args[0]},allowed=new Set(['--route','--phase','--step','--call-path']);
 for(let i=1;i<args.length;i+=2){need(allowed.has(args[i])&&typeof args[i+1]==='string'&&args[i+1].length>0&&args[i+1].length<=512&&!Object.hasOwn(result,args[i].slice(2)),'CiSmokeArguments');result[args[i].slice(2)]=args[i+1];}
 const keys={source:['mode','route'],'source-precheck':['mode','route'],guard:['mode','route','phase','step'],composite:['mode','route','phase','call-path'],target:['mode','route','phase']};
 exact(result,keys[result.mode]??['mode']);
 if(result.route)need(CI_SMOKE_ROUTES.includes(result.route)||['source','source-precheck'].includes(result.mode)&&extraSourceRoutes.includes(result.route),'CiSmokeRoute');
 if(result.phase)need(result.mode==='composite'?['all','prepare','finish'].includes(result.phase):phases.includes(result.phase)||result.mode==='guard'&&result.phase==='source','CiSmokePhase');
 return result;
}
export function parseSmokeLineage(raw){
 const v=parse(raw??'');exact(v,['originRevision','originTree','baselineRevision','baselineTree']);need(Object.values(v).every(git),'CiSmokeLineage');return v;
}
export function extractSmokeCommitment(log){
 need(typeof log==='string'&&Buffer.byteLength(log)<=8388608,'CiSmokeCommitmentLog');const values=[];
 for(const raw of log.split('\n')){
  const line=raw.replace(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z\s+/,''),prefix='MEM9_CI_SMOKE_COMMITMENT ';
  if(line.startsWith(prefix))values.push(inspectCiSmokeCommitment(parse(line.slice(prefix.length))));
 }
 need(values.length===1,'CiSmokeCommitmentAmbiguous');return values[0];
}
export function smokeArchiveConfig(env,stage,commitment){
 const roleArn=env.MEM9_CI_EVIDENCE_ROLE_ARN??env.MEM9_DEPLOY_ROLE_ARN;
 const role=/^arn:aws:iam::([0-9]{12}):role\/(?:[^/]+\/)*(github-actions-mem9-on-aws-(?:preview|prod))$/.exec(roleArn??'');
 need(role&&/^(?:prod|pr-[1-9][0-9]*)$/.test(stage)&&/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(env.AWS_REGION??''),'CiSmokeArchiveConfiguration');
 // A production reader may consume its verified PR source evidence. The role
 // stays scoped to the current job; the object stage comes from that source CI.
 const account=role[1],bucket=env.MEM9_DECISION_ARTIFACT_BUCKET||'mem9-audit-'+account,bucketArn='arn:aws:s3:::'+bucket;
 return ciSmokeArchiveLocation({stage,account,region:env.AWS_REGION,bucket,bucketArn,objectArn:bucketArn+'/'+ciSmokeArchiveKey(stage,commitment),roleArn,
  encryption:{algorithm:'aws:kms',keyArn:env.MEM9_CI_EVIDENCE_KMS_KEY_ARN,bucketKeyEnabled:true}},commitment);
}
function archiveInput(scope){return Object.fromEntries(['stage','account','region','bucket','bucketArn','objectArn','roleArn','encryption'].map(k=>[k,scope[k]]));}
class Objects{
 constructor(){this.objects=new Map();this.total=0;}
 bytes(value){const raw=Buffer.from(value),key=sha(raw);need(raw.length<=8388608,'CiSmokeObjectLimit');if(!this.objects.has(key)){this.total+=raw.length;need(this.total<=33554432&&this.objects.size<4096,'CiSmokeArchiveLimit');this.objects.set(key,raw);}return {sha256:key,bytesLength:raw.length};}
 json(value){const raw=Buffer.from(JSON.stringify(value)),b=this.bytes(raw);return {bytesHash:b.sha256,bytesLength:b.bytesLength,canonicalHash:hash(value)};}
 get(key){need(this.objects.has(key),'CiSmokeObjectMissing');return this.objects.get(key);}
 async save(directory){await mkdir(join(directory,'objects'),{mode:0o700});for(const[key,raw]of this.objects)await smokePrivateWrite(join(directory,'objects',key+'.bin'),raw);}
 async load(directory){for(const name of await readdir(join(directory,'objects'))){need(/^[a-f0-9]{64}\.bin$/.test(name),'CiSmokeObjectName');const raw=await smokePrivateRead(join(directory,'objects',name));need(sha(raw)+'.bin'===name,'CiSmokeObjectHash');this.bytes(raw);}return this;}
 rows(){return [...this.objects].map(([sha256,bytes])=>({sha256,bytes}));}
}
async function freshCheckout(host,expected){const value=await host.checkout();need(hash(value)===hash(expected),'CiSmokeCheckoutChanged');return value;}
async function currentJob(host){
 const list=await host.api('actions/runs/'+host.env.GITHUB_RUN_ID+'/attempts/'+host.env.GITHUB_RUN_ATTEMPT+'/jobs?per_page=100');
 need(Array.isArray(list.jobs)&&list.jobs.length===list.total_count,'CiSmokeCurrentJobsIncomplete');
 const workflow=parseDocument(await host.run('git',['show','HEAD:.github/workflows/infra-ci.yml'])).toJS();
 const definition=workflow.jobs?.[host.env.GITHUB_JOB];need(definition,'CiSmokeCurrentJobMissing');
 const name=definition.name.replace('${{ inputs.runtime_stage }}',host.env.STAGE??'');need(!name.includes('${{'),'CiSmokeCurrentJobName');
 const matches=list.jobs.filter(j=>j.name===name&&j.status==='in_progress');need(matches.length===1,'CiSmokeCurrentJobAmbiguous');
 const startedMs=Date.parse(matches[0].started_at),duration=definition['timeout-minutes'];
 need(Number.isSafeInteger(startedMs)&&Number.isInteger(duration)&&duration>0&&duration<=360,'CiSmokeCurrentJobTime');
 const expiresMs=startedMs+duration*60000;need(Date.now()<expiresMs,'CiSmokeCurrentJobExpired');return {id:matches[0].id,startedMs,expiresMs};
}

async function prepareSmoke(host){
 const env=host.env;need(env.GITHUB_JOB==='mnemo-nonroot-smoke','CiSmokeProducerJob');
 const checkout=await host.checkout(),lineage=parseSmokeLineage(env.MEM9_CI_SMOKE_LINEAGE),store=new Objects();
 const provenance=await captureCiSmokeGithub(host,{repository:env.GITHUB_REPOSITORY,runId:Number(env.GITHUB_RUN_ID),runAttempt:Number(env.GITHUB_RUN_ATTEMPT),sourceRevision:checkout.revision,purpose:'prepare'});
 need(provenance.sourceTree===checkout.tree&&provenance.buildDigest===env.MNEMO_DIGEST,'CiSmokeProducerSource');
 const origin=await captureSmokeTree(host,{revision:lineage.originRevision,tree:lineage.originTree},store);
 const candidate=await captureSmokeTree(host,{revision:provenance.candidateCommit.sha,tree:checkout.tree},store);
 const baseline=await captureSmokeTree(host,{revision:lineage.baselineRevision,tree:lineage.baselineTree},store);
 const {createCiSmokeIsolationRecord}=await import('./lib/ci-smoke-source-record.mjs');
 const source=await createCiSmokeIsolationRecord({origin:{revision:lineage.originRevision,context:origin.context},candidate:{revision:provenance.candidateCommit.sha,context:candidate.context},baseline:{revision:lineage.baselineRevision,context:baseline.context},databaseImage:NONROOT_SMOKE_DATABASE_IMAGE.qualifiedImage});
 await freshCheckout(host,checkout);const job=await currentJob(host),directory=await smokeDirectory(env,'mem9-ci-smoke-state',{create:true});
 const material={origin:store.json(origin.snapshot()),candidate:store.json(candidate.snapshot()),baseline:store.json(baseline.snapshot())};
 await smokePrivateWrite(join(directory,'source.json'),{...source,material});await store.save(directory);
 await smokePrivateWrite(join(directory,'precheck.json'),{version:1,kind:'ci-smoke-build-precheck',current:ownIdentity(env),checkout,lineage,provenance,job,stage:env.STAGE});
 return {phase:'smoke-source-prepared'};
}
async function producerState(host){
 const directory=await smokeDirectory(host.env,'mem9-ci-smoke-state'),precheck=await readJson(join(directory,'precheck.json'));
 need(precheck.version===1&&precheck.kind==='ci-smoke-build-precheck'&&hash(precheck.current)===hash(ownIdentity(host.env))&&Date.now()<precheck.job.expiresMs,'CiSmokeProducerPrecheck');
 await freshCheckout(host,precheck.checkout);return {directory,precheck,source:await readJson(join(directory,'source.json'))};
}
async function acquireSmoke(host){
 const {precheck,source}=await producerState(host),env=host.env;
 const account=/^arn:aws:iam::([0-9]{12}):role\//.exec(env.MEM9_DEPLOY_ROLE_ARN??'')?.[1];need(account&&env.AWS_REGION,'CiSmokeProducerAccount');
 const namespace=precheck.provenance.run.event==='pull_request'?'mem9-on-aws/preview':'mem9-on-aws';
 const qualifiedImage=`${account}.dkr.ecr.${env.AWS_REGION}.amazonaws.com/${namespace}/mnemo-server@${precheck.provenance.buildDigest}`;
 // Pull only the authenticated action digest. These are host registry
 // operations; no cloud credentials are forwarded into the smoke containers.
 for(const image of [qualifiedImage,NONROOT_SMOKE_DATABASE_IMAGE.qualifiedImage])await host.run('docker',['pull','--platform','linux/arm64',image],{timeoutMs:180000,maxBytes:8388608});
 const local=await localImageMetadata(qualifiedImage),server=Object.fromEntries(['qualifiedImage','rootDigest','arm64Digest','configDigest'].map(k=>[k,local[k]]));
 const identity={repository:env.GITHUB_REPOSITORY,runId:Number(env.GITHUB_RUN_ID),runAttempt:Number(env.GITHUB_RUN_ATTEMPT),workflowPath:'.github/workflows/infra-ci.yml',sourceRevision:precheck.checkout.revision,sourceTree:precheck.checkout.tree,
  buildJobId:precheck.provenance.buildJob.id,smokeJobId:precheck.provenance.smokeJob.id,stepId:'mnemo',outputDigest:server.rootDigest,qualifiedImage:server.qualifiedImage,arm64Digest:server.arm64Digest,configDigest:server.configDigest};
 const input=createCiSmokeProducerInput({identity,isolationHash:hash(source.isolation),images:{server,database:NONROOT_SMOKE_DATABASE_IMAGE}});
 await freshCheckout(host,precheck.checkout);await smokePrivateWrite(join(env.RUNNER_TEMP,'mem9-ci-smoke-input.json'),input);return {phase:'smoke-images-acquired'};
}
function producedExpected(result,observations,commandBindings,catalog){
 const identity=Object.fromEntries(identityKeys.map(k=>[k,result[k]]));
 need(hash(observations.images)===hash(commandBindings.images)&&observations.invocationId===commandBindings.invocationId,'CiSmokeProducerBindings');
 return {...observations,identity,isolationHash:result.isolationHash,commandCatalog:expectedCiSmokeCommandCatalog({catalog,bindings:commandBindings})};
}
function assertProducerClosure(observations,isolation){
 const sorted=files=>[...files].sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
 need(hash(sorted(observations.sourceFiles))===hash(sorted(isolation.smoke.closure)),'CiSmokeProducerClosureIncomplete');
}
export function imageMetadataRefs(images,store){
 return Object.fromEntries(['server','database'].map(role=>{
  const image=images[role],reference=digest=>{const raw=store.objects.get(digest.slice(7));return raw?{sha256:sha(raw),bytesLength:raw.length}:null;};
  const manifest=reference(image.arm64Digest),config=reference(image.configDigest);need(manifest&&config,'CiSmokeImageMetadataMissing');
  return [role,{root:reference(image.rootDigest),manifest,config}];
 }));
}
export async function verifyImageMetadataRefs(refs,images,readBytes){
 exact(refs,['server','database']);
 for(const role of ['server','database']){
  const r=refs[role],image=images[role];exact(r,['root','manifest','config']);
  need(r.manifest.sha256===image.arm64Digest.slice(7)&&r.config.sha256===image.configDigest.slice(7),'CiSmokeImageMetadataDigest');
  const manifest=parse(await readBytes(r.manifest)),config=parse(await readBytes(r.config));
  need(manifest.schemaVersion===2&&manifest.config?.digest===image.configDigest&&config.os==='linux'&&config.architecture==='arm64','CiSmokeImageMetadataBinding');
  if(r.root!==null){
   inspectCiSmokeRecord('ByteRef',r.root);
   need(r.root.sha256===image.rootDigest.slice(7),'CiSmokeImageMetadataDigest');const root=parse(await readBytes(r.root));
   need(image.rootDigest===image.arm64Digest||root.manifests?.some(m=>m.digest===image.arm64Digest&&m.platform?.os==='linux'&&m.platform.architecture==='arm64'),'CiSmokeImageMetadataBinding');
  }
 }
}
function completedExpected(produced,provenance){
 const job=raw=>({id:raw.id,runId:raw.run_id,runAttempt:raw.run_attempt,sourceRevision:provenance.sourceRevision,status:raw.status,conclusion:raw.conclusion,startedMs:Date.parse(raw.started_at),completedMs:Date.parse(raw.completed_at)});
 return {...produced,buildJob:job(provenance.buildJob),smokeJob:job(provenance.smokeJob)};
}
async function publishSmoke(host){
 const {directory,precheck,source}=await producerState(host),env=host.env,store=await new Objects().load(directory);
 const output=join(env.RUNNER_TEMP,'mem9-ci-smoke-evidence');
 const state=await lstat(output);need(state.isDirectory()&&!state.isSymbolicLink()&&state.uid===process.getuid()&&(state.mode&0o777)===0o700,'CiSmokeProducerOutput');
 const result=await readJson(join(output,'result.json')),observations=await readJson(join(output,'producer-observations.json')),commandBindings=await readJson(join(output,'command-bindings.json')),catalog=await readJson(join(output,'command-catalog.json'));
 need(result.sourceRevision===precheck.checkout.revision&&result.sourceTree===precheck.checkout.tree&&result.smokeJobId===precheck.provenance.smokeJob.id&&result.isolationHash===hash(source.isolation),'CiSmokePublishIdentity');
 for(const name of await readdir(join(output,'objects'))){need(/^[a-f0-9]{64}\.bin$/.test(name),'CiSmokeObjectName');const raw=await smokePrivateRead(join(output,'objects',name));need(sha(raw)+'.bin'===name,'CiSmokeObjectHash');store.bytes(raw);}
 const expected=producedExpected(result,observations,commandBindings,catalog);
 assertProducerClosure(observations,source.isolation);
 await validateCiSmokeProducedEvidence(result,{readJson:ref=>store.get(ref.bytesHash),readBytes:ref=>store.get(ref.sha256),expected,now:Date.now()});
 const material={version:1,kind:'ci-smoke-source-material',...source.material,provenance:store.json(precheck.provenance),expected:store.json(expected)};
 const imageMetadata=imageMetadataRefs(observations.images,store);await verifyImageMetadataRefs(imageMetadata,observations.images,async ref=>store.get(ref.sha256));
 const sourceRecord={version:1,kind:'ci-smoke-source-capture',originRecipe:source.originRecipe,candidateRecipe:source.candidateRecipe,material,imageMetadata};
 const records={result:store.json(result),source:store.json(sourceRecord),isolation:store.json(source.isolation),observations:store.json(observations),commandBindings:store.json(commandBindings),commandCatalog:store.json(catalog)};
 const encoded=encodeCiSmokeEnvelope({records,objects:store.rows()}),config=archiveInput(smokeArchiveConfig(env,precheck.stage,encoded.commitment));
 const {parseConfiguredAwsExpiration}=await import('./lib/ci-smoke-session.mjs');
 const expiration=parseConfiguredAwsExpiration(env.MEM9_CI_CREDENTIALS_EXPIRES,Date.now());
 const credentials={accessKeyId:env.AWS_ACCESS_KEY_ID,secretAccessKey:env.AWS_SECRET_ACCESS_KEY,sessionToken:env.AWS_SESSION_TOKEN,expiration};
 await freshCheckout(host,precheck.checkout);
 await smokePrivateWrite(join(directory,'put-intent.json'),{version:1,kind:'ci-smoke-private-put-intent',commitment:encoded.commitment,key:ciSmokeArchiveKey(precheck.stage,encoded.commitment),startedMs:Date.now()});
 const receipt=await putCiSmokeEnvelope(encoded,{config,credentials,expected,deadlineMs:Math.min(precheck.job.expiresMs,expiration.getTime(),Date.now()+900000)});
 await smokePrivateWrite(join(directory,'put-result.json'),receipt);
 if(env.GITHUB_OUTPUT)await appendFile(env.GITHUB_OUTPUT,'commitment='+JSON.stringify(receipt.commitment)+'\n');
 process.stdout.write('MEM9_CI_SMOKE_COMMITMENT '+JSON.stringify(receipt.commitment)+'\n');return {phase:'smoke-evidence-preserved'};
}

async function sourceCandidate(host,route,checkout){
 const env=host.env,preview=route==='deploy-preview'||route==='runtime-cutover-preview';let pr;
 if(preview){
  const number=/^pr-([1-9][0-9]*)$/.exec(env.STAGE??'')?.[1]??env.PR_NUMBER??/^refs\/pull\/([1-9][0-9]*)\/merge$/.exec(env.GITHUB_REF??'')?.[1];
  need(/^[1-9][0-9]*$/.test(number??''),'CiSmokeSourcePullRequest');pr=await host.api('pulls/'+number);
  need(pr.state==='open'&&pr.head?.repo?.full_name===env.GITHUB_REPOSITORY&&pr.base?.ref==='main','CiSmokeSourcePullRequest');
 }else{
  need(env.GITHUB_REF==='refs/heads/main','CiSmokeSourceMainRequired');
  const rows=await host.api('commits/'+checkout.revision+'/pulls');need(Array.isArray(rows),'CiSmokeSourcePullRequest');
  const matches=rows.filter(p=>p.merged_at&&p.merge_commit_sha===checkout.revision&&p.base?.ref==='main'&&p.head?.repo?.full_name===env.GITHUB_REPOSITORY);need(matches.length===1,'CiSmokeSourcePullRequest');pr=matches[0];
 }
 need(git(pr.head?.sha),'CiSmokeSourcePullRequest');const commit=await host.api('commits/'+pr.head.sha);need(commit.commit?.tree?.sha===checkout.tree,'CiSmokeSourceCandidateTree');return pr;
}
async function selectSource(host,route){
 const env=host.env,checkout=await host.checkout();need(route===env.GITHUB_JOB,'CiSmokeActualRoute');
 const currentRun=await host.api('actions/runs/'+env.GITHUB_RUN_ID+'/attempts/'+env.GITHUB_RUN_ATTEMPT),jobs=await host.api('actions/runs/'+env.GITHUB_RUN_ID+'/attempts/'+env.GITHUB_RUN_ATTEMPT+'/jobs?per_page=100');
 need(jobs.total_count===jobs.jobs?.length,'CiSmokeCurrentJobsIncomplete');
 const ownSmoke=jobs.jobs.filter(j=>j.name===CI_SMOKE_JOB_NAME&&j.status==='completed'&&j.conclusion==='success');
 let selectedRun=currentRun,smoke=ownSmoke[0],stage;
 if(!extraSourceRoutes.includes(route)&&!route.startsWith('runtime-')&&ownSmoke.length===1){
  stage=currentRun.event==='pull_request'?'pr-'+(/^refs\/pull\/([1-9][0-9]*)\/merge$/.exec(env.GITHUB_REF??'')?.[1]??env.PR_NUMBER):'prod';
 }else{
  const pr=await sourceCandidate(host,route,checkout),runs=await host.api('actions/workflows/infra-ci.yml/runs?event=pull_request&head_sha='+pr.head.sha+'&status=success&per_page=20');
  need(Array.isArray(runs.workflow_runs)&&runs.workflow_runs.length<=20,'CiSmokeSourceRuns');
  selectedRun=runs.workflow_runs.filter(r=>r.event==='pull_request'&&r.status==='completed'&&r.conclusion==='success'&&r.head_sha===pr.head.sha&&r.head_repository?.full_name===env.GITHUB_REPOSITORY).sort((a,b)=>b.id-a.id)[0];need(selectedRun,'CiSmokeSourceRunRequired');
  const list=await host.api('actions/runs/'+selectedRun.id+'/attempts/'+selectedRun.run_attempt+'/jobs?per_page=100');need(list.total_count===list.jobs?.length,'CiSmokeSourceJobs');
  const matches=list.jobs.filter(j=>j.name===CI_SMOKE_JOB_NAME&&j.status==='completed'&&j.conclusion==='success');need(matches.length===1,'CiSmokeSourceRunRequired');smoke=matches[0];stage='pr-'+pr.number;
 }
 const commitment=extractSmokeCommitment(await host.readLog(smoke.id));
 need(commitment.runId===selectedRun.id&&commitment.runAttempt===selectedRun.run_attempt&&commitment.smokeJobId===smoke.id&&commitment.sourceTree===checkout.tree,'CiSmokeSourceCommitment');
 const provenance=await captureCiSmokeGithub(host,{repository:env.GITHUB_REPOSITORY,runId:commitment.runId,runAttempt:commitment.runAttempt,sourceRevision:commitment.sourceRevision,purpose:'consume'});
 need(provenance.buildDigest===commitment.outputDigest,'CiSmokeSourceDigest');await freshCheckout(host,checkout);
 return {checkout,commitment,provenance,stage,current:ownIdentity(env),job:await currentJob(host)};
}
export async function verifyDecoded(decoded,provenance,now){
 const {result,source,isolation,observations,commandBindings,commandCatalog}=decoded.records;
 assertProducerClosure(observations,isolation);
 exact(source,['version','kind','originRecipe','candidateRecipe','material','imageMetadata']);need(source.version===1&&source.kind==='ci-smoke-source-capture','CiSmokeEnvelopeSource');
 await verifyImageMetadataRefs(source.imageMetadata,observations.images,decoded.readBytes);
 const expected=completedExpected(producedExpected(result,observations,commandBindings,commandCatalog),provenance),extra=new Objects();
 // Completion metadata is collected after the producer job ends. It is a new
 // record; the original envelope and its honest in-progress capture stay intact.
 const material={...source.material,provenance:extra.json(provenance),expected:extra.json(expected)};
 const checked=await verifyArchivedCiSmoke(isolation,result,{material,originRecipe:source.originRecipe,candidateRecipe:source.candidateRecipe,
  resolveJson:async ref=>extra.objects.get(ref.bytesHash)??decoded.readJson(ref),readBytes:async ref=>extra.objects.get(ref.sha256)??decoded.readBytes(ref),now});
 // These are the two original byte objects consumed above, not rebuilt JSON
 // or predicted job completion. This data remains non-authorizing; consumers
 // replay it with the immutable envelope and authenticated archive bindings.
 need(extra.objects.size===2,'CiSmokeCompletionInventory');
 const refs=[material.provenance,material.expected];
 const estimated=Buffer.byteLength(JSON.stringify(material))+2048+refs.reduce((n,ref)=>n+4*Math.ceil(ref.bytesLength/3),0);
 need(estimated<=CI_SMOKE_ARCHIVE_LIMITS.objectBytes,'CiSmokeCompletionLimit');
 const completion=parseCiSmokeJson(JSON.stringify({version:1,kind:'ci-smoke-completion-material',envelopeSha256:decoded.commitment.envelopeSha256,resultHash:decoded.commitment.resultHash,material,
  objects:refs.map(ref=>({ref,base64:extra.get(ref.bytesHash).toString('base64')}))}));
 need(Buffer.byteLength(JSON.stringify(completion))<=CI_SMOKE_ARCHIVE_LIMITS.objectBytes,'CiSmokeCompletionLimit');
 return Object.freeze({...checked,completion});
}
async function sourceGate(host,route,{precheckOnly=false}={}){
 const selected=await selectSource(host,route);if(precheckOnly)return {phase:'smoke-source-prechecked'};
 const config=archiveInput(smokeArchiveConfig(host.env,selected.stage,selected.commitment));
 const {withCiSmokeReadSession}=await import('./lib/ci-smoke-session.mjs');
 // Leave cleanup and server timestamp rounding inside the 900-second session.
 const deadlineMs=Math.min(selected.job.expiresMs,Date.now()+840000);
 const verifySmoke=async({credentials,signal,requestHandler,deadlineMs:readerDeadline=deadlineMs})=>{
  const decoded=await getCiSmokeEnvelope(selected.commitment,{config,credentials,signal,deadlineMs:Math.min(readerDeadline,credentials.expiration.getTime()),...(requestHandler?{requestHandler}:{})});
  const checked=await verifyDecoded(decoded,selected.provenance,Date.now());return {raw:decoded.envelopeBytes,checked};
 };
 let observed,receiptExpiresMs=selected.job.expiresMs;
 if(['deploy-preview','runtime-cutover-preview'].includes(route)){
  observed=await withCiSmokeReadSession({config,commitment:selected.commitment,env:host.env,deadlineMs},verifySmoke);
 }else{
  const {withCiSmokeSourceAllowance}=await import('./lib/ci-smoke-source-allowance.mjs');
  const result=await withCiSmokeSourceAllowance({env:host.env,host,scope:{kind:'source',jobKey:route,route,phase:'source',checkpoint:route+'/source'},config,commitment:selected.commitment,jobExpiresMs:selected.job.expiresMs},verifySmoke);
  observed=result.observed;receiptExpiresMs=Math.min(receiptExpiresMs,result.expiresMs);
 }
 // Both production readers have completed physical cleanup before exporting
 // any receipt. The normal deployment credential action remains later.
 await freshCheckout(host,selected.checkout);need(observed.raw instanceof Uint8Array,'CiSmokeEnvelopeBytesRequired');
 need(Date.now()<receiptExpiresMs,'CiSmokeSourceReceiptExpired');
 const directory=await smokeDirectory(host.env,'mem9-ci-smoke-source',{create:true}),envelopeFile=join(directory,'envelope.json');
 await smokePrivateWrite(envelopeFile,Buffer.from(observed.raw));
 const receipt={version:1,kind:'ci-smoke-source-receipt',current:selected.current,checkout:selected.checkout,sourceStage:selected.stage,commitment:selected.commitment,provenance:selected.provenance,
  envelopeFile,envelopeHash:sha(observed.raw),isolationHash:observed.checked.source.isolationHash,observedMs:Date.now(),expiresMs:receiptExpiresMs};
 const receiptFile=join(directory,'receipt.json'),receiptHash=await smokePrivateWrite(receiptFile,receipt);
 need(Date.now()<receiptExpiresMs,'CiSmokeSourceReceiptExpired');
 await smokeEnvironment(host.env,{MEM9_CI_SMOKE_SOURCE_RECEIPT:receiptFile,MEM9_CI_SMOKE_SOURCE_RECEIPT_HASH:receiptHash});return {phase:'smoke-source-verified'};
}
async function sourceReceipt(host,route){
 need(route===host.env.GITHUB_JOB,'CiSmokeActualRoute');const directory=await smokeDirectory(host.env,'mem9-ci-smoke-source'),file=join(directory,'receipt.json');
 need(host.env.MEM9_CI_SMOKE_SOURCE_RECEIPT===file&&hex(host.env.MEM9_CI_SMOKE_SOURCE_RECEIPT_HASH),'CiSmokeSourceReceiptRequired');
 const raw=await smokePrivateRead(file),receipt=parse(raw);need(sha(raw)===host.env.MEM9_CI_SMOKE_SOURCE_RECEIPT_HASH,'CiSmokeSourceReceiptChanged');
 exact(receipt,['version','kind','current','checkout','sourceStage','commitment','provenance','envelopeFile','envelopeHash','isolationHash','observedMs','expiresMs']);
 need(receipt.version===1&&receipt.kind==='ci-smoke-source-receipt'&&hash(receipt.current)===hash(ownIdentity(host.env))&&receipt.observedMs<=Date.now()&&Date.now()<receipt.expiresMs,'CiSmokeSourceReceiptExpired');
 need(receipt.envelopeFile===join(directory,'envelope.json'),'CiSmokeEnvelopePath');await freshCheckout(host,receipt.checkout);
 const envelope=await smokePrivateRead(receipt.envelopeFile,33554432);need(sha(envelope)===receipt.envelopeHash,'CiSmokeEnvelopeChanged');
 const verified=await verifyDecoded(decodeCiSmokeEnvelope(envelope,receipt.commitment),receipt.provenance,Date.now());need(verified.source.isolationHash===receipt.isolationHash,'CiSmokeSourceReceiptChanged');return receipt;
}
export function smokeGuardRow({route,step,phase}){
 const rows=CI_SMOKE_POLICY.rows.filter(r=>r.route===route&&r.callPath===step&&r.rule.kind==='protected'&&r.rule.phase===phase);need(rows.length===1,'CiSmokeGuardBinding');return rows[0];
}
export function verifySmokePhaseBundle(bundle,{sourceReceiptHash,phase,sourceTree,now=Date.now(),effect,route,step}){
 const p=bundle?.phaseReceipt;need(p&&p.phase===phase&&bundle.phaseEvidence?.phase===phase&&p.sourceReceiptHash===sourceReceiptHash&&Number.isSafeInteger(p.observedMs)&&Number.isSafeInteger(p.expiresMs)&&p.observedMs<=now&&now<p.expiresMs&&p.expiresMs<=bundle.phaseEvidence.expiresMs&&p.phaseEvidenceHash===hash(bundle.phaseEvidence),'CiSmokePhaseReceiptRequired');
 if(bundle.kind==='image-security-nonroot-deployment-bundle'){
  exact(p,['version','kind','phase','sourceReceiptHash','descriptorHash','parameterVersion','proofHash','reviewHash','deploymentSourceHash','phaseEvidenceHash','observedMs','expiresMs']);need(p.version===1&&p.kind==='image-deployment-phase-receipt','CiSmokePhaseKind');
  need(bundle.phase==='deployment'&&bundle.sourceReceiptHash===sourceReceiptHash&&bundle.source?.checkout?.tree===sourceTree&&hash(bundle.proof)===p.proofHash&&hash(bundle.deploymentSource)===p.deploymentSourceHash,'CiSmokePhaseMaterial');
  const data=parse(bundle.parameter.Value),review=bundle.operation.authorization.review;
  need(data.version===3&&hash(data)===p.descriptorHash&&bundle.parameter.Version===p.parameterVersion&&hash(review)===p.reviewHash&&p.expiresMs<=data.expiresMs&&p.expiresMs<=review.expiresMs,'CiSmokePhaseAuthority');
 }else{
  exact(p,['version','kind','stage','account','region','sourceTree','phase','sourceReceiptHash','targetState','coverage','operationsHash','phaseEvidenceHash','observedMs','expiresMs']);need(p.version===2&&p.kind==='nonroot-preview-phase-receipt','CiSmokePhaseKind');
  need(bundle.kind==='nonroot-preview-phase-bundle'&&bundle.source?.sourceTree===sourceTree&&p.sourceTree===sourceTree&&p.targetState===bundle.phaseEvidence.state,'CiSmokePreviewPhase');
  const evidence=bundle.phaseEvidence;
  need(evidence.version===2&&evidence.kind==='nonroot-preview-target-observation'&&['stage','account','region','sourceTree'].every(key=>p[key]===evidence[key]),'CiSmokePreviewPhase');
  need(Array.isArray(p.coverage)&&hash(p.coverage)===hash(evidence.coverage)&&hash(p.coverage)===hash(Object.keys(evidence.facts??{}).sort()),'CiSmokePreviewCoverage');
  if(effect==='workload-launch'||effect==='credentialed-hard-acceptance')need(p.targetState==='registered','CiSmokePreviewTargetNotRegistered');
  // Consume the producer's exact operation evidence. A source plan can admit
  // deployment preparation without certifying bootstrap or serving workloads.
  const operation=assertPreviewPhaseOperation(bundle,{route,step,phase});
  need(operation.effect===effect,'CiSmokePreviewOperationEffect');
 }
 return p;
}
async function guard(host,args){
 const row=smokeGuardRow(args),receipt=await sourceReceipt(host,args.route);if(args.phase==='source')return {phase:'smoke-source-guarded'};
 const {readImageDeploymentBundle}=await import('./lib/production-image-deployment-bundle.mjs');
 const bundle=await readImageDeploymentBundle(host.env.MEM9_IMAGE_TRANSITION_BUNDLE_FILE,host.env.MEM9_IMAGE_TRANSITION_BUNDLE_HASH);
 verifySmokePhaseBundle(bundle,{sourceReceiptHash:host.env.MEM9_CI_SMOKE_SOURCE_RECEIPT_HASH,phase:args.phase,sourceTree:receipt.checkout.tree,effect:row.rule.effect,route:args.route,step:args.step});return {phase:'smoke-target-guarded'};
}
async function composite(host,args){
 await sourceReceipt(host,args.route);const call=CI_SMOKE_POLICY.shared.parentCalls.find(c=>c.route===args.route&&c.route+'/'+c.baselineIndex===args['call-path']);need(call,'CiSmokeCompositeBinding');
 const expected=call.route==='runtime-cutover-prod'?'all':call.name.startsWith('Prepare')?'prepare':'finish';need(args.phase===expected,'CiSmokeCompositePhase');return {phase:'smoke-composite-verified'};
}
export function findCiSmokeCheckpoint(workflow,action,{route,phase,checkpoint}){
 need(CI_SMOKE_ROUTES.includes(route)&&phases.includes(phase)&&typeof checkpoint==='string'&&checkpoint.startsWith(route+'/'),'CiSmokeCheckpointBinding');
 const job=workflow.jobs?.[route];need(Array.isArray(job?.steps),'CiSmokeCheckpointJob');const matches=[];
 const inspect=(step,parent)=>{
  let key=step.env?.MEM9_CI_SMOKE_CHECKPOINT;
  if(parent&&typeof key==='string')key=key.replace('${{ inputs.ci-smoke-call-path }}',parent.with['ci-smoke-call-path']);
  if(key!==checkpoint)return;
  need(step.uses==='./.github/actions/ci-smoke-gate'&&!Object.hasOwn(step,'run')&&!Object.hasOwn(step,'shell'),'CiSmokeCheckpointPhase');
  exact(step.with,['mode','phase']);need(step.with.mode==='target'&&step.with.phase===phase,'CiSmokeCheckpointPhase');matches.push(step);
 };
 for(const step of job.steps){
  inspect(step);
  if(step.uses==='./.github/actions/runtime-cutover'){
   need(step.with?.['ci-smoke-route']===route&&typeof step.with['ci-smoke-call-path']==='string'&&Array.isArray(action?.runs?.steps),'CiSmokeCheckpointCaller');
   for(const child of action.runs.steps)inspect(child,step);
  }
 }
 need(matches.length===1,'CiSmokeCheckpointBinding');return {route,phase,checkpoint};
}
async function target(host,args){
 let acquisition,stage='source-receipt';
 try{
 const receipt=await sourceReceipt(host,args.route);
 stage='checkpoint';
 const workflow=parseDocument(await host.run('git',['show','HEAD:.github/workflows/infra-ci.yml'])).toJS(),action=parseDocument(await host.run('git',['show','HEAD:.github/actions/runtime-cutover/action.yml'])).toJS();
 const scope=findCiSmokeCheckpoint(workflow,action,{route:args.route,phase:args.phase,checkpoint:host.env.MEM9_CI_SMOKE_CHECKPOINT});
 const {openCiSmokeAcquisition}=await import('./lib/ci-smoke-acquisition.mjs');
 stage='acquisition';
 acquisition=await openCiSmokeAcquisition({env:host.env,scope,sourceReceipt:receipt,host});
 stage='verification';
 const {main}=await import('./verify-image-security-deployment.mjs');
 const result=await main({...host.env,MEM9_DEPLOY_ROLE_ARN:host.env.MEM9_DEPLOY_ROLE_ARN??host.env.MEM9_CI_EVIDENCE_ROLE_ARN},['--deploy','--phase',args.phase],{metadataReads:acquisition});
 stage='seal';const resourceReceiptRef=await acquisition.sealControlResources?.({bundleRef:result.bundleRef});
 stage='completion';
 const completed=await acquisition.finish({bundleRef:result.bundleRef,...(resourceReceiptRef?{resourceReceiptRef}:{})});
 if(args.route==='deploy-prod'&&['preconfigure','presst'].includes(args.phase)){
  need(completed.receiptRef&&typeof completed.receiptRef.path==='string'&&hex(completed.receiptRef.sha256),'CiSmokeAcquisitionReceipt');
  await smokeEnvironment(host.env,{MEM9_CI_ACQUISITION_COMPLETION_FILE:completed.receiptRef.path,MEM9_CI_ACQUISITION_COMPLETION_HASH:completed.receiptRef.sha256});
 }
 return {phase:result.phase};
 }catch(error){
  if(error&&typeof error==='object'&&Object.isExtensible(error))error.ciSmokeTargetStage=stage;
  await acquisition?.hold?.();throw error;
 }
}
async function cleanupSmoke(host){
 const env=host.env,output=join(env.RUNNER_TEMP,'mem9-ci-smoke-evidence');
 let stateDirectory;try{stateDirectory=await smokeDirectory(env,'mem9-ci-smoke-state');}catch(e){if(e.code!=='ENOENT')throw e;}
 if(stateDirectory){
  let intent;try{intent=await readJson(join(stateDirectory,'put-intent.json'));}catch(e){if(e.code!=='ENOENT')throw e;}
  if(intent){
   let result;try{result=await readJson(join(stateDirectory,'put-result.json'));}catch{throw Error('CiSmokePrivatePutUnresolved');}
   need(hash(result.commitment)===hash(intent.commitment)&&typeof result.etag==='string'&&result.etag.length>0,'CiSmokePrivatePutUnresolved');
  }
 }
 try{
  const s=await lstat(output);need(s.isDirectory()&&!s.isSymbolicLink()&&s.uid===process.getuid()&&(s.mode&0o777)===0o700,'CiSmokeCleanupOwnership');
  try{const failure=await readJson(join(output,'failure.json'));need(Array.isArray(failure.cleanupUnresolved)&&failure.cleanupUnresolved.length===0,'CiSmokeCleanupUnresolved');}catch(e){if(e.code!=='ENOENT')throw e;}
  const names=await readdir(output),allowed=['result.json','command-catalog.json','command-bindings.json','producer-observations.json','owned-resources.json','failure.json','objects'];
  need(names.every(name=>allowed.includes(name)),'CiSmokeCleanupUnknownEntry');const files=[],directories=[];
  for(const name of names){const file=join(output,name);
   if(name==='objects'){const d=await lstat(file);need(d.isDirectory()&&!d.isSymbolicLink()&&d.uid===process.getuid()&&(d.mode&0o777)===0o700);const objects=await readdir(file);need(objects.length<=4096&&objects.every(n=>/^[a-f0-9]{64}\.bin$/.test(n)),'CiSmokeCleanupUnknownEntry');for(const n of objects){await smokePrivateRead(join(file,n));files.push(join(file,n));}directories.push(file);}
   else{await smokePrivateRead(file);files.push(file);}
  }
  for(const file of files)await unlink(file);for(const dir of directories)await rmdir(dir);await rmdir(output);
 }catch(error){if(error.code!=='ENOENT')throw error;}
 const input=join(env.RUNNER_TEMP,'mem9-ci-smoke-input.json');try{await smokePrivateRead(input);await unlink(input);}catch(e){if(e.code!=='ENOENT')throw e;}
 await removeSmokeDirectory(env,'mem9-ci-smoke-state');return {phase:'smoke-owned-files-removed'};
}
export async function main(args=process.argv.slice(2),env=process.env){
 const options=parseSmokeArguments(args),host=ciSmokeHost(env);
 switch(options.mode){
  case 'prepare-smoke':return prepareSmoke(host);
  case 'acquire-smoke':return acquireSmoke(host);
  case 'publish-smoke':return publishSmoke(host);
  case 'cleanup-smoke':return cleanupSmoke(host);
  case 'source':return sourceGate(host,options.route);
  case 'source-precheck':return sourceGate(host,options.route,{precheckOnly:true});
  case 'guard':return guard(host,options);
  case 'composite':return composite(host,options);
  case 'target':return target(host,options);
  case 'cleanup-source':{const {cleanupCiSmokeControlResources}=await import('./lib/ci-smoke-control-resources.mjs');await cleanupCiSmokeControlResources({env});await removeSmokeDirectory(env,'mem9-ci-smoke-source');return {phase:'smoke-source-files-removed'};}
 }
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)main().then(v=>console.log(JSON.stringify(v))).catch(error=>{
 console.error(JSON.stringify({phase:'ci-smoke-held',code:/^[A-Za-z][A-Za-z0-9]{0,100}$/.test(error.message)?error.message:'CiSmokeFailed'}));process.exitCode=1;
});
