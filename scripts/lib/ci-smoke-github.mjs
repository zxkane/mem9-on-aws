import {CI_SMOKE_JOB_NAME} from './ci-smoke-isolation.mjs';

const need=(v,c='CiSmokeGithubInvalid')=>{if(!v)throw Error(c);};
const git=v=>typeof v==='string'&&/^[a-f0-9]{40}$/.test(v);
const id=v=>Number.isSafeInteger(v)&&v>0;
const one=(rows,name)=>{const matches=rows.filter(r=>r.name===name);need(matches.length===1,'CiSmokeGithubJobAmbiguous');return matches[0];};
const successful=job=>job.status==='completed'&&job.conclusion==='success';

export function extractMnemoBuildDigest(log,{event,revision}){
 need(typeof log==='string'&&Buffer.byteLength(log)<=8388608&&git(revision)&&['pull_request','push','workflow_dispatch'].includes(event));
 const preview=event==='pull_request',tag=(preview?'pr-':'mem9-')+revision.slice(0,7),name='/mem9-on-aws/'+(preview?'preview/':'')+'mnemo-server:'+tag+'@';
 const digests=new Set();
 for(const line of log.split('\n')){
  if(!line.includes('pushing manifest for')||!line.includes(' done')||!line.includes(name))continue;
  const rest=line.slice(line.indexOf(name)+name.length),match=/^(sha256:[a-f0-9]{64})(?:\s|$)/.exec(rest);
  need(match,'CiSmokeBuildDigestMalformed');digests.add(match[1]);
 }
 need(digests.size===1,'CiSmokeBuildDigestUnproven');return [...digests][0];
}

/** This collector has no AWS imports, credentials or AWS transport callback.
 * `prepare` observes its own in-progress smoke job; `consume` requires the
 * completed job and completed publishing step before private evidence access. */
export async function captureCiSmokeGithub({api,readLog},{repository,runId,runAttempt,sourceRevision,purpose='consume'}){
 need(typeof api==='function'&&typeof readLog==='function'&&/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(repository??'')&&id(runId)&&id(runAttempt)&&git(sourceRevision)&&['prepare','consume'].includes(purpose));
 const run=await api('actions/runs/'+runId+'/attempts/'+runAttempt);
 need(run.id===runId&&run.run_attempt===runAttempt&&run.path==='.github/workflows/infra-ci.yml'&&run.head_repository?.full_name===repository&&git(run.head_sha),'CiSmokeGithubRun');
 const jobs=await api('actions/runs/'+runId+'/attempts/'+runAttempt+'/jobs?per_page=100');
 need(Array.isArray(jobs.jobs)&&jobs.jobs.length<=100&&jobs.total_count===jobs.jobs.length,'CiSmokeGithubJobsIncomplete');
 const buildJob=one(jobs.jobs,'Build & push workload images'),smokeJob=one(jobs.jobs,CI_SMOKE_JOB_NAME);
 for(const job of [buildJob,smokeJob])need(id(job.id)&&job.run_id===runId&&job.run_attempt===runAttempt&&job.head_sha===run.head_sha,'CiSmokeGithubJobSource');
 need(successful(buildJob),'CiSmokeGithubBuildFailed');
 const buildStep=one(buildJob.steps??[],'Build & push mnemo-server (arm64)');need(successful(buildStep),'CiSmokeGithubBuildStepFailed');
 if(purpose==='consume'){
  need(successful(smokeJob),'CiSmokeGithubSmokeFailed');
  need(successful(one(smokeJob.steps??[],'Verify and preserve private smoke evidence'))&&successful(one(smokeJob.steps??[],'Remove owned smoke evidence')),'CiSmokeGithubPublishFailed');
 }else need(smokeJob.status==='in_progress','CiSmokeGithubSmokeNotCurrent');
 const commit=await api('commits/'+sourceRevision);
 need(commit.sha===sourceRevision&&git(commit.commit?.tree?.sha)&&Array.isArray(commit.parents)&&commit.parents.length>=1&&commit.parents.length<=2,'CiSmokeGithubCommit');
 const sourceTree=commit.commit.tree.sha;
 let candidateCommit=commit;
 if(run.event==='pull_request'){
  need(commit.parents.length===2&&commit.parents[1].sha===run.head_sha,'CiSmokeGithubMergeRelation');
  candidateCommit=await api('commits/'+run.head_sha);
  need(candidateCommit.sha===run.head_sha&&candidateCommit.commit?.tree?.sha===sourceTree,'CiSmokeGithubCandidateTree');
 }else need(['push','workflow_dispatch'].includes(run.event)&&sourceRevision===run.head_sha,'CiSmokeGithubSourceRelation');
 const buildLog=await readLog(buildJob.id);need(typeof buildLog==='string','CiSmokeGithubLog');
 const buildDigest=extractMnemoBuildDigest(buildLog,{event:run.event,revision:sourceRevision});
 return {run,buildJob,smokeJob,commit,candidateCommit,sourceRevision,sourceTree,buildDigest,buildLog};
}
