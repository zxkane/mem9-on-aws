import {readFileSync} from 'node:fs';
import {remainingCommandTimeout} from './bounded-subprocess.mjs';

const contract=JSON.parse(readFileSync(new URL('../workload-permissions-boundary-contract.json',import.meta.url),'utf8'));
const REPOSITORY=contract.repository,WORKFLOW='infra-ci.yml',WORKFLOW_NAME='Infra CI',JOB='Typecheck & Unit Tests';
const need=(value,reason)=>{if(!value)throw new Error('WorkloadBoundaryCi'+reason);};
const json=text=>{need(typeof text==='string'&&Buffer.byteLength(text)<=4194304,'Response');try{return JSON.parse(text);}catch{throw new Error('WorkloadBoundaryCiJson');}};
const runIdentity=(run,commit)=>run&&Number.isSafeInteger(run.databaseId)&&run.databaseId>0&&
 run.headSha===commit&&run.event==='push'&&run.workflowName===WORKFLOW_NAME;

/** One bounded read, never a poll or dispatch. runGh is the trusted owner's
 * read-only transport, not configuration or an adoptable JSON result. The same
 * predicate is used before acquisition and again by the guarded rollout. */
export async function verifyWorkloadBoundaryPushCi({reviewedCommit,runGh,signal,deadlineAt}={}){
 need(/^[a-f0-9]{40}$/.test(reviewedCommit??'')&&typeof runGh==='function','Input');
 need(deadlineAt===undefined||Number.isSafeInteger(deadlineAt),'Deadline');
 const end=Math.min(Date.now()+60000,deadlineAt??Infinity);
 need(end>Date.now(),'Deadline');signal?.throwIfAborted();
 const boundedSignal=AbortSignal.any([AbortSignal.timeout(Math.max(1,end-Date.now())),...(signal?[signal]:[])]);
 const read=async args=>{
  boundedSignal.throwIfAborted();
  const result=await runGh(args,{signal:boundedSignal,timeoutMs:Math.floor(remainingCommandTimeout({deadlineAt:end,maximumMs:30000}))});
  boundedSignal.throwIfAborted();need(Date.now()<end,'Deadline');return result;
 };
 need(typeof REPOSITORY==='string'&&/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(REPOSITORY),'Contract');
 const workflows=contract.deploymentWorkflows;
 need(Array.isArray(workflows)&&workflows.length===3&&workflows.filter(w=>w.id===WORKFLOW).length===1,'Contract');
 const branch=await read(['api',`repos/${REPOSITORY}`,'--jq','.default_branch']);
 need(typeof branch==='string'&&/^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$/.test(branch)&&!branch.includes('..')&&!branch.includes('//'),'Branch');
 const head=()=>read(['api',`repos/${REPOSITORY}/commits/${branch}`,'--jq','.sha']);
 need(await head()===reviewedCommit,'Head');
 for(const workflow of workflows){
  need(/^\.github\/workflows\/[a-z0-9-]+\.yml$/.test(workflow.path)&&/^[a-f0-9]{40}$/.test(workflow.reviewedBlob),'Contract');
  need(await read(['api','--method','GET',`repos/${REPOSITORY}/contents/${workflow.path}`,'-f',`ref=${reviewedCommit}`,'--jq','.sha'])===workflow.reviewedBlob,'WorkflowBlob');
 }
 const runs=json(await read(['run','list','--repo',REPOSITORY,'--workflow',WORKFLOW,'--all','--commit',reviewedCommit,'--event','push','--limit','20',
  '--json','databaseId,status,headSha,event,workflowName']));
 need(Array.isArray(runs)&&runs.length<=20&&runs.every(r=>runIdentity(r,reviewedCommit))&&new Set(runs.map(r=>r.databaseId)).size===runs.length,'Runs');
 const run=runs.find(r=>r.status==='completed');need(run,'MissingPush');
 const view=json(await read(['run','view',String(run.databaseId),'--repo',REPOSITORY,'--json','databaseId,status,headSha,event,workflowName,jobs']));
 need(runIdentity(view,reviewedCommit)&&view.databaseId===run.databaseId&&view.status==='completed','RunBinding');
 need(Array.isArray(view.jobs)&&view.jobs.length<=1000,'Jobs');
 const passed=view.jobs.filter(job=>job?.name===JOB&&job.conclusion==='success');
 need(passed.length===1&&passed[0].status==='completed','Typecheck');
 need(await head()===reviewedCommit,'Head');
 return Object.freeze({repository:REPOSITORY,reviewedCommit,workflow:WORKFLOW,runId:String(run.databaseId)});
}
