import {describe,it,expect} from 'vitest';
import {readFileSync} from 'node:fs';
import {verifyWorkloadBoundaryPushCi} from './lib/workload-permissions-boundary-ci.mjs';
import {classifyChangedPaths} from './classify-infra-changes.mjs';

const contract=JSON.parse(readFileSync(new URL('./workload-permissions-boundary-contract.json',import.meta.url)));
const commit='a'.repeat(40),runId=12345;
function fixture(change={}){
 const calls=[];
 const run={databaseId:runId,status:'completed',headSha:commit,event:'push',workflowName:'Infra CI',...change.run};
 const view={...run,jobs:[{name:'Typecheck & Unit Tests',conclusion:'success',status:'completed'}],...change.view};
 let heads=0;
 const runGh=async(args,options)=>{
  calls.push({args,options});
  if(change.error)throw change.error;
  if(args[0]==='api'){
   const path=args.find(v=>v.startsWith('repos/'));
   if(path===`repos/${contract.repository}`)return 'main';
   if(path.includes('/commits/'))return ++heads===2&&change.drift?'b'.repeat(40):commit;
   const workflow=contract.deploymentWorkflows.find(w=>path.endsWith('/contents/'+w.path));
   if(workflow)return change.blob??workflow.reviewedBlob;
  }
  if(args[0]==='run'&&args[1]==='list')return change.disabled&&!args.includes('--all')?'[]':change.malformed??JSON.stringify(change.runs??[run]);
  if(args[0]==='run'&&args[1]==='view')return JSON.stringify(view);
  throw Error('Unexpected fixture request');
 };
 return {calls,runGh};
}
describe('strict workload boundary push CI readiness',()=>{
 it('uses the current reviewed Infra CI push and exactly one successful Typecheck',async()=>{
  const f=fixture();const result=await verifyWorkloadBoundaryPushCi({reviewedCommit:commit,runGh:f.runGh});
  expect(result).toMatchObject({reviewedCommit:commit,runId:String(runId),workflow:'infra-ci.yml'});
  const listing=f.calls.find(c=>c.args[0]==='run'&&c.args[1]==='list').args;
  expect(listing).toEqual(expect.arrayContaining(['--workflow','infra-ci.yml','--event','push','--commit',commit,'--limit','20']));
  expect(f.calls.every(c=>c.options.timeoutMs>0&&c.options.timeoutMs<=30000)).toBe(true);
  expect(f.calls.filter(c=>c.args[0]==='run'&&c.args[1]==='list')).toHaveLength(1);
 });
 it('finds the required prior push after the workflow is disabled for the guarded window',async()=>{
  const f=fixture({disabled:true});
  await expect(verifyWorkloadBoundaryPushCi({reviewedCommit:commit,runGh:f.runGh})).resolves.toMatchObject({runId:String(runId)});
  expect(f.calls.find(c=>c.args[0]==='run'&&c.args[1]==='list').args).toContain('--all');
 });
 it.each([
  ['Docs-only', {runs:[]}],
  ['wrong workflow',{run:{workflowName:'Docs CI'}}],
  ['wrong event',{run:{event:'workflow_dispatch'}}],
  ['wrong SHA',{run:{headSha:'b'.repeat(40)}}],
  ['unfinished run',{run:{status:'in_progress'}}],
  ['Docs job',{view:{jobs:[{name:'Docs CI',conclusion:'success',status:'completed'}]}}],
  ['skipped Typecheck',{view:{jobs:[{name:'Typecheck & Unit Tests',conclusion:'skipped',status:'completed'}]}}],
  ['duplicate success',{view:{jobs:Array.from({length:2},()=>({name:'Typecheck & Unit Tests',conclusion:'success',status:'completed'}))}}],
  ['changed run identity',{view:{databaseId:12346}}],
  ['malformed response',{malformed:'{'}],
  ['workflow source drift',{blob:'f'.repeat(40)}],
  ['main drift',{drift:true}],
 ])('rejects %s without polling or accepting alternative CI',async(_name,change)=>{
  const f=fixture(change);await expect(verifyWorkloadBoundaryPushCi({reviewedCommit:commit,runGh:f.runGh})).rejects.toThrow();
  expect(f.calls.filter(c=>c.args[0]==='run'&&c.args[1]==='list').length).toBeLessThanOrEqual(1);
 });
 it('preserves native cleanup uncertainty',async()=>{
  const error=Object.assign(Error('cleanup unconfirmed'),{code:'ECLEANUP'}),f=fixture({error});
  await expect(verifyWorkloadBoundaryPushCi({reviewedCommit:commit,runGh:f.runGh})).rejects.toBe(error);
 });
 it('rejects cancellation and expired caller deadlines before a request',async()=>{
  const f=fixture(),abort=new AbortController();abort.abort();
  await expect(verifyWorkloadBoundaryPushCi({reviewedCommit:commit,runGh:f.runGh,signal:abort.signal})).rejects.toThrow();
  await expect(verifyWorkloadBoundaryPushCi({reviewedCommit:commit,runGh:f.runGh,deadlineAt:Date.now()-1})).rejects.toThrow();
  expect(f.calls).toEqual([]);
 });
 it('keeps this actual code change under the existing non-mutation classification',()=>{
  expect(classifyChangedPaths(['scripts/lib/workload-permissions-boundary-ci.mjs','scripts/workload-permissions-boundary-ci.test.mjs'])).toEqual({workloadChanged:false,applicationInfrastructureChanged:false,awsMutationRequired:false});
 });
});
