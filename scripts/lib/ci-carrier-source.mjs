/** The carrier is one compiled candidate-CI job, never a normal deployment
 * route. Formatting a template does not authenticate its workflow or role. */
import {inspectCarrierFundingPlan,carrierRunBinding,CARRIER_CI_JOB} from './ci-carrier-before-copy.mjs';
import {createControlSourceContext} from './production-control-source.mjs';
import {verifyCarrierCiSource} from './ci-carrier-source-policy.mjs';
export const CARRIER_JOB=Object.freeze({key:CARRIER_CI_JOB.jobKey,name:CARRIER_CI_JOB.jobName,workflowPath:CARRIER_CI_JOB.workflowPath,environment:'preview-ci',actionPath:'.github/actions/ci-carrier-before-copy'});
const need=(ok,code)=>{if(!ok)throw Error(code);};

export function verifyCarrierWorkerDefinition(template,env){
 const s=template?.source;
 need(s?.jobKey===CARRIER_JOB.key&&s.jobName===CARRIER_JOB.name&&s.workflowPath===CARRIER_JOB.workflowPath,'CarrierWorkerDefinition');
 need(typeof env?.AWS_PREVIEW_ROLE_ARN==='string'&&env.AWS_PREVIEW_ROLE_ARN===template.scope.previewRoleArn,'CarrierWorkerPreviewRole');
 need(env.GITHUB_ACTIONS==='true'&&env.GITHUB_REPOSITORY===s.repository&&env.GITHUB_JOB===CARRIER_JOB.key&&env.GITHUB_EVENT_NAME==='workflow_dispatch'&&env.GITHUB_REF===s.candidateRef&&env.GITHUB_SHA===s.candidateRevision&&env.GITHUB_WORKFLOW_SHA===s.workflowSha&&env.GITHUB_WORKFLOW_REF===s.repository+'/'+CARRIER_JOB.workflowPath+'@'+s.candidateRef&&(env.GITHUB_SERVER_URL??'https://github.com')==='https://github.com','CarrierWorkerEnvironment');
 for(const key of ['GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT'])need(/^[1-9][0-9]*$/.test(env[key]??'')&&Number.isSafeInteger(Number(env[key])),'CarrierWorkerEnvironment');
}
export function verifyCarrierWorkerSource({plan:input,grantHash,env,observations,checkout}){
 // Independent anchors fail before even asking the host for observations.
 verifyCarrierWorkerDefinition(input?.template,env);
 const plan=inspectCarrierFundingPlan(input),binding=carrierRunBinding(plan,grantHash,observations);
 need(binding.runId===Number(env.GITHUB_RUN_ID)&&binding.runAttempt===Number(env.GITHUB_RUN_ATTEMPT)&&observations.run.status==='in_progress','CarrierWorkerActualRun');
 need(checkout?.revision===plan.template.source.candidateRevision&&checkout?.tree===plan.template.source.candidateTree,'CarrierWorkerCheckout');
 return binding;
}

/** Host is the existing bounded Git/GitHub reader. No AWS dependency is loaded
 * here, and no template-selected job is searched as an alternative. */
export async function authenticateCarrierWorkerSource({config,env,host}){
 verifyCarrierWorkerDefinition(config?.plan?.template,env);
 const plan=inspectCarrierFundingPlan(config.plan),s=plan.template.source;
 need(host?.env===env&&typeof host.api==='function'&&typeof host.checkout==='function'&&typeof host.run==='function','CarrierWorkerHost');
 const checkout=await host.checkout();
 need((await host.run('git',['status','--porcelain','--untracked-files=all'])).trim()==='','CarrierWorkerDirtyCheckout');
 const entries=(await host.run('git',['ls-tree','-r','-z','--full-tree',s.candidateRevision])).split('\0').filter(Boolean).map(row=>{
  const m=/^(\d+) (\w+) ([a-f0-9]{40})\t(.+)$/.exec(row);need(m,'CarrierWorkerGitEntry');return {mode:m[1],type:m[2],oid:m[3],path:m[4]};
 });
 const sourceContext=createControlSourceContext({tree:s.candidateTree,entries},oid=>host.run('git',['cat-file','blob',oid],{encoding:'buffer',maxBytes:8388608}));
 const sourcePolicy=await verifyCarrierCiSource(plan.template,sourceContext);
 const run=await host.api('actions/runs/'+env.GITHUB_RUN_ID);
 const jobs=await host.api('actions/runs/'+env.GITHUB_RUN_ID+'/attempts/'+env.GITHUB_RUN_ATTEMPT+'/jobs?per_page=100');
 need(Number.isSafeInteger(jobs?.total_count)&&jobs.total_count<=100&&Array.isArray(jobs.jobs)&&jobs.jobs.length===jobs.total_count,'CarrierWorkerJobInventory');
 const matches=jobs.jobs.filter(j=>j.name===CARRIER_JOB.name);need(matches.length===1,'CarrierWorkerJobIdentity');
 const commit=await host.api('git/commits/'+s.candidateRevision),pullRequest=await host.api('pulls/'+s.prNumber);
 const binding=verifyCarrierWorkerSource({plan,grantHash:config.grantHash,env,checkout,observations:{run,job:matches[0],commit,pullRequest}});
 return Object.freeze({binding,sourceContext,sourcePolicy});
}
