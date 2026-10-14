import {imageTransitionContextBindings} from './production-image-transition-proof.mjs';
const fail=()=>{throw Error('ImageDeploymentSourceReadInvalid');};
const hex=v=>typeof v==='string'&&/^[a-f0-9]{40}$/.test(v);
const positive=v=>/^[1-9][0-9]*$/.test(v??'')&&Number.isSafeInteger(Number(v));
/** Git/CI facts are obtained by the fixed host adapter, never accepted from a
 * serialized caller-supplied source claim. This reader performs no mutations.
 */
export async function captureImageDeploymentSource({git,api},env,imageTransition){
 const b=imageTransitionContextBindings(imageTransition),repository=b.control.repository;
 if(typeof git!=='function'||typeof api!=='function'||typeof repository!=='string'||!/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(repository)||env.GITHUB_REPOSITORY!==repository||env.GITHUB_EVENT_NAME!=='push'||env.GITHUB_REF!=='refs/heads/main'||!hex(env.GITHUB_SHA)||!hex(env.GITHUB_WORKFLOW_SHA)||!positive(env.GITHUB_RUN_ID)||!positive(env.GITHUB_RUN_ATTEMPT))fail();
 await git(['diff','--quiet']);await git(['diff','--cached','--quiet']);
 const fields=(await git(['show','-s','--format=%H%n%T%n%P','HEAD'])).trim().split('\n');
 if(fields.length!==3||!hex(fields[0])||!hex(fields[1])||fields[0]!==env.GITHUB_SHA)fail();
 const parents=fields[2].split(' ');if(parents.some(p=>!hex(p)))fail();
 const main=await api('commits/main'),commit=await api('commits/'+fields[0]),pr=await api('pulls/'+b.control.prNumber),run=await api(`actions/runs/${env.GITHUB_RUN_ID}/attempts/${env.GITHUB_RUN_ATTEMPT}`);
 if(commit.sha!==fields[0]||commit.commit?.tree?.sha!==fields[1]||!Array.isArray(commit.parents)||JSON.stringify(commit.parents.map(p=>p.sha))!==JSON.stringify(parents)||
  run.id!==Number(env.GITHUB_RUN_ID)||run.run_attempt!==Number(env.GITHUB_RUN_ATTEMPT))fail();
 return {repository,event:env.GITHUB_EVENT_NAME,ref:env.GITHUB_REF,checkout:{sha:fields[0],tree:fields[1],parents,clean:true},main:{sha:main.sha,tree:main.commit?.tree?.sha},
  run:{id:run.id,attempt:run.run_attempt,event:run.event,headSha:run.head_sha,repository:run.head_repository?.full_name,path:run.path,workflowSha:env.GITHUB_WORKFLOW_SHA},
  pullRequest:{number:pr.number,state:pr.state,merged:pr.merged,headSha:pr.head?.sha,headRepository:pr.head?.repo?.full_name,baseRef:pr.base?.ref,mergeCommitSha:pr.merge_commit_sha}};
}
