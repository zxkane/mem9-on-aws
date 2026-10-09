import {inspectNonrootRecord,nonrootHash as hash} from './production-nonroot-contracts.mjs';

const need=(ok)=>{if(!ok)throw Error('NonrootSourceReadInvalid');};
const git=v=>typeof v==='string'&&/^[a-f0-9]{40}$/.test(v);
const positive=v=>typeof v==='string'&&/^[1-9][0-9]*$/.test(v)&&Number.isSafeInteger(Number(v));

/** Fixed read-only transport. The caller obtains expected candidate identities
 * from the authenticated deployment contract, never from model output. */
export async function captureNonrootMainSource({git:readGit,api},env,expected){
 need(typeof readGit==='function'&&typeof api==='function'&&expected&&
  /^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(expected.repository??'')&&
  ['candidateRevision','candidateTree','baseRevision'].every(key=>git(expected[key]))&&
  Number.isSafeInteger(expected.prNumber)&&expected.prNumber>0);
 need(env.GITHUB_REPOSITORY===expected.repository&&env.GITHUB_EVENT_NAME==='push'&&env.GITHUB_REF==='refs/heads/main'&&
  git(env.GITHUB_SHA)&&env.GITHUB_WORKFLOW_SHA===env.GITHUB_SHA&&positive(env.GITHUB_RUN_ID)&&positive(env.GITHUB_RUN_ATTEMPT));
 const checkout=async()=>{
  need((await readGit(['diff','--quiet'])).trim()==='');need((await readGit(['diff','--cached','--quiet'])).trim()==='');
  const fields=(await readGit(['show','-s','--format=%H%n%T%n%P','HEAD'])).trim().split('\n');
  need(fields.length===3&&fields.every((field,index)=>index===2||git(field)));
  const parents=fields[2].split(' ');
  need(parents.length>=1&&parents.length<=2&&parents.every(git)&&fields[0]===env.GITHUB_SHA&&fields[1]===expected.candidateTree&&
   parents[0]===expected.baseRevision&&(parents.length===1||parents[1]===expected.candidateRevision));
  return {sha:fields[0],tree:fields[1],parents,clean:true};
 };
 const local=await checkout();
 const main=await api('commits/main'),commit=await api('commits/'+local.sha),pr=await api('pulls/'+expected.prNumber),
  run=await api('actions/runs/'+env.GITHUB_RUN_ID+'/attempts/'+env.GITHUB_RUN_ATTEMPT);
 need(main.sha===local.sha&&main.commit?.tree?.sha===local.tree&&commit.sha===local.sha&&commit.commit?.tree?.sha===local.tree&&
  Array.isArray(commit.parents)&&hash(commit.parents.map(value=>value.sha))===hash(local.parents));
 need(pr.number===expected.prNumber&&pr.state==='closed'&&pr.merged===true&&pr.head?.sha===expected.candidateRevision&&
  pr.head?.repo?.full_name===expected.repository&&pr.base?.ref==='main'&&pr.merge_commit_sha===local.sha);
 need(run.id===Number(env.GITHUB_RUN_ID)&&run.run_attempt===Number(env.GITHUB_RUN_ATTEMPT)&&run.event==='push'&&
  run.head_sha===local.sha&&run.head_repository?.full_name===expected.repository&&run.path==='.github/workflows/infra-ci.yml');
 const latest=await api('commits/main');need(latest.sha===main.sha&&latest.commit?.tree?.sha===local.tree&&hash(await checkout())===hash(local));
 return {repository:expected.repository,event:'push',ref:'refs/heads/main',checkout:local,main:{sha:main.sha,tree:main.commit.tree.sha},
  run:{id:run.id,attempt:run.run_attempt,event:run.event,headSha:run.head_sha,repository:run.head_repository.full_name,path:run.path,workflowSha:env.GITHUB_WORKFLOW_SHA},
  pullRequest:{number:pr.number,state:pr.state,merged:pr.merged,headSha:pr.head.sha,headRepository:pr.head.repo.full_name,baseRef:pr.base.ref,mergeCommitSha:pr.merge_commit_sha}};
}

/** Construct only after the captured source bytes have been archived. The
 * reference is verified again by the independent provenance consumer. */
export function createNonrootActualMainRecord(source,reference,expected){
 const ref=inspectNonrootRecord('JsonRef',reference);need(ref.canonicalHash===hash(source));
 return inspectNonrootRecord('ActualMainV1',{version:1,kind:'actual-hardening-main',repository:expected.repository,
  candidateRevision:expected.candidateRevision,candidateTree:expected.candidateTree,baseRevision:expected.baseRevision,
  mainRevision:source.checkout.sha,mainTree:source.checkout.tree,parents:source.checkout.parents,prNumber:expected.prNumber,
  workflowRun:source.run.id,workflowAttempt:source.run.attempt,workflowPath:source.run.path,workflowSha:source.run.workflowSha,authenticatedSource:ref});
}
