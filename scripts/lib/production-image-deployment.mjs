import {requireActiveDataRelease} from './production-data-release.mjs';
import {assertImageTransitionDataRelease,imageTransitionContextBindings,parseImageTransitionJson} from './production-image-transition-proof.mjs';
import {PRODUCTION_DATA_RELEASE_PARAMETER} from './production-data-issuance.mjs';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';

const fail=()=>{throw Error('ImageDeploymentSourceInvalid');};
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join();
const hex=v=>typeof v==='string'&&/^[a-f0-9]{40}$/.test(v);
const positive=v=>Number.isSafeInteger(v)&&v>0;

export const imageDeploymentParameterBinding=p=>Object.fromEntries(['Name','Type','ARN','Version','Value'].map(k=>[k,p?.[k]]));
/** The immutable operation is read by the fixed authenticated archive adapter.
 * Its predecessor binds the only successor version the one-Put protocol issued. */
export function imageAuthorizationParameterVersion(operation,selected){
 const data=selected?.data,p=operation?.predecessor;
 if(data?.version!==2||operation?.version!==1||operation.kind!=='image-security-transition'||operation.operation?.owner!==data.authorizationId||
  operation.authorization?.hash!==selected.hash||hash(operation.authorization.data)!==selected.hash||hash(operation.authorization.review)!==data.policyHash||
  operation.expected?.transitionProofHash!==data.transition.proofHash||p?.Type!=='SecureString'||!positive(p.Version)||!Number.isSafeInteger(p.Version+1)||typeof p.Value!=='string'||
  hash(parseImageTransitionJson(p.Value))!==data.transition.predecessorHash)fail();
 return p.Version+1;
}

/** A fixed local/CI adapter supplies these facts from Git and authenticated
 * GitHub/SSM reads. A returned record is an audit result, not a bearer permit.
 * Call this before the first deployment write, including ECR build publication.
 */
export function verifyImageDeploymentSource({parameter,source,imageTransition,operation},{now=Date.now()}={}){
 const b=imageTransitionContextBindings(imageTransition),root=b.root,c=b.control;
 if(!parameter||parameter.Name!==PRODUCTION_DATA_RELEASE_PARAMETER||parameter.Type!=='SecureString'||!positive(parameter.Version)||
  parameter.ARN!==`arn:aws:ssm:${root.region}:${root.account}:parameter${PRODUCTION_DATA_RELEASE_PARAMETER}`||typeof parameter.Value!=='string')fail();
 const selected=requireActiveDataRelease(parameter.Value,{stage:'prod',account:root.account,region:root.region,controlSourceTree:c.sourceTree},{now});
 if(selected.data.version!==2)fail();
 if(parameter.Version!==imageAuthorizationParameterVersion(operation,selected))fail();
 assertImageTransitionDataRelease(imageTransition,{current:selected.data,controlSourceTree:c.sourceTree,now,mode:'admission'});
 if(!exact(source,['repository','event','ref','checkout','main','run','pullRequest'])||typeof c.repository!=='string'||!positive(c.prNumber)||source.repository!==c.repository||source.event!=='push'||source.ref!=='refs/heads/main')fail();
 const checkout=source.checkout,main=source.main,run=source.run,pr=source.pullRequest;
 if(!exact(checkout,['sha','tree','parents','clean'])||!hex(checkout.sha)||!hex(checkout.tree)||checkout.clean!==true||
  !Array.isArray(checkout.parents)||![1,2].includes(checkout.parents.length)||checkout.parents.some(p=>!hex(p))||new Set(checkout.parents).size!==checkout.parents.length||
  !exact(main,['sha','tree'])||main.sha!==checkout.sha||main.tree!==checkout.tree||checkout.tree!==c.sourceTree)fail();
 // Only the reviewed base plus candidate merge, or its tree-identical squash,
 // is admitted. Rebase/other parent relationships need a separate review.
 if(checkout.parents[0]!==c.baseRevision||checkout.parents.length===2&&checkout.parents[1]!==c.revision)fail();
 if(!exact(pr,['number','state','merged','headSha','headRepository','baseRef','mergeCommitSha'])||pr.number!==c.prNumber||pr.state!=='closed'||pr.merged!==true||pr.headSha!==c.revision||pr.headRepository!==c.repository||pr.baseRef!=='main'||pr.mergeCommitSha!==checkout.sha)fail();
 if(!exact(run,['id','attempt','event','headSha','repository','path','workflowSha'])||!positive(run.id)||!positive(run.attempt)||run.event!=='push'||run.headSha!==checkout.sha||run.workflowSha!==checkout.sha||run.repository!==c.repository||run.path!=='.github/workflows/infra-ci.yml')fail();
 return Object.freeze({version:1,kind:'image-security-deployment-source',parameterVersion:parameter.Version,dataReleaseHash:selected.hash,
  proofHash:b.proofHash,reviewedControlRevision:c.revision,reviewedControlTree:c.sourceTree,actualMainRevision:checkout.sha,actualMainTree:checkout.tree,
  runId:run.id,runAttempt:run.attempt});
}
