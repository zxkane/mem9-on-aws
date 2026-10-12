import {OBSERVER_ACCOUNTING_V3} from './production-nonroot-observer-accounting.mjs';
/** Prospective source planning DATA. This cannot satisfy HealthyOverlapPlanV1
 * or create a rehearsal, process identity, completion or deployment context. */
import {inspectNonrootRecord,copyNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';

export const DIRECT_A_REHEARSAL_PROFILE='direct-authenticated-A-v1';
export const OVERLAP_PREPARATION_KIND='overlap-preparation-v1';
export const ORIGINAL_OVERLAP_CASES=Object.freeze(['successful-handover','prefix-start-failure','sidecar-readiness-failure','post-liveness-regression','nonterminal-timeout']);
const need=(v,c)=>{if(!v)throw Error(c);};
const exact=(v,k)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===k.slice().sort().join(),'OverlapPreparationFields');
const hex=(v,n)=>typeof v==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(v);
const same=(a,b,c)=>need(hash(a)===hash(b),c);

export function inspectNonrootOverlapPreparation(value){
 const v=copyNonrootJson(value);
 exact(v,['version','kind','authority','profile','owner','source','acquisition','controlImage','construction','dataImages','configurationHash','cases','baseline',...(v.version===2?['accounting']:[])]);
 need([1,2].includes(v.version)&&v.kind===(v.version===2?'overlap-preparation-v2':OVERLAP_PREPARATION_KIND)&&v.authority===false&&v.profile===DIRECT_A_REHEARSAL_PROFILE&&hex(v.owner,32),'OverlapPreparationKind');
 if(v.version===2)same(v.accounting,OBSERVER_ACCOUNTING_V3,'OverlapPreparationAccounting');
 exact(v.source,['repository','prNumber','candidateRevision','candidateTree','baseRevision']);
 need(typeof v.source.repository==='string'&&/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(v.source.repository)&&Number.isSafeInteger(v.source.prNumber)&&v.source.prNumber>0&&['candidateRevision','candidateTree','baseRevision'].every(k=>hex(v.source[k],40)),'OverlapPreparationSource');
 inspectNonrootRecord('JsonRef',v.acquisition);inspectNonrootRecord('ControlImageBindingV1',v.controlImage);
 need(v.controlImage.repositoryName==='mem9-on-aws/preview/bootstrap','OverlapPreparationControlImage');
 exact(v.construction,['plan','planHash','copyHash']);inspectNonrootRecord('JsonRef',v.construction.plan);
 need(hex(v.construction.planHash,64)&&hex(v.construction.copyHash,64)&&hex(v.configurationHash,64),'OverlapPreparationCommitment');
 inspectNonrootRecord('ImageSet',v.dataImages);same(v.cases,ORIGINAL_OVERLAP_CASES,'OverlapPreparationCases');
 const b=v.baseline;exact(b,['account','region','clusterArn','serviceArn','oldTaskArn','oldTaskDefinitionArn','probeSourceHash','probePath','probeSuccessHash','cloudMap','ordinaryWorkflow']);
 need(/^[0-9]{12}$/.test(b.account)&&/^[a-z]{2}(?:-[a-z]+)+-\d$/.test(b.region),'OverlapPreparationScope');
 need(v.controlImage.account===b.account&&v.controlImage.region===b.region,'OverlapPreparationScope');
 for(const [key,type]of [['clusterArn','cluster'],['serviceArn','service'],['oldTaskArn','task'],['oldTaskDefinitionArn','task-definition']])need(typeof b[key]==='string'&&b[key].startsWith('arn:aws:ecs:'+b.region+':'+b.account+':'+type+'/')&&Buffer.byteLength(b[key])<=4096&&!/[\s*?]/.test(b[key]),'OverlapPreparationIdentity');
 need(/^arn:aws:ecs:[a-z0-9-]+:\d{12}:task\/[A-Za-z0-9_-]+\/[a-f0-9]{32}$/.test(b.oldTaskArn)&&/^arn:aws:ecs:[a-z0-9-]+:\d{12}:task-definition\/[A-Za-z0-9_-]+:[1-9][0-9]*$/.test(b.oldTaskDefinitionArn),'OverlapPreparationIdentity');
 need(hex(b.probeSourceHash,64)&&hex(b.probeSuccessHash,64)&&typeof b.probePath==='string'&&b.probePath.startsWith('/')&&b.probePath.length<=4096,'OverlapPreparationRoute');
 inspectNonrootRecord('JsonRef',b.cloudMap);inspectNonrootRecord('JsonRef',b.ordinaryWorkflow);
 return v;
}

/** Contract version selects the current rule. Missing evidence cannot select
 * the legacy branch. Existing v1 historical inspection remains distinct. */
export function requireNonrootRehearsalProfile(contract,preparation){
 need(contract?.version===1||contract?.version===2,'OverlapPreparationContract');
 if(contract.version===1){need(preparation===undefined,'OverlapPreparationDowngrade');return null;}
 const v=inspectNonrootOverlapPreparation(preparation);
 same(v.source,{repository:contract.repository,prNumber:contract.prNumber,candidateRevision:contract.candidate.revision,candidateTree:contract.candidate.tree,baseRevision:contract.candidate.baseRevision},'OverlapPreparationSource');
 same({planHash:v.construction.planHash,copyHash:v.construction.copyHash},contract.recipe.composition,'OverlapPreparationRecipe');
 return v;
}
