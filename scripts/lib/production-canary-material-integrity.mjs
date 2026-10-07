import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {normalizeCanaryTask} from './production-canary-material.mjs';
import {validateProductionBackendBinding} from './production-artifacts.mjs';

const fail=()=>{throw Error('CanaryMaterialCaptureFailed');};

// These legacy checks are shared verbatim by V1/V2 and transition verification.
const policyShape=(value,key='')=>{
  if(['Action','Resource','Statement'].includes(key)&&!Array.isArray(value))value=[value];
  if(Array.isArray(value))return value.map(v=>policyShape(v)).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)));
  return value&&typeof value==='object'?Object.fromEntries(Object.keys(value).filter(k=>k!=='Sid').sort().map(k=>[k,policyShape(value[k],k)])):value;
};

export function normalizeCanaryAuthority(snapshot){
  const {account,region,definitions,scheduler,authority:roles,network}=snapshot;
  if(scheduler?.roleArn!==`arn:aws:iam::${account}:role/mem9-on-aws-prod-Mem9ConsolidationSchedulerRole-role`||
    !/^mem9-on-aws-prod-consolidation-[A-Za-z0-9-]+$/.test(scheduler.groupName??''))fail();
  const role=roles?.find(r=>r.arn===scheduler.roleArn),workers=[definitions.planner,definitions.executor];
  const revisions=workers.map(d=>d.taskDefinitionArn),families=revisions.map(arn=>arn.replace(/:[1-9][0-9]*$/,''));
  const cluster=network?.cluster,clusterPrefix=`arn:aws:ecs:${region}:${account}:cluster/`;
  if(!cluster?.startsWith(clusterPrefix+'mem9-on-aws-prod-')||new Set(families).size!==2||
    role?.boundary?.arn!==`arn:aws:iam::${account}:policy/mem9-on-aws-workload-boundary`||
    !role.roleId||role.inlinePolicies?.length!==1||role.attachedPolicies?.length!==0)fail();
  const expectedTrust={Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'sts:AssumeRole',Principal:{Service:'scheduler.amazonaws.com'},
    Condition:{StringEquals:{'aws:SourceAccount':account,'aws:SourceArn':`arn:aws:scheduler:${region}:${account}:schedule-group/${scheduler.groupName}`}}}]};
  const expectedPolicy={Version:'2012-10-17',Statement:[
    {Effect:'Deny',Action:'ecs:RunTask',Resource:`arn:aws:ecs:${region}:${account}:task-definition/${cluster.slice(clusterPrefix.length)}-Mem9Consolidation:*`},
    {Effect:'Allow',Action:'ecs:RunTask',Resource:revisions,Condition:{ArnEquals:{'ecs:cluster':cluster}}},
    {Effect:'Allow',Action:'iam:PassRole',Resource:workers.flatMap(d=>[d.taskRoleArn,d.executionRoleArn]),Condition:{StringEquals:{'iam:PassedToService':'ecs-tasks.amazonaws.com'}}},
  ]};
  if(hash(policyShape(role.trust))!==hash(policyShape(expectedTrust))||hash(policyShape(role.inlinePolicies[0].document))!==hash(policyShape(expectedPolicy)))fail();
  const normalized=structuredClone(roles),copy=normalized.find(r=>r.arn===role.arn);
  const document=policyShape(copy.inlinePolicies[0].document);
  // Exact current-revision permission was verified above. Substitute only its
  // two RunTask resources for comparison, never for a deployed IAM document.
  document.Statement.find(s=>s.Effect==='Allow'&&s.Action.join()==='ecs:RunTask').Resource=families.map(f=>'canary-worker-family:'+f).sort();
  copy.inlinePolicies[0].document=document;
  return normalized;
}

export function verifyLegacyCanaryMaterial(snapshot){
  const binding=validateProductionBackendBinding(snapshot.backendBinding,snapshot.network?.cluster),task=snapshot.backendTask;
  const names=['llm-proxy','mnemo-server','qwen3-embed'];
  if(!snapshot.network?.cluster||snapshot.definitions?.backend?.taskDefinitionArn!==binding.taskDefinitionArn||
    task?.taskArn!==binding.taskArn||task.taskDefinitionArn!==binding.taskDefinitionArn||task.clusterArn!==snapshot.network.cluster||task.lastStatus!=='RUNNING')fail();
  for(const containers of [binding.containers,task.containers,snapshot.definitions.backend.containerDefinitions]){
    if(!Array.isArray(containers)||hash(containers.map(c=>c?.name).sort())!==hash(names))fail();
  }
  for(const bound of binding.containers){
    const image=snapshot.components[bound.name],actual=task.containers.find(c=>c.name===bound.name),configured=snapshot.definitions.backend.containerDefinitions.find(c=>c.name===bound.name);
    if(!image||![image.rootDigest,image.arm64Digest].includes(bound.imageDigest)||actual.imageDigest!==bound.imageDigest||actual.image!==configured.image)fail();
  }
  const images=new Map([[snapshot.workerImage,snapshot.components.worker]]);
  for(const c of snapshot.definitions.backend.containerDefinitions)images.set(c.image,snapshot.components[c.name]);
  const context={account:snapshot.account,region:snapshot.region,images},material={};
  const roleArns=[...new Set([snapshot.scheduler?.roleArn,...Object.values(snapshot.definitions).flatMap(d=>[d.taskRoleArn,d.executionRoleArn])])].sort();
  const references=[...new Set(Object.values(snapshot.definitions).flatMap(d=>d.containerDefinitions.flatMap(c=>(c.secrets??[]).map(s=>s.valueFrom))))].sort();
  if(!Array.isArray(snapshot.authority)||hash(snapshot.authority.map(r=>r.arn).sort())!==hash(roleArns)||
    !Array.isArray(snapshot.credentials)||hash(snapshot.credentials.map(c=>c.reference).sort())!==hash(references)||
    snapshot.credentials.some(c=>typeof c.version!=='string'||!c.version||!/^[a-f0-9]{64}$/.test(c.valueHash??'')))fail();
  for(const kind of ['planner','executor','backend'])material[kind]=hash(normalizeCanaryTask(snapshot.definitions[kind],context));
  for(const kind of ['network','credentials'])material[kind]=hash(snapshot[kind]);
  material.authority=hash(normalizeCanaryAuthority(snapshot));
  if(hash(material)!==hash(snapshot.material))fail();
  return material;
}

