import {isDeepStrictEqual} from 'node:util';
import {parseStrictJson} from './authorization-archive-policy.mjs';

export const RETAINED_OPERATOR_MUTATION_ACTIONS=Object.freeze([
  'iam:CreateRole','iam:DeleteRole','iam:UpdateRole','iam:UpdateRoleDescription','iam:UpdateAssumeRolePolicy',
  'iam:PutRolePolicy','iam:DeleteRolePolicy','iam:AttachRolePolicy','iam:DetachRolePolicy',
  'iam:PutRolePermissionsBoundary','iam:DeleteRolePermissionsBoundary','iam:TagRole','iam:UntagRole',
]);
export const RETAINED_OPERATOR_CLOUDFORMATION_MUTATIONS=Object.freeze([
  'cloudformation:CancelUpdateStack','cloudformation:ContinueUpdateRollback','cloudformation:CreateChangeSet',
  'cloudformation:CreateStack','cloudformation:CreateStackRefactor','cloudformation:DeleteChangeSet',
  'cloudformation:DeleteStack','cloudformation:ExecuteChangeSet','cloudformation:ExecuteStackRefactor',
  'cloudformation:RecordHandlerProgress','cloudformation:RollbackStack','cloudformation:SetStackPolicy',
  'cloudformation:SignalResource','cloudformation:TagResource','cloudformation:UntagResource',
  'cloudformation:UpdateStack','cloudformation:UpdateTerminationProtection',
]);
const cfReads=new Set(['DescribeStacks','DescribeStackEvents','DescribeStackResources','DescribeStackResource',
  'GetTemplate','GetTemplateSummary','ListStackResources','ValidateTemplate','DescribeChangeSet','ListChangeSets',
  'DescribeEvents','ListStacks','ListExports','ListImports'].map(name=>('cloudformation:'+name).toLowerCase()));
const cfWrites=new Set(RETAINED_OPERATOR_CLOUDFORMATION_MUTATIONS.map(action=>action.toLowerCase()));
const ciNames=Object.freeze(['github-actions-mem9-on-aws','github-actions-mem9-on-aws-preview','github-actions-mem9-on-aws-prod']);
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const fail=message=>{throw Error('RetainedOperatorProtection: '+message);};
const ensure=(ok,message)=>{if(!ok)fail(message);};
const list=value=>Array.isArray(value)?value:[value];
function policyValues(value){
  const values=list(value);
  ensure(values.length>0&&values.every(v=>typeof v==='string'&&v.length>0&&v.length<=4096),'invalid policy values');
  return [...values];
}
function strings(value){
  const values=policyValues(value);
  ensure(new Set(values).size===values.length,'duplicate protection policy values');
  return [...values].sort();
}
function checked(context){
  ensure(object(context)&&/^aws(?:-us-gov|-cn)?$/u.test(context.partition)&&/^\d{12}$/u.test(context.accountId),'invalid identity');
  ensure(ciNames.includes(context.roleName),'unexpected CI role');
  return {...context,namespace:`arn:${context.partition}:iam::${context.accountId}:role/mem9-on-aws-namespace-operator`,
    human:`arn:${context.partition}:iam::${context.accountId}:role/mem9-on-aws-preview-human-acceptance`,
    ciArns:ciNames.map(name=>`arn:${context.partition}:iam::${context.accountId}:role/${name}`)};
}
export function retainedOperatorProtectionPolicyName(roleName){
  ensure(ciNames.includes(roleName),'unexpected CI role');
  return roleName+'-retained-operator-protection';
}
export function expectedRetainedOperatorProtectionPolicy(context){
  const c=checked(context);
  return {Version:'2012-10-17',Statement:[
    {Sid:'DenyRetainedOperatorMutation',Effect:'Deny',Action:[...RETAINED_OPERATOR_MUTATION_ACTIONS],Resource:[c.namespace,c.human]},
    {Sid:'DenyNamespaceOperatorPassRole',Effect:'Deny',Action:'iam:PassRole',Resource:c.namespace},
    {Sid:'DenyPreviewHumanAcceptancePassRole',Effect:'Deny',Action:'iam:PassRole',Resource:c.human,
      ...(c.roleName.endsWith('-prod')?{}:{Condition:{StringNotEquals:{'iam:PassedToService':'ecs-tasks.amazonaws.com'}}})},
    {Sid:'DenyCloudFormationMutation',Effect:'Deny',Action:[...RETAINED_OPERATOR_CLOUDFORMATION_MUTATIONS],Resource:'*'},
  ]};
}

function decode(document){
  if(typeof document==='string')return parseStrictJson(document.trimStart().startsWith('{')?document:decodeURIComponent(document));
  return document;
}
function statements(document){
  const value=decode(document);
  ensure(object(value)&&value.Version==='2012-10-17'&&value.Statement,'invalid policy document');
  const rows=list(value.Statement);ensure(rows.length>0,'empty policy document');
  for(const s of rows){
    ensure(object(s)&&['Allow','Deny'].includes(s.Effect)&&
      Object.hasOwn(s,'Action')!==Object.hasOwn(s,'NotAction')&&Object.hasOwn(s,'Resource')!==Object.hasOwn(s,'NotResource'),'invalid identity statement');
    policyValues(s.Action??s.NotAction);policyValues(s.Resource??s.NotResource);
  }
  return rows;
}
function normalized(statement){
  ensure(object(statement),'invalid protection statement');
  return Object.fromEntries(Object.entries(statement).map(([key,value])=>[
    key,['Action','NotAction','Resource','NotResource'].includes(key)?strings(value):value,
  ]));
}
// Bounded wildcard matching without evaluating policy conditions or trusting
// them to make an otherwise reachable self/peer grant harmless.
function matches(pattern,value,ignoreCase=false){
  if(ignoreCase){pattern=pattern.toLowerCase();value=value.toLowerCase();}
  let p=0,v=0,star=-1,retry=0;
  while(v<value.length){
    if(pattern[p]==='?'||pattern[p]===value[v]){p++;v++;}
    else if(pattern[p]==='*'){star=p++;retry=v;}
    else if(star!==-1){p=star+1;v=++retry;}
    else return false;
  }
  while(pattern[p]==='*')p++;
  return p===pattern.length;
}
const variable=/\$\{[^}]+\}/gu;
function mayAllow(s,action,resource){
  const actionMatches=s.Action!==undefined?policyValues(s.Action).some(p=>matches(p.replace(variable,'*'),action,true)):
    !policyValues(s.NotAction).some(p=>!p.includes('${')&&matches(p,action,true));
  const resourceMatches=s.Resource!==undefined?policyValues(s.Resource).some(p=>matches(p.replace(variable,'*'),resource)):
    !policyValues(s.NotResource).some(p=>!p.includes('${')&&matches(p,resource));
  return actionMatches&&resourceMatches;
}
function verifyGrantCoverage(rows,c){
  for(const s of rows.filter(s=>s.Effect==='Allow')){
    for(const action of RETAINED_OPERATOR_MUTATION_ACTIONS)for(const resource of c.ciArns)
      ensure(!mayAllow(s,action,resource),'CI self/peer mutation grant is reachable');
    if(s.NotAction!==undefined){
      ensure(policyValues(s.NotAction).some(p=>['*','cloudformation:*'].includes(p.toLowerCase())),'unbounded CloudFormation NotAction grant');
      continue;
    }
    for(const action of policyValues(s.Action)){
      const lower=action.toLowerCase();
      const separator=action.indexOf(':');
      ensure(action==='*'||separator>0,'invalid action pattern');
      if(action==='*'||matches(action.slice(0,separator),'cloudformation',true)||action.includes('${')){
        ensure(!/[*?]/u.test(action)&&!action.includes('${')&&(cfReads.has(lower)||cfWrites.has(lower)),'uncovered CloudFormation grant');
      }
    }
  }
}

/** Checks complete managed + inline identity documents. Conditions on Allow
 * statements are deliberately ignored for self/peer mutation reachability.
 * The caller separately authenticates attachments and the exact named inline
 * policy. Quarantine cannot substitute for the source-owned protection. */
export function verifyRetainedOperatorProtectionDocuments(documents,context){
  const c=checked(context);ensure(Array.isArray(documents)&&documents.length>0,'missing policy documents');
  const rows=documents.flatMap(statements);
  verifyGrantCoverage(rows,c);
  for(const expected of expectedRetainedOperatorProtectionPolicy(c).Statement){
    const found=rows.filter(s=>s.Sid===expected.Sid);
    ensure(found.length===1&&isDeepStrictEqual(normalized(found[0]),normalized(expected)),'missing, duplicate or changed '+expected.Sid);
  }
  return true;
}

export function verifyRetainedOperatorProtectionPolicy(document,context){
  const value=decode(document),expected=expectedRetainedOperatorProtectionPolicy(context);
  ensure(object(value)&&Object.keys(value).sort().join()===['Statement','Version'].join()&&
    list(value.Statement).length===expected.Statement.length,'changed named protection document');
  return verifyRetainedOperatorProtectionDocuments([value],context);
}

/** Probe the verified permanent policy with an exact Allow witness per request.
 * This checks the protection's behavior, not complete effective runner access;
 * live identity documents are checked separately and preview E2E remains required. */
export function retainedOperatorProtectionProbes(context){
  const c=checked(context),probes=[];
  for(const action of RETAINED_OPERATOR_MUTATION_ACTIONS)for(const resource of [c.namespace,c.human])
    probes.push({action,resource,decision:'explicitDeny'});
  probes.push({action:'iam:PassRole',resource:c.namespace,decision:'explicitDeny'});
  for(const service of [undefined,'lambda.amazonaws.com','ecs-tasks.amazonaws.com'])probes.push({
    action:'iam:PassRole',resource:c.human,...(service?{context:{'iam:PassedToService':service}}:{}),
    decision:service==='ecs-tasks.amazonaws.com'&&!c.roleName.endsWith('-prod')?'allowed':'explicitDeny',
  });
  for(const action of RETAINED_OPERATOR_CLOUDFORMATION_MUTATIONS)probes.push({action,resource:'*',decision:'explicitDeny'});
  return probes;
}
