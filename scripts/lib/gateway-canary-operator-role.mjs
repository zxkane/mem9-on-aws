import {readFileSync} from 'node:fs';
import {globMatches} from './workload-permissions-boundary.mjs';
import {compileGatewayRuntimeCanaryScope,buildGatewayCanaryOperatorPolicies,buildGatewayCanarySessionPolicyBootstrap,gatewayCanaryDocumentHash as hash} from './gateway-runtime-canary-resources.mjs';

/** The dedicated, ephemeral role every canary lane session assumes. It exists
 * only for a canary window (deploy, run the broker, --delete): the owner check
 * holds only when it runs, so a role left standing would keep admitting an
 * owner narrowed later. Its name is
 * outside the mem9-on-aws-* role namespace, so the deploy role's IAM grants and
 * the workload-boundary role inventory never reach it. Only the configured
 * owner role may assume it; it can assume nothing itself.
 *
 * The role is administrator-equivalent: CreateStack takes an arbitrary
 * template, so its CloudFormation, IAM and Lambda grants can create any policy
 * and role. It must therefore grant its owner nothing new. Before deployment
 * and before any broker session, the operator's own policy and the owner's
 * identity policies and boundary are simulated on the same cases, and nothing
 * proceeds unless every pair the operator is allowed is allowed to the owner. */
export const GATEWAY_CANARY_OPERATOR_ROLE_NAME='gateway-canary-operator-mem9-on-aws';
export const GATEWAY_CANARY_OPERATOR_POLICY_NAME='gateway-canary-operator';
export const GATEWAY_CANARY_OPERATOR_STACK_NAME='gateway-canary-operator-mem9-on-aws';
const check=(ok,reason)=>{if(!ok)throw Error('GatewayCanaryOperator'+reason);};
const freeze=v=>{if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;};
// Sentinels compiled through the real lane policies, then generalized. The
// verification id becomes twelve single-character wildcards: that segment only.
const SENTINEL={verificationId:'f0f0f0f0f0f0',accountId:'9'.repeat(12),region:'zz-sentinel-9'};
const WILDCARD='?'.repeat(12);
const LIKE={StringEquals:'StringLike',ArnEquals:'ArnLike'};

export const gatewayCanaryOperatorRoleArn=accountId=>{check(/^\d{12}$/.test(accountId??''),'Account');return `arn:aws:iam::${accountId}:role/${GATEWAY_CANARY_OPERATOR_ROLE_NAME}`;};

/** Exactly the observe, provision and bootstrap lane statements, with only the
 * verification-id segment generalized. Exact-match conditions on a value that
 * contains it become the matching *Like operator; nothing else changes. */
function lanePolicyStatements(accountId,applicationRegion,verificationId){
  const scope=compileGatewayRuntimeCanaryScope({accountId,applicationRegion,verificationId,vpcId:'vpc-00000000',ownerRoleArn:gatewayCanaryOperatorRoleArn(accountId)});
  const lanes=buildGatewayCanaryOperatorPolicies(scope);
  return [...lanes.observe.Statement,...lanes.provision.Statement,...buildGatewayCanarySessionPolicyBootstrap(scope).policy.Statement];
}
function generalizedLanePolicy(accountId,applicationRegion){
  const replace=v=>typeof v==='string'?v.replaceAll(SENTINEL.verificationId,WILDCARD):Array.isArray(v)?v.map(replace):v;
  const varies=v=>JSON.stringify(v).includes(SENTINEL.verificationId);
  const statement=s=>{
    const {Condition,...rest}=s,out=Object.fromEntries(Object.entries(rest).map(([k,v])=>[k,replace(v)]));
    if(Condition){
      const condition={};
      for(const [operator,entries] of Object.entries(Condition))for(const [key,value] of Object.entries(entries)){
        const target=varies(value)?LIKE[operator]:operator;check(target,'Generalization');
        (condition[target]??={})[key]=replace(value);
      }
      out.Condition=condition;
    }
    return out;
  };
  const statements=lanePolicyStatements(accountId,applicationRegion,SENTINEL.verificationId).map(statement);
  check(!JSON.stringify(statements).includes(SENTINEL.verificationId)&&!statements.some(s=>[s.Action].flat().some(a=>a.startsWith('sts:'))),'Generalization');
  return {Version:'2012-10-17',Statement:statements};
}

/** The operator role's identity policy for one account and application region. */
export function gatewayCanaryOperatorPolicy({accountId,applicationRegion}){
  const policy=generalizedLanePolicy(accountId,applicationRegion);
  // Aggregate inline policies on a role are limited to 10,240 characters.
  check(JSON.stringify(policy).length<=10240,'PolicyTooLarge');
  return freeze(policy);
}

// Every role ARN glob the CI deploy roles are granted, from the reviewed
// template with its parameter defaults. IAM's `*` crosses `/`, so each is
// matched against the owner's whole ARN, path included.
const CI_ROLE_TEMPLATE=new URL('../../infra/cloudformation/github-actions-role.yaml',import.meta.url);
function ciRoleGlobs(accountId){
  const text=readFileSync(CI_ROLE_TEMPLATE,'utf8'),defaults={};
  for(const name of ['ProjectName','GitHubRepo']){
    const match=new RegExp('^  '+name+':\\n(?:    .*\\n)*?    Default: ([a-z0-9-]+)$','m').exec(text);check(match,'CiTemplate');defaults[name]=match[1];
  }
  const globs=[...text.matchAll(/arn:(?:\$\{AWS::Partition\}|aws):iam::\$\{AWS::AccountId\}:role\/[^\s"',\]]+/g)].map(m=>m[0]
    .replace('${AWS::Partition}','aws').replace('${AWS::AccountId}',accountId).replaceAll('${ProjectName}',defaults.ProjectName).replaceAll('${GitHubRepo}',defaults.GitHubRepo));
  check(globs.length>0&&globs.every(g=>!g.includes('${')),'CiTemplate');
  return globs;
}
/** Why an owner role may not hold the operator trust, or null. The operator
 * itself would renew its own sessions. A role whose path or name starts with
 * mem9-on-a or github-actions-mem9-on-aws, or that any CI deploy-role grant
 * names, is administered or assumed by CI. The whole path and name count, not
 * only the last segment, and IAM role names compare case-insensitively. */
export function gatewayCanaryOwnerRoleRefusal(ownerRoleArn){
  const match=typeof ownerRoleArn==='string'&&/^arn:aws:iam::(\d{12}):role\/([\w+=,.@/-]{1,512})$/.exec(ownerRoleArn);
  if(!match||match[2].split('/').some(segment=>segment===''))return 'malformed';
  const path=match[2].toLowerCase(),segments=path.split('/');
  if(segments.at(-1)===GATEWAY_CANARY_OPERATOR_ROLE_NAME)return 'operator';
  if([path,...segments].some(s=>s.startsWith('mem9-on-a')))return 'project-role';
  if([path,...segments].some(s=>s.startsWith('github-actions-mem9-on-aws')))return 'deploy-role';
  if(ciRoleGlobs(match[1]).some(glob=>globMatches(glob,ownerRoleArn)))return 'ci-granted';
  return null;
}
export function assertGatewayCanaryOwnerRole(ownerRoleArn){check(gatewayCanaryOwnerRoleRefusal(ownerRoleArn)===null,'Owner');return ownerRoleArn;}

/** The simulation cases proving the owner already holds every operator
 * permission: each statement's actions on concrete sample resources (a fixed
 * verification id, stack and key id), with its condition values and the
 * owner's own ARN as context. */
const SAMPLE={verificationId:'abcdef012345',uuid:'11111111-2222-4333-8444-555555555555'};
export function gatewayCanaryOperatorSimulationCases({accountId,applicationRegion,ownerRoleArn}){
  assertGatewayCanaryOwnerRole(ownerRoleArn);
  const sample=r=>r==='*'?'*':/:(stack\/[^/]+|key)\/\*$/.test(r)?r.slice(0,-1)+SAMPLE.uuid:r.endsWith('*')?r.slice(0,-1)+'sample':r;
  // One request per combination of condition values, so every value a
  // multi-valued condition admits (e.g. both permissions boundaries) is covered.
  const combinations=entries=>entries.reduce((all,[key,value])=>all.flatMap(prefix=>[value].flat().map(v=>[...prefix,{ContextKeyName:key,ContextKeyValues:[v],ContextKeyType:'string'}])),[[]]);
  const principal={ContextKeyName:'aws:PrincipalArn',ContextKeyValues:[ownerRoleArn],ContextKeyType:'string'};
  return freeze(lanePolicyStatements(accountId,applicationRegion,SAMPLE.verificationId).flatMap(s=>
    combinations(Object.values(s.Condition??{}).flatMap(e=>Object.entries(e))).map(entries=>
      ({ActionNames:[s.Action].flat(),ResourceArns:[s.Resource].flat().map(sample),ContextEntries:[...entries,principal]}))));
}

/** The owner role's own identity policies and permissions boundary: every
 * inline policy, every attached managed policy at its default version, and the
 * boundary document if one is set. Explicit denies are kept. Any truncated
 * list, more than ten policies, an oversize document or a read error fails. */
export const GATEWAY_CANARY_OWNER_POLICY_LIMITS=Object.freeze({policies:10,characters:131072});
const policyText=v=>{
  let document=v;
  if(typeof v==='string'){try{document=JSON.parse(v);}catch{document=JSON.parse(decodeURIComponent(v));}}
  check(document&&typeof document==='object'&&!Array.isArray(document)&&document.Statement!==undefined,'OwnerPolicies');
  const text=JSON.stringify(document);check(text.length<=GATEWAY_CANARY_OWNER_POLICY_LIMITS.characters,'OwnerPolicyTooLarge');
  return text;
};
export async function readGatewayCanaryOwnerPolicies({iam,ownerRoleArn}){
  assertGatewayCanaryOwnerRole(ownerRoleArn);
  const RoleName=ownerRoleArn.slice(ownerRoleArn.lastIndexOf('/')+1);
  const role=(await iam('get-role',{RoleName})).Role;check(role?.Arn===ownerRoleArn,'OwnerPolicies');
  const inline=await iam('list-role-policies',{RoleName}),attached=await iam('list-attached-role-policies',{RoleName});
  check(!inline.IsTruncated&&!inline.Marker&&Array.isArray(inline.PolicyNames)&&!attached.IsTruncated&&!attached.Marker&&Array.isArray(attached.AttachedPolicies),'OwnerPolicies');
  const count=inline.PolicyNames.length+attached.AttachedPolicies.length;
  check(count>0&&count<=GATEWAY_CANARY_OWNER_POLICY_LIMITS.policies,'OwnerPolicyCount');
  const managed=async PolicyArn=>{
    const policy=(await iam('get-policy',{PolicyArn})).Policy;check(policy?.Arn===PolicyArn&&/^v[1-9][0-9]*$/.test(policy.DefaultVersionId??''),'OwnerPolicies');
    const version=(await iam('get-policy-version',{PolicyArn,VersionId:policy.DefaultVersionId})).PolicyVersion;
    check(version?.VersionId===policy.DefaultVersionId&&version.IsDefaultVersion===true,'OwnerPolicies');
    return policyText(version.Document);
  };
  const policies=[];
  for(const PolicyName of inline.PolicyNames){const r=await iam('get-role-policy',{RoleName,PolicyName});check(r?.PolicyName===PolicyName,'OwnerPolicies');policies.push(policyText(r.PolicyDocument));}
  for(const a of attached.AttachedPolicies)policies.push(await managed(a.PolicyArn));
  const boundaryArn=role.PermissionsBoundary?.PermissionsBoundaryArn;
  // The role's tags are its aws:PrincipalTag values; a Deny keyed on them must apply.
  const tags=role.Tags??[];check(Array.isArray(tags)&&tags.every(t=>typeof t?.Key==='string'&&typeof t.Value==='string'),'OwnerPolicies');
  return freeze({policies,boundary:boundaryArn?await managed(boundaryArn):null,tags:tags.map(t=>({Key:t.Key,Value:t.Value}))});
}
/** iam:SimulateCustomPolicy requests: the owner's documents with each case,
 * and the owner role's tags as aws:PrincipalTag context. Organizations
 * policies are deliberately absent. That is sound only while no SCP or RCP
 * treats the owner differently from the operator, which the operator
 * acknowledges with GATEWAY_CANARY_ORG_POLICIES_PRINCIPAL_NEUTRAL=true and
 * checkGatewayCanaryOrganizationPolicies checks where it can.
 * SimulatePrincipalPolicy's Organizations evaluation can deny actions the same
 * principal performs successfully, so it cannot be used. */
export function gatewayCanaryOwnerSimulationRequests({accountId,applicationRegion,ownerRoleArn,owner}){
  check(Array.isArray(owner?.policies)&&owner.policies.length>0,'OwnerPolicies');
  const principalTags=(owner.tags??[]).map(t=>({ContextKeyName:'aws:PrincipalTag/'+t.Key,ContextKeyValues:[t.Value],ContextKeyType:'string'}));
  return gatewayCanaryOperatorSimulationCases({accountId,applicationRegion,ownerRoleArn}).map(c=>freeze({PolicyInputList:[...owner.policies],
    ...(owner.boundary?{PermissionsBoundaryPolicyInputList:[owner.boundary]}:{}),...structuredClone(c),ContextEntries:[...structuredClone(c.ContextEntries),...principalTags],MaxItems:1000}));
}

/** The acknowledgement the simulation's SCP/RCP exclusion depends on. */
export const GATEWAY_CANARY_ORG_POLICIES_ACK='GATEWAY_CANARY_ORG_POLICIES_PRINCIPAL_NEUTRAL';
export const gatewayCanaryOrganizationPoliciesAcknowledged=environment=>environment?.[GATEWAY_CANARY_ORG_POLICIES_ACK]==='true';
// Condition keys (and policy variables) through which an SCP or RCP can treat
// the owner and the operator differently although both are in one account:
// every aws:Principal* key, aws:userid and aws:SourceIdentity. Some aws:Principal*
// keys (PrincipalAccount, PrincipalOrgID) cannot tell the two apart, but the
// scan refuses them too rather than judge each key.
const PRINCIPAL_KEYS=['aws:principal','aws:userid','aws:sourceidentity'];
const principalKey=key=>PRINCIPAL_KEYS.some(p=>String(key).toLowerCase().startsWith(p));
/** Whether a policy document conditions on, or interpolates, a principal key.
 * The parsed document is walked: every Condition key, and every ${...}
 * variable in any string, so JSON \u escapes cannot hide one. A raw
 * lowercased substring check stays as a backstop. Unparseable content fails. */
export function organizationPolicyKeysPrincipal(content){
  if(PRINCIPAL_KEYS.some(key=>content.toLowerCase().includes(key)))return true;
  let document;try{document=JSON.parse(content);}catch{check(false,'OrgPolicyUnparseable');}
  const walk=v=>{
    if(typeof v==='string')return [...v.matchAll(/\$\{([^}]*)\}/g)].some(m=>principalKey(m[1].trim()));
    if(Array.isArray(v))return v.some(walk);
    if(!v||typeof v!=='object')return false;
    return Object.entries(v).some(([k,x])=>walk(k)||walk(x));
  };
  const statements=[document?.Statement].flat().filter(Boolean);
  return statements.some(s=>Object.values(s?.Condition??{}).some(entries=>Object.keys(entries??{}).some(principalKey)))||walk(document);
}
const serviceError=(error,codes)=>typeof error?.stderr==='string'&&codes.some(code=>error.stderr.includes(`(${code})`));
/** Best-effort scan of every SCP and RCP that applies to the account, through
 * its OU chain to the root. Any principal-specific key refuses, even with the
 * acknowledgement. A not-in-organization account is trivially neutral. When the
 * policies cannot be read completely, the result says so and only the
 * acknowledgement stands. */
export async function checkGatewayCanaryOrganizationPolicies({organizations,accountId}){
  const targets=[accountId];
  try{
    for(let child=accountId,depth=0;;depth++){
      check(depth<8,'OrgHierarchy');
      const parents=await organizations('list-parents',{ChildId:child});
      check(Array.isArray(parents.Parents)&&parents.Parents.length===1&&!parents.NextToken,'OrgHierarchy');
      const parent=parents.Parents[0];targets.push(parent.Id);
      if(parent.Type==='ROOT')break;
      check(parent.Type==='ORGANIZATIONAL_UNIT','OrgHierarchy');child=parent.Id;
    }
  }catch(error){
    if(serviceError(error,['AWSOrganizationsNotInUseException']))return freeze({status:'not-in-organization',policies:0});
    return freeze({status:'unreadable',policies:0});
  }
  const seen=new Map();
  for(const target of targets)for(const filter of ['SERVICE_CONTROL_POLICY','RESOURCE_CONTROL_POLICY']){
    let listed;
    try{listed=await organizations('list-policies-for-target',{TargetId:target,Filter:filter});}
    catch(error){if(serviceError(error,['PolicyTypeNotEnabledException']))continue;return freeze({status:'unreadable',policies:seen.size});}
    if(listed.NextToken||!Array.isArray(listed.Policies))return freeze({status:'unreadable',policies:seen.size});
    for(const policy of listed.Policies){
      if(seen.has(policy.Id))continue;
      let content;
      try{content=(await organizations('describe-policy',{PolicyId:policy.Id})).Policy?.Content;}catch{return freeze({status:'unreadable',policies:seen.size});}
      if(typeof content!=='string')return freeze({status:'unreadable',policies:seen.size});
      check(!organizationPolicyKeysPrincipal(content),'OrgPolicyPrincipalScoped');
      seen.set(policy.Id,filter);
    }
  }
  return freeze({status:'principal-neutral',policies:seen.size});
}
/** The same cases with only the operator's own deployed policy, rendered for
 * this account and region. They make the comparison symmetric: the simulator
 * applies every listed action to every listed resource and returns implicitDeny
 * for resource-type mismatches (and for some valid pairs). Such pairs are not
 * operator permissions, so the owner need not hold them. */
export function gatewayCanaryOperatorSimulationRequests({accountId,applicationRegion,ownerRoleArn}){
  const operator=JSON.stringify(gatewayCanaryOperatorPolicy({accountId,applicationRegion}));
  return gatewayCanaryOperatorSimulationCases({accountId,applicationRegion,ownerRoleArn}).map(c=>freeze({PolicyInputList:[operator],...structuredClone(c),MaxItems:1000}));
}
/** The decision for every requested (action, resource) pair. A truncated or
 * incomplete response fails; action names compare case-insensitively. */
export function gatewayCanarySimulationDecisions(request,response){
  check(response&&!response.IsTruncated&&Array.isArray(response.EvaluationResults),'Simulation');
  const decisions=new Map();
  for(const r of response.EvaluationResults){
    const specific=Array.isArray(r.ResourceSpecificResults)&&r.ResourceSpecificResults.length?r.ResourceSpecificResults.map(x=>[x.EvalResourceName,x.EvalResourceDecision]):[[r.EvalResourceName,r.EvalDecision]];
    for(const [resource,decision] of specific)decisions.set(String(r.EvalActionName).toLowerCase()+' '+resource,decision==='allowed'&&r.EvalDecision==='allowed');
  }
  const pairs=request.ActionNames.flatMap(a=>request.ResourceArns.map(r=>a.toLowerCase()+' '+r));
  check(pairs.every(pair=>decisions.has(pair)),'Simulation');
  return new Map(pairs.map(pair=>[pair,decisions.get(pair)]));
}
/** The pairs the simulator denies the operator although its policy names
 * them, derived from the statements alone: an IAM action on a resource of the
 * other type (a role action on a policy ARN, a policy action on a role ARN), and
 * logs:GetLogEvents on a log-stream ARN. Every other pair must be allowed. */
export function gatewayCanaryExpectedOperatorDenials(request){
  const type=resource=>resource.includes(':role/')?'role':resource.includes(':policy/')?'policy':null;
  return new Set(request.ActionNames.flatMap(action=>request.ResourceArns.filter(resource=>{
    const a=action.toLowerCase();
    if(a.startsWith('iam:')&&type(resource))return (a.includes('role')?'role':'policy')!==type(resource);
    return a==='logs:getlogevents'&&resource.includes(':log-stream:');
  }).map(resource=>action.toLowerCase()+' '+resource)));
}
/** The operator must be allowed exactly the expected pairs: a simulator or
 * compiler drift that newly denies, or newly allows, any pair fails. */
export function verifyGatewayCanaryOperatorDecisions(request,operator){
  const denials=gatewayCanaryExpectedOperatorDenials(request);
  for(const [pair,granted] of operator)check(granted===!denials.has(pair),'OperatorSimulationDrift');
  return operator.size-denials.size;
}
/** Every pair the operator is allowed must be allowed to the owner. */
export function compareGatewayCanaryOwnerToOperator(operator,owner){
  let allowed=0;
  for(const [pair,granted] of operator){if(!granted)continue;allowed++;check(owner.get(pair)===true,'OwnerLacksPermission');}
  return allowed;
}
/** Read the owner's documents, simulate the operator and the owner on every
 * case, require the operator's decisions to be exactly the expected ones, and
 * require the owner to hold every pair the operator is allowed. */
export async function verifyGatewayCanaryOwnerHoldsOperator({iam,accountId,applicationRegion,ownerRoleArn}){
  const owner=await readGatewayCanaryOwnerPolicies({iam,ownerRoleArn});
  const operatorRequests=gatewayCanaryOperatorSimulationRequests({accountId,applicationRegion,ownerRoleArn});
  const ownerRequests=gatewayCanaryOwnerSimulationRequests({accountId,applicationRegion,ownerRoleArn,owner});
  check(operatorRequests.length===ownerRequests.length,'Simulation');
  let allowed=0;
  for(const [i,operatorRequest] of operatorRequests.entries()){
    const operator=gatewayCanarySimulationDecisions(operatorRequest,await iam('simulate-custom-policy',operatorRequest));
    verifyGatewayCanaryOperatorDecisions(operatorRequest,operator);
    const ownerDecisions=gatewayCanarySimulationDecisions(ownerRequests[i],await iam('simulate-custom-policy',ownerRequests[i]));
    allowed+=compareGatewayCanaryOwnerToOperator(operator,ownerDecisions);
  }
  check(allowed>0,'OperatorSimulationEmpty');
  return freeze({simulations:ownerRequests.length,operatorPairs:allowed,policies:owner.policies.length,boundary:owner.boundary!==null});
}

/** Tag keys a chained owner session forwards as transitive tags besides
 * Project and usage (set by the local credential helper). Role chaining sends
 * every transitive tag, so aws:TagKeys must admit them; their values are not
 * constrained, while Project and usage stay exact. */
export const GATEWAY_CANARY_TRANSITIVE_CALLER_TAG_KEYS=Object.freeze(['User','Host']);
/** Only the exact owner role, with the session tags when they are configured. */
export function gatewayCanaryOperatorTrustPolicy({ownerRoleArn,tags=null}){
  assertGatewayCanaryOwnerRole(ownerRoleArn);
  const tagged=Array.isArray(tags)&&tags.length===2;
  return freeze({Version:'2012-10-17',Statement:[{Effect:'Allow',Principal:{AWS:ownerRoleArn},
    Action:tagged?['sts:AssumeRole','sts:TagSession']:['sts:AssumeRole'],
    ...(tagged?{Condition:{StringEquals:Object.fromEntries(tags.map(t=>['aws:RequestTag/'+t.Key,t.Value])),'ForAllValues:StringEquals':{'aws:TagKeys':[...tags.map(t=>t.Key),...GATEWAY_CANARY_TRANSITIVE_CALLER_TAG_KEYS]}}}:{})}]});
}

/** The committed CloudFormation template, rendered from the same compiler.
 * The account and region are CloudFormation substitutions; a test pins the
 * committed file to this output so the role cannot drift from the lanes. */
export async function renderGatewayCanaryOperatorRoleTemplate(){
  const {stringify}=await import('yaml');
  const policy=generalizedLanePolicy(SENTINEL.accountId,SENTINEL.region);
  check(!JSON.stringify(policy).includes('${'),'Generalization');
  const sub=v=>typeof v==='string'?v.includes(SENTINEL.accountId)||v.includes(SENTINEL.region)
    ?{'Fn::Sub':v.replaceAll(SENTINEL.accountId,'${AWS::AccountId}').replaceAll(SENTINEL.region,'${ApplicationRegion}')}:v
    :Array.isArray(v)?v.map(sub):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).map(([k,x])=>[k,sub(x)])):v;
  const template={
    AWSTemplateFormatVersion:'2010-09-09',
    Description:'Ephemeral operator role for the Gateway source-condition canary; delete it after the canary window. Generated by scripts/lib/gateway-canary-operator-role.mjs; do not edit by hand.',
    Parameters:{
      OwnerRoleName:{Type:'String',Description:'Path and name of the same-account owner role allowed to assume this role.',AllowedPattern:'^[\\w+=,.@/-]{1,512}$'},
      ApplicationRegion:{Type:'String',AllowedPattern:'^[a-z]{2}-[a-z]+-[0-9]$'},
      SessionTagProject:{Type:'String',Default:'',AllowedPattern:'^[a-z0-9-]{0,64}$'},
      SessionTagUsage:{Type:'String',Default:'',AllowedPattern:'^((cc|codex)-[a-z0-9-]{1,64})?$'},
    },
    Conditions:{HasSessionTags:{'Fn::Not':[{'Fn::Equals':[{Ref:'SessionTagProject'},'']}]}},
    // Delete, not Retain: deleting the stack must remove the role.
    Resources:{GatewayCanaryOperatorRole:{Type:'AWS::IAM::Role',DeletionPolicy:'Delete',UpdateReplacePolicy:'Delete',Properties:{
      RoleName:GATEWAY_CANARY_OPERATOR_ROLE_NAME,
      Description:'Gateway source-condition canary lanes; assumed only by the owner role',
      MaxSessionDuration:3600,
      AssumeRolePolicyDocument:{Version:'2012-10-17',Statement:[{Effect:'Allow',
        Principal:{AWS:{'Fn::Sub':'arn:aws:iam::${AWS::AccountId}:role/${OwnerRoleName}'}},
        Action:{'Fn::If':['HasSessionTags',['sts:AssumeRole','sts:TagSession'],['sts:AssumeRole']]},
        Condition:{'Fn::If':['HasSessionTags',{StringEquals:{'aws:RequestTag/Project':{Ref:'SessionTagProject'},'aws:RequestTag/usage':{Ref:'SessionTagUsage'}},
          'ForAllValues:StringEquals':{'aws:TagKeys':['Project','usage',...GATEWAY_CANARY_TRANSITIVE_CALLER_TAG_KEYS]}},{Ref:'AWS::NoValue'}]}}]},
      Policies:[{PolicyName:GATEWAY_CANARY_OPERATOR_POLICY_NAME,PolicyDocument:sub(policy)}],
      Tags:[{Key:'Project',Value:'mem9-on-aws'},{Key:'ManagedBy',Value:'cloudformation'}],
    }}},
    Outputs:{RoleArn:{Value:{'Fn::GetAtt':['GatewayCanaryOperatorRole','Arn']}}},
  };
  return '# Generated by scripts/lib/gateway-canary-operator-role.mjs (renderGatewayCanaryOperatorRoleTemplate).\n'+
    '# With session tags, aws:TagKeys also admits User and Host: a chained owner session forwards them as\n'+
    '# transitive tags (role chaining sends every transitive tag), so a Project/usage-only list would deny it.\n'+
    '# Project and usage values stay exact; nothing else is admitted.\n'+
    '# The trust names the owner role, so it is equivalent to an unrestricted session of that role: it admits\n'+
    '# every session of it, including a narrowed one, and session policies are not visible to the owner check.\n'+
    '# Never give a scoped or narrowed owner session sts:AssumeRole or sts:TagSession on this role.\n'+
    '# The role is ephemeral (DeletionPolicy Delete): deploy it for a canary window, then remove it with\n'+
    '# scripts/deploy-gateway-canary-operator-role.sh --delete. Left in place it keeps trusting an owner whose\n'+
    '# permissions may since have been narrowed, and the owner check runs only at deploy and broker start.\n'+
    '# Regenerate instead of editing: node -e "import(\'./scripts/lib/gateway-canary-operator-role.mjs\').then(async m=>process.stdout.write(await m.renderGatewayCanaryOperatorRoleTemplate()))" > infra/cloudformation/gateway-canary-operator-role.yaml\n'+
    // Quote the format and policy versions, which a YAML 1.1 parser reads as
    // dates, and a bare wildcard value, which would begin with an indicator.
    stringify(template,{lineWidth:0}).replace(/: (2010-09-09|2012-10-17)$/gm,': "$1"').replace(/([:-]) (\?{12})$/gm,'$1 "$2"');
}

export const gatewayCanaryOperatorDocumentHash=hash;
