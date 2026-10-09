import {nonrootHash as hash,parseNonrootJson,inspectNonrootRecord} from './production-nonroot-contracts.mjs';
import {readNonrootEvidence} from './production-nonroot-runtime.mjs';
import {verifyNonrootPostApplyDeployment,verifyPostApplyEndpoints,verifyPostApplySecurityGroups} from './nonroot-postapply.mjs';

const need=(v,c)=>{if(!v)throw Error(c);};
const same=(a,b,c)=>need(hash(a)===hash(b),c);
const exact=(v,keys,c)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.toSorted().join(),c);
const fresh=(t,now)=>need(Number.isSafeInteger(t)&&t<=now&&now-t<=300000,'RootPrerequisiteExpired');
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const array=(v,n,c)=>need(Array.isArray(v)&&v.length<=n,c);
const profile=(service,action,count,requestBytes=16384,responseBytes=1048576)=>Object.freeze({service,action,count,requestBytes,responseBytes,lane:'normal'});
/** Additional calls, never aliases for the original 155 operations. */
export const ROOT_PREREQUISITE_PROFILES=Object.freeze({
 'prerequisite.role':profile('iam','GetRole',10),
 'prerequisite.attached':profile('iam','ListAttachedRolePolicies',20),
 'prerequisite.inlineList':profile('iam','ListRolePolicies',20),
 'prerequisite.policy':profile('iam','GetPolicy',64),
 'prerequisite.policyVersion':profile('iam','GetPolicyVersion',64),
 'prerequisite.inline':profile('iam','GetRolePolicy',64),
 'prerequisite.simulate':profile('iam','SimulateCustomPolicy',9,1048576),
 'prerequisite.organization':profile('organizations','DescribeOrganization',2),
 'prerequisite.bucket':profile('s3','GetBucketPolicy',2),
 'prerequisite.keyPolicy':profile('kms','GetKeyPolicy',8),
 'prerequisite.grants':profile('kms','ListGrants',16),
 'prerequisite.secretPolicy':profile('secretsmanager','GetResourcePolicy',2),
 'prerequisite.parameterPolicies':profile('ssm','GetResourcePolicies',2),
 'prerequisite.repositoryPolicy':profile('ecr','GetRepositoryPolicy',2),
 'prerequisite.endpoints':profile('ec2','DescribeVpcEndpoints',4),
 'prerequisite.subnets':profile('ec2','DescribeSubnets',2),
 'prerequisite.securityGroups':profile('ec2','DescribeSecurityGroups',2),
 'prerequisite.scanner':profile('accessanalyzer','ValidatePolicy',32,1048576),
 'health.parameters':profile('ssm','GetParameters',5,16384,262144),
 'health.target':profile('agentcore','GetGatewayTarget',2),
 'health.function':profile('lambda','GetFunctionConfiguration',2),
 'health.instances':profile('servicediscovery','ListInstances',4),
 'health.token':profile('https','OAuthToken',1,16384,65536),
 'health.initialize':profile('https','McpInitialize',1,16384,65536),
 'health.tools':profile('https','McpTools',1,16384,262144),
 'health.search':profile('https','McpKeywordSearch',1,16384,65536),
});

export function rootPrerequisiteProfileDelta(){
 const rows=Object.values(ROOT_PREREQUISITE_PROFILES);
 return {calls:rows.reduce((n,r)=>n+r.count,0)+20,ecrRequests:2,sourceSessions:4,sourceMetadataCalls:8,sourceStsCalls:12,cleanupCredentialBytes:524288,wireQuotaIncrease:0,localQuotaIncrease:0};
}
export function decodeRootPolicy(value){
 if(typeof value==='string')value=parseNonrootJson(value.trimStart().startsWith('{')?value:decodeURIComponent(value));
 need(value&&typeof value==='object'&&!Array.isArray(value),'RootPermissionPolicy');
 // Omitted Version uses IAM's 2008-10-17 semantics (no variable interpolation).
 // Preserve the document: inserting a default would change evidence hashes.
 need(!Object.hasOwn(value,'Version')||['2012-10-17','2008-10-17'].includes(value.Version),'RootPermissionPolicy');
 const rows=Array.isArray(value.Statement)?value.Statement:[value.Statement];
 need(rows.length>0&&rows.length<=128&&rows.every(r=>r&&['Allow','Deny'].includes(r.Effect)),'RootPermissionPolicy');return value;
}

export function decodeRootIdentityPolicy(value){
 const p=decodeRootPolicy(value);
 for(const s of Array.isArray(p.Statement)?p.Statement:[p.Statement]){
  need(!Object.hasOwn(s,'Principal')&&!Object.hasOwn(s,'NotPrincipal'),'RootPermissionIdentityPrincipal');
  need((s.Action!==undefined)!==(s.NotAction!==undefined)&&(s.Resource!==undefined)!==(s.NotResource!==undefined),'RootPermissionIdentityStatement');
 }
 return p;
}

/** References only: never a value, name lookup, ARN suffix selector or URL. */
export function inspectRootAdministratorCredential(value,{account,region}){
 exact(value,['service','arn'],'RootCredentialFields');
 need(['ssm','secretsmanager'].includes(value.service)&&typeof value.arn==='string'&&value.arn.length<=2048,'RootCredentialReference');
 const prefix=`arn:aws:${value.service}:${region}:${account}:`;
 need(value.arn.startsWith(prefix),'RootCredentialScope');
 const tail=value.arn.slice(prefix.length);
 need(value.service==='ssm'?/^parameter\/mem9-on-aws\/prod\/[A-Za-z0-9_.\/-]+$/.test(tail):/^secret:mem9-on-aws-prod-[A-Za-z0-9_+=.@\/-]+$/.test(tail),'RootCredentialReference');
 need(!tail.includes('//')&&!tail.split('/').some(s=>s==='.'||s==='..'),'RootCredentialReference');
 return value;
}

export function rootCredentialPolicyRequest(credential,scope){
 const c=inspectRootAdministratorCredential(credential,scope);
 return c.service==='ssm'?{ResourceArn:c.arn,MaxResults:50}:{SecretId:c.arn};
}

/** The commitment includes the provider and exact ARN even for an empty set.
 * PolicyHash from SSM is an opaque version, never a claimed content digest. */
export function normalizeRootCredentialPolicies(credential,response){
 const text=v=>typeof v==='string'&&v.length>0&&v.length<=256&&!/[\r\n]/.test(v);
 let policies;
 if(credential.service==='ssm'){
  need(!response.NextToken&&Array.isArray(response.Policies)&&response.Policies.length<=50,'RootCredentialPoliciesIncomplete');
  const ids=new Set();policies=response.Policies.map(p=>{need(text(p.PolicyId)&&text(p.PolicyHash)&&!ids.has(p.PolicyId)&&typeof p.Policy==='string','RootCredentialPolicyEntry');ids.add(p.PolicyId);return {policyId:p.PolicyId,policyVersion:p.PolicyHash,document:decodeRootPolicy(p.Policy)};}).sort((a,b)=>a.policyId.localeCompare(b.policyId));
 }else{
  need(credential.service==='secretsmanager'&&response.ARN===credential.arn,'RootCredentialResponseIdentity');
  policies=response.ResourcePolicy===undefined?[]:[{document:decodeRootPolicy(response.ResourcePolicy)}];
 }
 return {service:credential.service,arn:credential.arn,policies};
}

export function verifyRootSimulation(row,expected){
 exact(row,['request','response','observedMs'],'RootPermissionSimulation');same(row.request,expected.request,'RootPermissionSimulationRequest');
 const r=row.response;need(r&&r.IsTruncated!==true&&!r.Marker&&Array.isArray(r.EvaluationResults),'RootPermissionSimulationPage');
 const cases=new Map(expected.cases.map(c=>[c.action+'\0'+c.resource,c]));need(cases.size===expected.cases.length,'RootPermissionCases');
 for(const e of r.EvaluationResults){
  need(!e.MissingContextValues?.length,'RootPermissionMissingContext');
  for(const item of e.ResourceSpecificResults?.length?e.ResourceSpecificResults:[e]){
   const key=e.EvalActionName+'\0'+item.EvalResourceName,c=cases.get(key);need(c&&!item.MissingContextValues?.length,'RootPermissionSimulationCoverage');cases.delete(key);
   const decision=item.EvalResourceDecision??item.EvalDecision;
   need(c.allowed?decision==='allowed':['explicitDeny','implicitDeny'].includes(decision),'RootPermissionSimulationDecision');
   if(c.allowed&&expected.boundary)need((item.PermissionsBoundaryDecisionDetail??e.PermissionsBoundaryDecisionDetail)?.AllowedByPermissionsBoundary===true,'RootPermissionBoundary');
   if(c.allowed)for(const d of Object.values(item.EvalDecisionDetails??{}))need(d==='allowed','RootPermissionSimulationDecision');
  }
 }
 need(cases.size===0,'RootPermissionSimulationCoverage');return row;
}

function actionMatches(statement,action){
 const list=v=>Array.isArray(v)?v:[v],match=(pattern,value)=>new RegExp('^'+String(pattern).split('*').map(s=>s.split('?').map(t=>RegExp.escape(t)).join('.')).join('.*')+'$','i').test(value);
 if(statement.Action!==undefined)return list(statement.Action).some(p=>match(p,action));
 need(statement.NotAction!==undefined,'RootPermissionAction');return !list(statement.NotAction).some(p=>match(p,action));
}
/** Conservative whole-family coverage, not a sampled revision's permission.
 * Unsupported grants/denies HOLD rather than approximating IAM evaluation. */
export function verifyRootRunPolicyCoverage(documents,scope){
 const action='ecs:RunTask',resource=`arn:aws:ecs:${scope.region}:${scope.account}:task-definition/${scope.family}:*`;
 const context={'aws:RequestedRegion':scope.region,'aws:PrincipalArn':`arn:aws:iam::${scope.account}:role/BedrockTrackedInvoke`,'aws:PrincipalAccount':scope.account,'ecs:cluster':scope.clusterArn,'aws:RequestTag/mem9-supersession-owner':scope.owner,'aws:TagKeys':['mem9-supersession-owner']};
 let allowed=false;
 for(const d of documents){const policy=decodeRootIdentityPolicy(d);for(const s of Array.isArray(policy.Statement)?policy.Statement:[policy.Statement]){
  if(!actionMatches(s,action))continue;
  // A revision-specific deny cannot be dismissed before the actual revision
  // exists. The fixed production route accepts only demonstrable coverage.
  need(s.Effect!=='Deny','RootPermissionRunDeny');
  const resources=Array.isArray(s.Resource)?s.Resource:[s.Resource];if(!resources.includes('*')&&!resources.includes(resource))continue;
  for(const [operator,conditions]of Object.entries(s.Condition??{})){
   need(['StringEquals','ArnEquals','ForAllValues:StringEquals','Null'].includes(operator),'RootPermissionRunCondition');
   for(const [key,value]of Object.entries(conditions)){
    need(Object.hasOwn(context,key),'RootPermissionRunContext');
    if(operator==='Null'){need(String(value)==='false','RootPermissionRunCondition');continue;}
    const wanted=Array.isArray(value)?value:[value],actual=Array.isArray(context[key])?context[key]:[context[key]];
    need(actual.every(v=>wanted.includes(v)),'RootPermissionRunCondition');
   }
  }allowed=true;
 }}
 need(allowed,'RootPermissionRunCoverage');return true;
}

/** Shared semantics for the nine existing refs. Raw observations are supplied
 * by the authenticated collector/archive; this function never mints authority. */
export async function verifyRootPermissionsDossier(value,{expected,...resolvers}){
 const p=inspectNonrootRecord('PermissionsDossierV1',value),now=expected.now;fresh(p.observedMs,now);
 need(p.account===expected.account&&p.applicationRegion===expected.region&&p.iamRegion===expected.iamRegion&&p.carrierRunTaskContractHash===expected.runTaskContractHash,'RootPermissionScope');
 const json=ref=>readNonrootEvidence(ref,resolvers),[caller,actors,identity,boundary,resources,controls,matrix,tests,scanner]=await Promise.all([
  p.caller,p.actorBindings,p.identityPolicies,p.boundaries,p.trustAndResourcePolicies,p.organizationAndEndpointControls,p.actionMatrix,p.positiveNegativeTests,p.analyzerScannerReview,
 ].map(json));
 need(caller.Account===expected.account&&caller.Arn===expected.callerArn,'RootPermissionCaller');
 exact(actors,['kind','owner','roles','scopeHash'],'RootPermissionActors');need(actors.kind==='root-permission-actors'&&actors.owner===expected.owner&&actors.scopeHash===expected.scopeHash,'RootPermissionActors');
 same(actors.roles,expected.roles,'RootPermissionActors');array(identity.snapshots,2,'RootPermissionSnapshots');need(identity.kind==='root-policy-snapshots'&&identity.snapshots.length===2,'RootPermissionSnapshots');
 let first;
 for(const snap of identity.snapshots){
  fresh(snap.observedMs,now);array(snap.roles,8,'RootPermissionRoles');need(snap.roles.length===actors.roles.length,'RootPermissionRoles');
  const names=new Set();for(const r of snap.roles){
   const actor=actors.roles.find(v=>v.arn===r.role.Arn);need(actor&&!names.has(actor.arn)&&r.role.RoleId===actor.roleId,'RootPermissionRoleIdentity');names.add(actor.arn);
   need(r.role.Arn.split(':')[4]===expected.account&&r.role.RoleName===actor.arn.split('/').at(-1),'RootPermissionRoleIdentity');need(hash(decodeRootPolicy(r.role.AssumeRolePolicyDocument))===expected.resourceHashes['trust:'+actor.arn],'RootPermissionTrustReview');
   array(r.managed,32,'RootPermissionPolicySet');array(r.inline,32,'RootPermissionPolicySet');
   same(r.attached.toSorted(),r.managed.map(x=>x.arn).toSorted(),'RootPermissionManagedCoverage');same(r.inlineNames.toSorted(),r.inline.map(x=>x.name).toSorted(),'RootPermissionInlineCoverage');
   need(new Set(r.attached).size===r.attached.length&&new Set(r.inlineNames).size===r.inlineNames.length,'RootPermissionPolicyDuplicate');
   need(r.attached.every(arn=>expected.policyArns.includes(arn))&&r.inlineNames.every(name=>expected.inlinePolicies[actor.arn].includes(name)),'RootPermissionPolicyScope');
   for(const m of r.managed){need(/^v[1-9][0-9]*$/.test(m.version)&&m.metadata.Arn===m.arn&&m.metadata.DefaultVersionId===m.version&&m.raw.VersionId===m.version&&m.raw.IsDefaultVersion===true,'RootPermissionPolicyVersion');same(decodeRootIdentityPolicy(m.raw.Document),m.document,'RootPermissionPolicyBytes');}
   for(const m of r.inline){need(m.raw.RoleName===r.role.RoleName&&m.raw.PolicyName===m.name,'RootPermissionInlineIdentity');same(decodeRootIdentityPolicy(m.raw.PolicyDocument),m.document,'RootPermissionPolicyBytes');}
   if(r.role.PermissionsBoundary){need(r.boundary&&expected.policyArns.includes(r.boundary.arn)&&r.boundary.arn===r.role.PermissionsBoundary.PermissionsBoundaryArn,'RootPermissionBoundary');same(decodeRootIdentityPolicy(r.boundary.raw.Document),r.boundary.document,'RootPermissionBoundary');need(r.boundary.metadata.Arn===r.boundary.arn&&r.boundary.raw.IsDefaultVersion===true&&r.boundary.raw.VersionId===r.boundary.version&&r.boundary.metadata.DefaultVersionId===r.boundary.version,'RootPermissionBoundary');}
   else need(r.boundary===null,'RootPermissionBoundary');
  }
  const stable=snap.roles.map(r=>{const {RoleLastUsed,...role}=r.role;return {...r,role};});if(first)same(stable,first,'RootPermissionDrift');else first=stable;
 }
 need(identity.snapshots[0].observedMs<=identity.snapshots[1].observedMs,'RootPermissionClock');
 need(identity.snapshots[1].observedMs<=p.observedMs,'RootPermissionClock');
 const owner=first.find(r=>r.role.Arn===`arn:aws:iam::${expected.account}:role/BedrockTrackedInvoke`);need(owner,'RootPermissionOwner');
 verifyRootRunPolicyCoverage([...owner.managed,...owner.inline].map(r=>r.document),expected.runScope);
 if(owner.boundary)verifyRootRunPolicyCoverage([owner.boundary.document],expected.runScope);
 verifyRootRunPolicyCoverage([expected.sessionPolicy],expected.runScope);
 same(boundary,{kind:'root-boundaries',roles:first.map(r=>({arn:r.role.Arn,boundary:r.boundary}))},'RootPermissionBoundary');
 exact(resources,['kind','credentialBinding','before','after'],'RootPermissionResources');need(resources.kind==='root-resource-policies','RootPermissionResources');
 const credential=inspectRootAdministratorCredential(expected.administratorCredential,expected);
 same(resources.credentialBinding,{reference:credential,oldControlBinding:expected.oldControlBinding},'RootCredentialProvenance');
 const original=await json(resources.credentialBinding.oldControlBinding);
 need(original.binding?.operator?.administratorCredential===credential.arn&&original.binding.operator.account===expected.account&&original.binding.operator.region===expected.region,'RootCredentialOriginalBinding');
 same(original.binding.definitions.control.containerDefinitions[0].secrets,[{name:'MEM9_DB_SECRET',valueFrom:credential.arn}],'RootCredentialOriginalBinding');
 same(resources.before.map(r=>r.key).toSorted(),expected.resourceKeys.toSorted(),'RootPermissionResourceCoverage');
 const projection=rows=>rows.map(({responseHash,responseRef,...r})=>r);same(projection(resources.before),projection(resources.after),'RootPermissionResourceDrift');
 for(const r of resources.before){need(hex(r.requestHash)&&hex(r.responseHash)&&r.requestHash===hash(expected.resourceRequests.find(q=>q.id===r.key)?.input),'RootPermissionResourceReceipt');
  if(r.key==='credential'){
   same(expected.resourceRequests.find(q=>q.id===r.key).input,rootCredentialPolicyRequest(credential,expected),'RootCredentialRequest');
   for(const observation of [r,resources.after.find(q=>q.key==='credential')]){
    exact(observation,['key','requestHash','responseHash','responseRef','credentialPolicies'],'RootCredentialPolicyEvidence');
    const response=await json(observation.responseRef);need(hash(response)===observation.responseHash,'RootCredentialResponseHash');same(observation.credentialPolicies,normalizeRootCredentialPolicies(credential,response),'RootCredentialPolicyEvidence');
   }
   need(hash(r.credentialPolicies)===expected.resourceHashes.credential,'RootPermissionResourceReview');continue;
  }
  if(r.grants){array(r.grants,100,'RootPermissionGrants');need(r.policy===null&&new Set(r.grants.map(g=>g.GrantId)).size===r.grants.length,'RootPermissionGrants');}else if(r.policy!==null)decodeRootPolicy(r.policy);else need(['RepositoryPolicyNotFoundException','none-returned'].includes(r.absence),'RootPermissionPolicyAbsence');need(hash(r.grants??r.policy)===expected.resourceHashes[r.key],'RootPermissionResourceReview');}
 exact(controls,['kind','before','after',...(expected.postApply?['postApply']:[])],'RootPermissionControls');need(controls.kind==='root-organization-endpoints','RootPermissionControls');same(controls.before,controls.after,'RootPermissionControlDrift');
 const org=controls.before.organization;need(org.Id===expected.organizationId&&org.MasterAccountId===expected.account&&org.FeatureSet==='ALL','RootPermissionManagementAccount');
 same(controls.before.vpcIds.toSorted(),expected.vpcIds.toSorted(),'RootPermissionEndpointScope');array(controls.before.endpoints,64,'RootPermissionEndpoints');
 same(controls.before.subnets.map(s=>s.SubnetId).sort(),expected.subnetIds.toSorted(),'RootPermissionSubnetScope');
 need(controls.before.subnets.every(s=>s.OwnerId===expected.account),'RootPermissionSubnetOwner');same([...new Set(controls.before.subnets.map(s=>s.VpcId))].sort(),expected.vpcIds.toSorted(),'RootPermissionSubnetVpc');
 need(new Set(controls.before.endpoints.map(e=>e.VpcEndpointId)).size===controls.before.endpoints.length,'RootPermissionEndpointDuplicate');
 for(const e of controls.before.endpoints){need(expected.vpcIds.includes(e.VpcId)&&e.OwnerId===expected.account,'RootPermissionEndpointScope');decodeRootPolicy(e.PolicyDocument);}
 need(hash(controls.before.endpoints)===expected.resourceHashes.endpoints,'RootPermissionEndpointReview');
 if(expected.securityGroupIds){
  array(controls.before.securityGroups,3,'RootPermissionSecurityGroups');same(controls.before.securityGroups.map(g=>g.GroupId).sort(),expected.securityGroupIds.toSorted(),'RootPermissionSecurityGroups');
  need(controls.before.securityGroups.every(g=>g.OwnerId===expected.account&&expected.vpcIds.includes(g.VpcId)),'RootPermissionSecurityGroups');
 }
 if(expected.postApply){
  const evidence=await json(controls.postApply);same(evidence,expected.postApply.evidence,'RootPermissionPostApplySource');
  const deployment=verifyNonrootPostApplyDeployment(evidence.artifact,evidence.expected);
  verifyPostApplyEndpoints(controls.before.endpoints,{baseline:evidence.baseline.endpoints,deployment,account:expected.account});
  verifyPostApplySecurityGroups(controls.before.securityGroups,{baseline:evidence.baseline.securityGroups,oldProxySecurityGroupIds:evidence.oldProxySecurityGroupIds,backendSecurityGroupId:expected.backendSecurityGroupId,deployment,account:expected.account});
 }
 const derived=deriveRootPermissionMatrix({roles:first},{runTaskContract:expected.runTaskContract,scope:expected.runScope,sessionPolicy:expected.sessionPolicy});
 same(matrix,derived,'RootPermissionMatrix');same(matrix,expected.matrix,'RootPermissionMatrix');array(tests.rows,128,'RootPermissionTests');need(tests.kind==='root-policy-simulations'&&tests.rows.length===matrix.length,'RootPermissionTests');
 tests.rows.forEach((r,i)=>{fresh(r.observedMs,now);need(r.observedMs>=identity.snapshots[0].observedMs&&r.observedMs<=identity.snapshots[1].observedMs,'RootPermissionClock');verifyRootSimulation(r,matrix[i]);});
 need(scanner.kind==='root-policy-scanner-review'&&Array.isArray(scanner.policies),'RootPermissionScanner');
 const policies=new Map(first.flatMap(r=>[...r.managed,...r.inline,...(r.boundary?[r.boundary]:[])]).map(r=>[hash(r.document),r.document]));
 same(scanner.policies.map(r=>r.policyHash).toSorted(),[...policies.keys()].sort(),'RootPermissionScannerCoverage');
 for(const r of scanner.policies){fresh(r.observedMs,now);need(r.observedMs>=identity.snapshots[0].observedMs&&r.observedMs<=identity.snapshots[1].observedMs,'RootPermissionClock');need(r.policyHash===hash(decodeRootIdentityPolicy(r.request.policyDocument))&&r.request.policyType==='IDENTITY_POLICY'&&r.request.locale==='EN'&&Array.isArray(r.response.findings)&&!r.response.nextToken,'RootPermissionScanner');
  need(r.response.findings.every(f=>['ERROR','SECURITY_WARNING','WARNING','SUGGESTION'].includes(f.findingType)),'RootPermissionScannerFinding');
  const dangerous=r.response.findings.filter(f=>['ERROR','SECURITY_WARNING'].includes(f.findingType));
  same(dangerous,expected.acceptedFindings?.[r.policyHash]??[],'RootPermissionScannerFinding');
 }
 return {permissionsHash:hash(p),scopeHash:actors.scopeHash,observedMs:p.observedMs};
}

export function decodeRootMcpResponse(raw,id){
 need(typeof raw==='string'&&Buffer.byteLength(raw)<=262144,'RootHealthBody');let rows;
 try{rows=[parseNonrootJson(raw)];}catch{rows=raw.split(/\r?\n\r?\n/).flatMap(frame=>{const text=frame.split(/\r?\n/).filter(l=>l.startsWith('data:')).map(l=>l.slice(5).trimStart()).join('\n');return text?[parseNonrootJson(text)]:[];});}
 const found=rows.filter(r=>r.id===id);need(found.length===1&&found[0].jsonrpc==='2.0'&&!found[0].error&&found[0].result&&!found[0].result.isError,'RootHealthRpc');return found[0].result;
}
export function verifyRootIndependentHealth(v,expected){
 exact(v,['kind','startedMs','completedMs','nonce','taskArn','taskDefinitionArn','endpointHash','sourceHash','configuration','routingBefore','routingAfter','requests'],'RootHealthEvidence');
 need(v.kind==='root-readonly-health'&&hex(v.nonce)&&v.nonce===expected.nonce&&v.taskArn===expected.taskArn&&v.taskDefinitionArn===expected.taskDefinitionArn&&v.endpointHash===expected.endpointHash&&v.sourceHash===expected.sourceHash,'RootHealthScope');
 fresh(v.startedMs,expected.now);fresh(v.completedMs,expected.now);need(v.startedMs<=v.completedMs,'RootHealthClock');
 same(v.configuration,expected.configuration,'RootHealthConfiguration');same(v.routingBefore,v.routingAfter,'RootHealthRouteDrift');same(v.routingBefore,expected.routing,'RootHealthRoute');
 need(v.requests.length===3,'RootHealthRequests');
 const [init,list,search]=v.requests;for(const [i,r]of v.requests.entries()){need(r.statusCode===200&&r.request.id===i+1&&r.request.jsonrpc==='2.0'&&r.observedMs>=v.startedMs&&r.observedMs<=v.completedMs,'RootHealthRequest');fresh(r.observedMs,expected.now);}
 same(init.request.params,{protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'mem9-root-health',version:'1'}},'RootHealthInitialize');need(init.request.method==='initialize'&&decodeRootMcpResponse(init.raw,1).protocolVersion==='2025-03-26','RootHealthInitialize');
 need(list.request.method==='tools/list','RootHealthTools');same(list.request.params,{},'RootHealthTools');const listing=decodeRootMcpResponse(list.raw,2),tools=listing.tools;array(tools,16,'RootHealthTools');need(!listing.nextCursor&&new Set(tools.map(t=>t.name)).size===tools.length,'RootHealthTools');
 const wanted=expected.targetName+'___search_memories';need(tools.filter(t=>t.name===wanted).length===1&&!tools.some(t=>['add_memory','ingest_messages'].some(n=>t.name===n||t.name.endsWith('___'+n))),'RootHealthReadScope');
 need(search.request.method==='tools/call','RootHealthSearch');same(search.request.params,{name:wanted,arguments:{q:'mem9-root-health-'+v.nonce,search_mode:'keyword',limit:1}},'RootHealthSearch');
 const result=decodeRootMcpResponse(search.raw,3);need(result.content?.length===1&&result.content[0].type==='text','RootHealthSearch');const body=parseNonrootJson(result.content[0].text);
 need(Array.isArray(body.memories)&&body.memories.length===0&&body.total===0,'RootHealthUnexpectedData');return {healthHash:hash(v),completedMs:v.completedMs};
}

export function deriveRootPermissionMatrix(snapshot,{runTaskContract,scope,sessionPolicy}){
 const role=snapshot.roles.find(r=>r.role.Arn===`arn:aws:iam::${scope.account}:role/BedrockTrackedInvoke`);need(role,'RootPermissionOwnerRole');
 const context=[{ContextKeyName:'aws:RequestedRegion',ContextKeyType:'string',ContextKeyValues:[scope.region]},{ContextKeyName:'aws:PrincipalArn',ContextKeyType:'string',ContextKeyValues:[role.role.Arn]},{ContextKeyName:'aws:PrincipalAccount',ContextKeyType:'string',ContextKeyValues:[scope.account]},{ContextKeyName:'aws:SecureTransport',ContextKeyType:'boolean',ContextKeyValues:['true']},{ContextKeyName:'iam:PassedToService',ContextKeyType:'string',ContextKeyValues:['ecs-tasks.amazonaws.com']},{ContextKeyName:'ecs:cluster',ContextKeyType:'string',ContextKeyValues:[scope.clusterArn]},{ContextKeyName:'aws:RequestTag/mem9-supersession-owner',ContextKeyType:'string',ContextKeyValues:[scope.owner]},{ContextKeyName:'aws:TagKeys',ContextKeyType:'stringList',ContextKeyValues:['mem9-supersession-owner']}];
 const documents=[...role.managed,...role.inline].map(p=>JSON.stringify(p.document));need(documents.length>0,'RootPermissionIdentityPolicies');
 const rows=[];for(const [action,resource]of [['ecs:RegisterTaskDefinition','*'],['iam:PassRole',scope.taskRoleArn],['iam:PassRole',scope.executionRoleArn]]){
  for(const identity of [true,false]){const request={PolicyInputList:identity?documents:[JSON.stringify(sessionPolicy)],ActionNames:[action],ResourceArns:[resource],ContextEntries:context,...(identity&&role.boundary?{PermissionsBoundaryPolicyInputList:[JSON.stringify(role.boundary.document)]}:{})};rows.push({request,cases:[{action,resource,allowed:true}],boundary:!!(identity&&role.boundary)});}
 }
 for(const roleArn of [scope.taskRoleArn,scope.executionRoleArn])rows.push({request:{PolicyInputList:[JSON.stringify(sessionPolicy)],ActionNames:['iam:PassRole'],ResourceArns:[roleArn],ContextEntries:context.map(c=>c.ContextKeyName==='iam:PassedToService'?{...c,ContextKeyValues:['lambda.amazonaws.com']}:c)},cases:[{action:'iam:PassRole',resource:roleArn,allowed:false}],boundary:false});
 const credential=inspectRootAdministratorCredential(scope.prerequisites.administratorCredential,scope),execution=snapshot.roles.find(r=>r.role.Arn===scope.executionRoleArn);
 need(execution,'RootCredentialExecutionRole');const action=credential.service==='ssm'?'ssm:GetParameters':'secretsmanager:GetSecretValue',policyInputs=[...execution.managed,...execution.inline].map(p=>JSON.stringify(p.document));need(policyInputs.length>0,'RootCredentialExecutionPolicy');
 rows.push({request:{PolicyInputList:policyInputs,ActionNames:[action],ResourceArns:[credential.arn],ContextEntries:context.filter(c=>['aws:RequestedRegion','aws:PrincipalArn','aws:PrincipalAccount','aws:SecureTransport'].includes(c.ContextKeyName)).map(c=>c.ContextKeyName==='aws:PrincipalArn'?{...c,ContextKeyValues:[execution.role.Arn]}:c),...(execution.boundary?{PermissionsBoundaryPolicyInputList:[JSON.stringify(execution.boundary.document)]}:{})},cases:[{action,resource:credential.arn,allowed:true}],boundary:!!execution.boundary});
 need(runTaskContract.cluster===scope.clusterArn,'RootPermissionRunContract');return rows;
}
