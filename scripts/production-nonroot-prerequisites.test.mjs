import {it,expect} from 'vitest';
import {verifyRootIndependentHealth,decodeRootMcpResponse,decodeRootPolicy,verifyRootSimulation,verifyRootRunPolicyCoverage,rootPrerequisiteProfileDelta,inspectRootAdministratorCredential,rootCredentialPolicyRequest,normalizeRootCredentialPolicies} from './lib/production-nonroot-prerequisites.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';

for(const singleton of [false,true])it(`versionless policy preserves its document and commitment (${singleton?'single statement':'statement array'})`,()=>{
 const statement={Effect:'Allow',Principal:'*',Action:'*',Resource:'*'},document=Object.freeze({Statement:singleton?statement:[statement]});
 const raw='\n'+JSON.stringify(document,null,2),commitment=hash(document);
 expect(decodeRootPolicy(document)).toBe(document);
 for(const input of [document,raw,encodeURIComponent(raw)]){
  const decoded=decodeRootPolicy(input);expect(decoded).toEqual(document);expect(Object.hasOwn(decoded,'Version')).toBe(false);expect(hash(decoded)).toBe(commitment);
 }
 expect(hash(document)).toBe(commitment);
});
for(const Version of ['2008-10-17','2012-10-17'])it(`explicit policy version ${Version} remains accepted unchanged`,()=>{
 const document={Version,Statement:{Effect:'Allow',Action:'ecs:RunTask',Resource:'*'}};
 for(const input of [document,JSON.stringify(document),encodeURIComponent(JSON.stringify(document))])expect(decodeRootPolicy(input)).toEqual(document);
});
for(const [label,Version]of [
 ['null',null],['undefined',undefined],['number',20081017],['boolean',true],['object',{}],['array',['2008-10-17']],['empty',''],['unknown','2012-10-18'],['whitespace','2008-10-17 '],
])it(`an explicitly invalid policy version is rejected: ${label}`,()=>{
 const document={Version,Statement:{Effect:'Allow',Action:'*',Resource:'*'}};
 expect(()=>decodeRootPolicy(document)).toThrow('RootPermissionPolicy');
 if(Version!==undefined)for(const input of [JSON.stringify(document),encodeURIComponent(JSON.stringify(document))])expect(()=>decodeRootPolicy(input)).toThrow('RootPermissionPolicy');
});
it('omitted Version does not bypass statement validation or duplicate JSON-key rejection',()=>{
 for(const document of [null,[],{}, {Statement:[]},{Statement:null},{Statement:[{Effect:'pass'}]},{Statement:Array.from({length:129},()=>({Effect:'Allow'}))}])expect(()=>decodeRootPolicy(document)).toThrow('RootPermissionPolicy');
 expect(()=>decodeRootPolicy('{"Version":null,"Version":"2008-10-17","Statement":{"Effect":"Allow"}}')).toThrow();
});
const now=1791500000000,nonce='a'.repeat(64),targetName='prod-mem9-rest';
function health(){
 const packet=(id,method,params,result)=>({request:{jsonrpc:'2.0',id,method,params},statusCode:200,raw:JSON.stringify({jsonrpc:'2.0',id,result}),observedMs:now-10});
 const routing={instance:'synthetic-private-backend'},configuration=[{name:'synthetic-authorized-parameter',version:1}],value={kind:'root-readonly-health',startedMs:now-20,completedMs:now,nonce,taskArn:'synthetic-task',taskDefinitionArn:'synthetic-definition',endpointHash:'b'.repeat(64),sourceHash:'c'.repeat(64),configuration,routingBefore:routing,routingAfter:{...routing},requests:[
  packet(1,'initialize',{protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'mem9-root-health',version:'1'}},{protocolVersion:'2025-03-26'}),
  packet(2,'tools/list',{}, {tools:[{name:targetName+'___search_memories'},{name:targetName+'___get_ingest_job_status'}]}),
  packet(3,'tools/call',{name:targetName+'___search_memories',arguments:{q:'mem9-root-health-'+nonce,search_mode:'keyword',limit:1}},{content:[{type:'text',text:JSON.stringify({memories:[],total:0})}]}),
 ]};
 const expected={now,nonce,taskArn:value.taskArn,taskDefinitionArn:value.taskDefinitionArn,endpointHash:value.endpointHash,sourceHash:value.sourceHash,configuration,routing,targetName};return {value,expected};
}
it('read-only health validates actual RPC contents and target/configuration bindings',()=>{
 const f=health();expect(verifyRootIndependentHealth(f.value,f.expected).completedMs).toBe(now);
 const json=f.value.requests[1].raw;f.value.requests[1].raw='event: message\ndata: '+json+'\n\n';expect(verifyRootIndependentHealth(f.value,f.expected).completedMs).toBe(now);
});
for(const [name,change]of [
 ['JSON PASS',v=>{v.requests[2].raw=JSON.stringify({pass:true});}],
 ['semantic query',v=>{v.requests[2].request.params.arguments.search_mode='semantic';}],
 ['different nonce',v=>{v.nonce='d'.repeat(64);}],
 ['different endpoint',v=>{v.endpointHash='d'.repeat(64);}],
 ['different source',v=>{v.sourceHash='d'.repeat(64);}],
 ['route changes',v=>{v.routingAfter.instance='different';}],
 ['old observation restamped',v=>{v.requests[2].observedMs=v.startedMs-1;}],
 ['HTTP denial',v=>{v.requests[2].statusCode=403;}],
 ['wrong response id',v=>{v.requests[2].raw=v.requests[2].raw.replace('"id":3','"id":4');}],
 ['memory data',v=>{const r=JSON.parse(v.requests[2].raw);r.result.content[0].text=JSON.stringify({memories:[{content:'synthetic'}],total:1});v.requests[2].raw=JSON.stringify(r);}],
 ['write tool exposed',v=>{const r=JSON.parse(v.requests[1].raw);r.result.tools.push({name:targetName+'___add_memory'});v.requests[1].raw=JSON.stringify(r);}],
 ['partial tool discovery',v=>{const r=JSON.parse(v.requests[1].raw);r.result.nextCursor='unread';v.requests[1].raw=JSON.stringify(r);}],
 ['wrong negotiated protocol',v=>{const r=JSON.parse(v.requests[0].raw);r.result.protocolVersion='unknown';v.requests[0].raw=JSON.stringify(r);}],
 ['duplicate matching RPC',v=>{const r=v.requests[2].raw;v.requests[2].raw='data: '+r+'\n\ndata: '+r+'\n\n';}],
])it('health rejects '+name,()=>{const f=health();change(f.value);expect(()=>verifyRootIndependentHealth(f.value,f.expected)).toThrow();});
it('RPC duplicate JSON keys are not accepted after parsing',()=>expect(()=>decodeRootMcpResponse('{"jsonrpc":"2.0","id":1,"id":1,"result":{}}',1)).toThrow());
const scope={account:'123456789012',region:'us-west-2',family:'synthetic-control',owner:'a'.repeat(32),clusterArn:'arn:aws:ecs:us-west-2:123456789012:cluster/synthetic'};
const resource=`arn:aws:ecs:${scope.region}:${scope.account}:task-definition/${scope.family}:*`;
const policy=()=>({Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'ecs:RunTask',Resource:resource,Condition:{ArnEquals:{'ecs:cluster':scope.clusterArn}}}]});
it('omitted Version permits literal RunTask coverage but never interpolates policy variables',()=>{
 const p=policy();delete p.Version;expect(verifyRootRunPolicyCoverage([p],scope)).toBe(true);
 const variableResource=structuredClone(p);variableResource.Statement[0].Resource=resource.replace(scope.account,'${aws:PrincipalAccount}');
 expect(decodeRootPolicy(variableResource).Statement[0].Resource).toContain('${aws:PrincipalAccount}');
 expect(()=>verifyRootRunPolicyCoverage([variableResource],scope)).toThrow('RootPermissionRunCoverage');
 const variableCondition=structuredClone(p);variableCondition.Statement[0].Condition={StringEquals:{'aws:RequestedRegion':'${aws:RequestedRegion}'}};
 expect(()=>verifyRootRunPolicyCoverage([variableCondition],scope)).toThrow('RootPermissionRunCondition');
});
it('RunTask coverage proves a whole fixed family, not a sampled future revision',()=>{
 expect(verifyRootRunPolicyCoverage([policy()],scope)).toBe(true);
 for(const resourceValue of [resource.replace('*','17'),resource.replace('synthetic-control','other')]){const p=policy();p.Statement[0].Resource=resourceValue;expect(()=>verifyRootRunPolicyCoverage([p],scope)).toThrow();}
});
for(const [name,change]of [
 ['a revision deny',p=>p.Statement.push({Effect:'Deny',Action:'ecs:RunTask',Resource:resource.replace('*','18')})],
 ['no RunTask grant',p=>p.Statement[0].Action='iam:PassRole'],
 ['unknown condition context',p=>p.Statement[0].Condition.StringEquals={'callerProvided':true}],
 ['other cluster',p=>p.Statement[0].Condition.ArnEquals['ecs:cluster']='different'],
])it('RunTask rejects '+name,()=>{const p=policy();change(p);expect(()=>verifyRootRunPolicyCoverage([p],scope)).toThrow();});
function simulation(){const request={ActionNames:['iam:PassRole'],ResourceArns:['synthetic-role']},expected={request,cases:[{action:'iam:PassRole',resource:'synthetic-role',allowed:true}],boundary:true},row={request,response:{IsTruncated:false,EvaluationResults:[{EvalActionName:'iam:PassRole',EvalResourceName:'synthetic-role',EvalDecision:'allowed',PermissionsBoundaryDecisionDetail:{AllowedByPermissionsBoundary:true}}]},observedMs:now};return {row,expected};}
it('simulation must cover each exact requested action/resource and real boundary decision',()=>{const f=simulation();expect(verifyRootSimulation(f.row,f.expected)).toBe(f.row);});
for(const [name,change]of [
 ['missing rows',r=>r.response.EvaluationResults=[]],['missing context',r=>r.response.EvaluationResults[0].MissingContextValues=['aws:RequestTag/owner']],
 ['missing boundary',r=>delete r.response.EvaluationResults[0].PermissionsBoundaryDecisionDetail],['another action',r=>r.response.EvaluationResults[0].EvalActionName='ecs:RunTask'],
 ['truncated result',r=>r.response.IsTruncated=true],['denial',r=>r.response.EvaluationResults[0].EvalDecision='explicitDeny'],
])it('simulation rejects '+name,()=>{const f=simulation();change(f.row);expect(()=>verifyRootSimulation(f.row,f.expected)).toThrow();});
it('collector delta reports ECR additions explicitly without raising wire or LOCAL quotas',()=>{
 const d=rootPrerequisiteProfileDelta();expect(d.ecrRequests).toBe(2);expect(d.sourceSessions).toBe(4);expect(d.sourceMetadataCalls).toBe(8);expect(d.sourceStsCalls).toBe(12);expect(d.wireQuotaIncrease).toBe(0);expect(d.localQuotaIncrease).toBe(0);
});

const admin={service:'ssm',arn:'arn:aws:ssm:us-west-2:123456789012:parameter/mem9-on-aws/prod/runtime/schema-administrator-credential'},secret={service:'secretsmanager',arn:'arn:aws:secretsmanager:us-west-2:123456789012:secret:mem9-on-aws-prod-admin-example'};
it('administrator references accept only explicit same-scope SSM and Secrets Manager resources',()=>{
 for(const ref of [admin,secret])expect(inspectRootAdministratorCredential(ref,scope)).toEqual(ref);
 expect(rootCredentialPolicyRequest(admin,scope)).toEqual({ResourceArn:admin.arn,MaxResults:50});expect(rootCredentialPolicyRequest(secret,scope)).toEqual({SecretId:secret.arn});
});
for(const [name,change]of [
 ['other account',v=>v.arn=v.arn.replace('123456789012','0'.repeat(12))],['other region',v=>v.arn=v.arn.replace('us-west-2','us-east-1')],
 ['different provider',v=>v.service='secretsmanager'],['unknown provider',v=>v.service='http'],['bare name',v=>v.arn='/mem9-on-aws/prod/runtime/schema-administrator-credential'],
 ['version selector',v=>v.arn+=':1'],['wildcard',v=>v.arn+='*'],['traversal',v=>v.arn=v.arn.replace('/runtime/','/../')],['foreign prefix',v=>v.arn=v.arn.replace('/mem9-on-aws/prod/','/other/prod/')],
 ['plaintext field',v=>v.value='synthetic-forbidden'],
])it('administrator reference rejects '+name,()=>{const v={...admin};change(v);expect(()=>inspectRootAdministratorCredential(v,scope)).toThrow();});
it('resource-policy hashes commit service and ARN even when the complete response has no policies',()=>{
 expect(normalizeRootCredentialPolicies(admin,{Policies:[]})).toEqual({...admin,policies:[]});expect(normalizeRootCredentialPolicies(secret,{ARN:secret.arn})).toEqual({...secret,policies:[]});
 expect(normalizeRootCredentialPolicies(admin,{Policies:[]})).not.toEqual(normalizeRootCredentialPolicies({...admin,arn:admin.arn+'-other'},{Policies:[]}));
 const row={PolicyId:'policy-one',PolicyHash:'opaque-service-version',Policy:JSON.stringify({Version:'2012-10-17',Statement:[{Effect:'Allow',Principal:{AWS:'arn:aws:iam::123456789012:role/synthetic'},Action:'ssm:GetParameters',Resource:admin.arn}]})};
 expect(normalizeRootCredentialPolicies(admin,{Policies:[row]}).policies[0]).toMatchObject({policyId:row.PolicyId,policyVersion:row.PolicyHash});
 for(const response of [{},{Policies:[],NextToken:'unread'},{Policies:[row,row]},{Policies:[{...row,PolicyHash:''}]},{Policies:[{...row,Policy:'not json'}]}])expect(()=>normalizeRootCredentialPolicies(admin,response)).toThrow();
 expect(()=>normalizeRootCredentialPolicies(secret,{ARN:secret.arn+'-wrong'})).toThrow();
});
