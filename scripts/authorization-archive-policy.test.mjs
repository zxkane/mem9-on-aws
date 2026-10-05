import {readFileSync} from 'node:fs';
import {it,expect} from 'vitest';
import {parse} from 'yaml';

const bucket='example-audit',arn='arn:aws:s3:::'+bucket,archive=arn+'/data-authorizations/*';
const fixture=()=>({Version:'2012-10-17',Statement:[
 {Sid:'DenyInsecureTransport',Effect:'Deny',Principal:'*',Action:'s3:*',Resource:[arn,arn+'/*'],Condition:{Bool:{'aws:SecureTransport':'false'}}},
 {Sid:'DenyAuthorizationArchiveMissingCondition',Effect:'Deny',Principal:'*',Action:'s3:PutObject',Resource:archive,Condition:{Null:{'s3:if-none-match':'true'}}},
 {Sid:'DenyAuthorizationArchiveWrongCondition',Effect:'Deny',Principal:'*',Action:'s3:PutObject',Resource:archive,Condition:{Null:{'s3:if-none-match':'false'},StringNotEquals:{'s3:if-none-match':'*'}}},
 {Sid:'DenyAuthorizationArchiveDestructiveChanges',Effect:'Deny',Principal:'*',Action:['s3:DeleteObject','s3:DeleteObjectVersion','s3:ReplicateObject','s3:ReplicateDelete','s3:PutObjectAcl','s3:PutObjectVersionAcl'],Resource:archive},
 {Sid:'DenyAuthorizationArchiveCopy',Effect:'Deny',Principal:'*',Action:'s3:PutObject',Resource:archive,Condition:{Null:{'s3:x-amz-copy-source':'false'}}}
]});
const policy=fixture;
const lib=()=>import('./lib/authorization-archive-policy.mjs');
function template(){return parse(readFileSync(new URL('../infra/cloudformation/decision-artifact-bucket.yaml',import.meta.url),'utf8'),{customTags:[
 {tag:'!Ref',resolve:value=>({Ref:value})},{tag:'!Sub',resolve:value=>({'Fn::Sub':value})},{tag:'!GetAtt',resolve:value=>({'Fn::GetAtt':value.split('.')})}
]});}
function render(value){
 if(Array.isArray(value))return value.map(render);
 if(value&&typeof value==='object'){
  if(value['Fn::Sub'])return value['Fn::Sub'].replaceAll('${DecisionArtifactBucket.Arn}',arn);
  if(value['Fn::GetAtt']?.join('.')==='DecisionArtifactBucket.Arn')return arn;
  return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,render(v)]));
 }return value;
}
it('declares the exact prefix-scoped five-Deny policy in the owner template',()=>{
 expect(render(template().Resources.DecisionArtifactBucketPolicy.Properties.PolicyDocument)).toEqual(policy());
});
it('accepts the policy and provider-equivalent array/order forms',async()=>{
 const {verifyArchivePolicy}=await lib(),base=verifyArchivePolicy(JSON.stringify(policy()),{bucket}),changed=policy();
 changed.Statement.reverse();for(const s of changed.Statement){s.Principal={AWS:['*']};s.Action=Array.isArray(s.Action)?s.Action.reverse():[s.Action];s.Resource=Array.isArray(s.Resource)?s.Resource.reverse():[s.Resource];if(s.Condition)for(const op of Object.values(s.Condition))for(const k of Object.keys(op))op[k]=[op[k]];}
 expect(verifyArchivePolicy(JSON.stringify(changed),{bucket})).toEqual(base);
});
it('keeps legacy pre-update inspection separate from protected archive verification',async()=>{
 const {verifyLegacyArtifactPolicy,verifyArchivePolicy}=await lib(),legacy=policy();legacy.Statement=legacy.Statement.slice(0,1);
 expect(verifyLegacyArtifactPolicy(JSON.stringify(legacy),{bucket}).mode).toBe('legacy');
 expect(()=>verifyArchivePolicy(JSON.stringify(legacy),{bucket})).toThrow();
 expect(()=>verifyLegacyArtifactPolicy(JSON.stringify(policy()),{bucket})).toThrow();
});
for(const change of [
 p=>p.Statement.push({...p.Statement[0]}),p=>p.Statement[4].Sid=p.Statement[0].Sid,p=>p.Id='extra',p=>p.Statement[2].NotAction='s3:GetObject',
 p=>p.Statement[0].Effect='Allow',p=>p.Statement[1].Resource=arn+'/*',p=>p.Statement[1].Resource='${DecisionArtifactBucket.Arn}/data-authorizations/*',
 p=>p.Statement[3].Action.pop(),p=>p.Statement[3].Action.push(p.Statement[3].Action[0]),p=>p.Statement[4].Resource=[archive,archive],
 p=>p.Statement[2].Condition.Null['s3:if-none-match']='true',p=>p.Statement[2].Condition.StringNotEquals['s3:if-none-match']=['*','*'],
])it('rejects policy drift '+change.toString(),async()=>{
 const {verifyArchivePolicy}=await lib(),p=policy();change(p);expect(()=>verifyArchivePolicy(JSON.stringify(p),{bucket})).toThrow();
});
for(const [needle,replacement]of [
 ['"Statement":[','"Statement":[],"Statement":['],['"Action":"s3:*"','"Action":"s3:PutObject","Action":"s3:*"'],
 ['"Action":"s3:*"','"\\u0041ction":"s3:PutObject","Action":"s3:*"'],['"Resource":[','"Resource":"*","Resource":['],
 ['"Effect":"Deny"','"Effect":"Allow","Effect":"Deny"'],['"Condition":','"Condition":{},"Condition":'],
 ['"Null":','"Null":{},"Null":'],['"s3:if-none-match":"true"','"s3:if-none-match":"false","s3:if-none-match":"true"'],
])it('rejects duplicate raw members before parsed values can hide them: '+needle,async()=>{
 const {verifyArchivePolicy}=await lib(),raw=JSON.stringify(policy()).replace(needle,replacement);
 expect(JSON.parse(raw)).toEqual(policy());expect(()=>verifyArchivePolicy(raw,{bucket})).toThrow();
});
for(const raw of ['null','---\nVersion: 2012-10-17','{"a":1} trailing','{"a":/*comment*/1}'])it('rejects non-policy JSON or YAML '+raw,async()=>{
 const {verifyArchivePolicy}=await lib();expect(()=>verifyArchivePolicy(raw,{bucket})).toThrow();
});
const lifecycle=()=>({Rules:[{ID:'decision',Status:'Enabled',Filter:{Prefix:'decisions/'},Expiration:{Days:3}},{ID:'digest',Status:'Enabled',Prefix:'consolidation-digests/',Expiration:{Days:70}}]});
it('accepts disjoint lifecycle rules and a complete empty tiering inventory',async()=>{
 const {verifyArchiveAvailability}=await lib();expect(()=>verifyArchiveAvailability({lifecycle:lifecycle(),intelligentTiering:{IsTruncated:false}})).not.toThrow();
});
for(const filter of [undefined,{}, {Tag:{Key:'any',Value:'any'}},{And:{Tags:[{Key:'any',Value:'any'}]}},{Prefix:''},{Prefix:'data'},{Prefix:'data-authorizations/'},{Prefix:'data-authorizations/child/'}]){
 for(const action of [{Expiration:{Days:1}},{NoncurrentVersionExpiration:{NoncurrentDays:1}},{Transitions:[{Days:1,StorageClass:'GLACIER'}]}])it('rejects overlapping lifecycle '+JSON.stringify({filter,action}),async()=>{
  const {verifyArchiveAvailability}=await lib();expect(()=>verifyArchiveAvailability({lifecycle:{Rules:[{ID:'bad',Status:'Enabled',...(filter===undefined?{}:{Filter:filter}),...action}]},intelligentTiering:{IsTruncated:false}})).toThrow();
 });
}
it('rejects matching archive-access tiers and incomplete tiering pages',async()=>{
 const {verifyArchiveAvailability}=await lib();
 for(const intelligentTiering of [{IsTruncated:true},{IsTruncated:false,IntelligentTieringConfigurationList:[{Id:'bad',Status:'Enabled',Filter:{Prefix:'data-authorizations/'},Tierings:[{Days:90,AccessTier:'ARCHIVE_ACCESS'}]}]}])expect(()=>verifyArchiveAvailability({lifecycle:lifecycle(),intelligentTiering})).toThrow();
});
it('rejects null collections and client- or service-truncated inventories',async()=>{
 const {verifyArchiveAvailability}=await lib();
 for(const intelligentTiering of [{IsTruncated:false,IntelligentTieringConfigurationList:null},{IsTruncated:false,NextToken:'more'},{IsTruncated:false,ContinuationToken:'started-late'}])expect(()=>verifyArchiveAvailability({lifecycle:lifecycle(),intelligentTiering})).toThrow();
});
it('rejects lifecycle-only fields masquerading as a disjoint tiering scope',async()=>{
 const {verifyArchiveAvailability}=await lib();
 const configuration={Id:'invalid',Status:'Enabled',Prefix:'decisions/',Tierings:[{Days:90,AccessTier:'ARCHIVE_ACCESS'}]};
 expect(()=>verifyArchiveAvailability({lifecycle:lifecycle(),intelligentTiering:{IsTruncated:false,IntelligentTieringConfigurationList:[configuration]}})).toThrow();
});
it('collects every tiering page before asserting completeness',async()=>{
 const {collectArchiveTiering}=await import('./verify-authorization-archive.mjs'),calls=[];
 const result=await collectArchiveTiering({bucket,region:'ap-northeast-1',owner:'123456789012'},{run:async(command,args)=>{
  expect(command).toBe('aws');calls.push(args);
  return {stdout:JSON.stringify(calls.length===1?{IsTruncated:true,NextContinuationToken:'next',IntelligentTieringConfigurationList:[{Id:'one'}]}:{IsTruncated:false,ContinuationToken:'next',IntelligentTieringConfigurationList:[{Id:'two'}]})};
 }});
 expect(result).toEqual({IsTruncated:false,IntelligentTieringConfigurationList:[{Id:'one'},{Id:'two'}]});expect(calls[1]).toContain('--continuation-token=next');
});
it('rejects repeated pagination tokens and malformed page shapes',async()=>{
 const {collectArchiveTiering}=await import('./verify-authorization-archive.mjs');
 for(const response of [{IsTruncated:true,NextContinuationToken:'same'},{IsTruncated:false,IntelligentTieringConfigurationList:null},{IsTruncated:false,NextToken:'partial'}])await expect(collectArchiveTiering({bucket,region:'ap-northeast-1',owner:'123456789012'},{run:async()=>({stdout:JSON.stringify(response)})})).rejects.toThrow();
});
