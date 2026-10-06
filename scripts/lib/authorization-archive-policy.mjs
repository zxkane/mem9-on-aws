import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {parseDocument} from 'yaml';

export const AUTHORIZATION_ARCHIVE_PREFIX='data-authorizations/';
export const MAX_ARCHIVE_CONFIGURATION_BYTES=1024*1024;
const fail=code=>{throw Error(code);};
const object=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const exact=(v,keys)=>object(v)&&Object.keys(v).sort().join()===keys.slice().sort().join();
const canonical=v=>Array.isArray(v)?v.map(canonical):object(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;
const hash=v=>createHash('sha256').update(JSON.stringify(canonical(v))).digest('hex');

/** Keep the original bytes for both parsers. JSON limits the grammar; YAML's
 * JSON schema detects duplicate decoded keys recursively. Never use its value
 * conversion, or a reserialized JSON value, as the duplicate-check input. */
export function parseStrictJson(raw){
 if(typeof raw!=='string'||Buffer.byteLength(raw)>MAX_ARCHIVE_CONFIGURATION_BYTES)fail('ArchiveConfigurationInvalid');
 let value,document;
 try{value=JSON.parse(raw);document=parseDocument(raw,{schema:'json',uniqueKeys:true,prettyErrors:false});}
 catch{fail('ArchiveConfigurationInvalid');}
 if(!document||document.contents===null||document.contents===undefined||document.errors.length)fail('ArchiveConfigurationInvalid');
 return value;
}

export function expectedArchivePolicy(bucket){
 if(typeof bucket!=='string'||!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(bucket))fail('ArchiveBucketInvalid');
 const arn='arn:aws:s3:::'+bucket,resource=arn+'/'+AUTHORIZATION_ARCHIVE_PREFIX+'*';
 return {Version:'2012-10-17',Statement:[
  {Sid:'DenyInsecureTransport',Effect:'Deny',Principal:'*',Action:'s3:*',Resource:[arn,arn+'/*'],Condition:{Bool:{'aws:SecureTransport':'false'}}},
  {Sid:'DenyAuthorizationArchiveMissingCondition',Effect:'Deny',Principal:'*',Action:'s3:PutObject',Resource:resource,Condition:{Null:{'s3:if-none-match':'true'}}},
  {Sid:'DenyAuthorizationArchiveWrongCondition',Effect:'Deny',Principal:'*',Action:'s3:PutObject',Resource:resource,Condition:{Null:{'s3:if-none-match':'false'},StringNotEquals:{'s3:if-none-match':'*'}}},
  {Sid:'DenyAuthorizationArchiveDestructiveChanges',Effect:'Deny',Principal:'*',Action:['s3:DeleteObject','s3:DeleteObjectVersion','s3:ReplicateObject','s3:ReplicateDelete','s3:PutObjectAcl','s3:PutObjectVersionAcl'],Resource:resource},
  {Sid:'DenyAuthorizationArchiveCopy',Effect:'Deny',Principal:'*',Action:'s3:PutObject',Resource:resource,Condition:{Null:{'s3:x-amz-copy-source':'false'}}},
 ]};
}
function strings(value){
 const values=Array.isArray(value)?value:[value];
 if(!values.length||values.some(v=>typeof v!=='string')||new Set(values).size!==values.length)fail('ArchivePolicyInvalid');
 return [...values].sort();
}
function normalizeStatement(statement,expected){
 if(!exact(statement,Object.keys(expected)))fail('ArchivePolicyInvalid');
 let principal=statement.Principal;
 if(object(principal)){if(!exact(principal,['AWS']))fail('ArchivePolicyInvalid');principal=principal.AWS;}
 const normalized={Sid:statement.Sid,Effect:statement.Effect,Principal:strings(principal),Action:strings(statement.Action),Resource:strings(statement.Resource)};
 if(statement.Condition!==undefined){
  if(!exact(statement.Condition,Object.keys(expected.Condition)))fail('ArchivePolicyInvalid');
  normalized.Condition={};
  for(const [operator,keys]of Object.entries(expected.Condition)){
   if(!exact(statement.Condition[operator],Object.keys(keys)))fail('ArchivePolicyInvalid');
   normalized.Condition[operator]=Object.fromEntries(Object.keys(keys).map(key=>[key,strings(statement.Condition[operator][key])]));
  }
 }
 return normalized;
}
function verifyExpectedPolicy(raw,expected){
 const actual=parseStrictJson(raw),size=expected.Statement.length;
 if(!exact(actual,['Version','Statement'])||actual.Version!==expected.Version||!Array.isArray(actual.Statement)||actual.Statement.length!==size)fail('ArchivePolicyInvalid');
 const sids=actual.Statement.map(s=>s?.Sid),known=expected.Statement.map(s=>s.Sid);
 if(new Set(sids).size!==size||sids.some(s=>!known.includes(s)))fail('ArchivePolicyInvalid');
 const statements=new Map(actual.Statement.map(s=>[s.Sid,s]));
 const normalized=expected.Statement.map(s=>normalizeStatement(statements.get(s.Sid),s));
 const target=expected.Statement.map(s=>normalizeStatement(s,s));
 if(!isDeepStrictEqual(normalized,target))fail('ArchivePolicyMismatch');
 return {policyHash:hash({Version:actual.Version,Statement:normalized})};
}
export function verifyArchivePolicy(raw,{bucket}){return verifyExpectedPolicy(raw,expectedArchivePolicy(bucket));}
/** Before-update compatibility only; this does not certify archive protection. */
export function verifyLegacyArtifactPolicy(raw,{bucket}){
 const expected=expectedArchivePolicy(bucket);expected.Statement=expected.Statement.slice(0,1);
 return {...verifyExpectedPolicy(raw,expected),mode:'legacy'};
}

function prefix(value){if(typeof value!=='string')fail('ArchiveAvailabilityInvalid');return value;}
function scope(record,{lifecycle=true}={}){
 if(record.Prefix!==undefined){if(!lifecycle||record.Filter!==undefined)fail('ArchiveAvailabilityInvalid');return prefix(record.Prefix);}
 if(record.Filter===undefined)return '';
 const filter=record.Filter;
 if(!object(filter)||Object.keys(filter).some(k=>!['Prefix','And','Tag','ObjectSizeGreaterThan','ObjectSizeLessThan'].includes(k)))fail('ArchiveAvailabilityInvalid');
 if(!lifecycle&&['ObjectSizeGreaterThan','ObjectSizeLessThan'].some(k=>filter[k]!==undefined||filter.And?.[k]!==undefined))fail('ArchiveAvailabilityInvalid');
 if(filter.And!==undefined){
  if(Object.keys(filter).length!==1||!object(filter.And)||Object.keys(filter.And).some(k=>!['Prefix','Tags','ObjectSizeGreaterThan','ObjectSizeLessThan'].includes(k)))fail('ArchiveAvailabilityInvalid');
  return filter.And.Prefix===undefined?'':prefix(filter.And.Prefix);
 }
 if(filter.Prefix!==undefined){if(Object.keys(filter).length!==1)fail('ArchiveAvailabilityInvalid');return prefix(filter.Prefix);}
 return '';
}
const overlaps=value=>AUTHORIZATION_ARCHIVE_PREFIX.startsWith(value)||value.startsWith(AUTHORIZATION_ARCHIVE_PREFIX);
const enabled=record=>{if(!object(record)||!['Enabled','Disabled'].includes(record.Status))fail('ArchiveAvailabilityInvalid');return record.Status==='Enabled';};

/** This checks availability configuration, not who may modify it. The live
 * admission inventory must separately govern configuration and policy writers. */
export function verifyArchiveAvailability({lifecycle,intelligentTiering}){
 if(!object(lifecycle)||!Array.isArray(lifecycle.Rules)||!object(intelligentTiering)||intelligentTiering.IsTruncated!==false||
    intelligentTiering.NextContinuationToken!==undefined&&intelligentTiering.NextContinuationToken!=='')fail('ArchiveAvailabilityIncomplete');
 for(const key of ['NextToken','ContinuationToken'])if(intelligentTiering[key]!==undefined&&intelligentTiering[key]!=='')fail('ArchiveAvailabilityIncomplete');
 const configurations=intelligentTiering.IntelligentTieringConfigurationList===undefined?[]:intelligentTiering.IntelligentTieringConfigurationList;
 if(!Array.isArray(configurations))fail('ArchiveAvailabilityInvalid');
 for(const rule of lifecycle.Rules){
  if(!enabled(rule)||!overlaps(scope(rule)))continue;
  if(rule.Expiration!==undefined||rule.NoncurrentVersionExpiration!==undefined)fail('ArchiveExpirationOverlap');
  for(const key of ['Transitions','NoncurrentVersionTransitions']){
   if(rule[key]===undefined)continue;if(!Array.isArray(rule[key]))fail('ArchiveAvailabilityInvalid');
   for(const transition of rule[key])if(!object(transition)||!['STANDARD_IA','ONEZONE_IA','INTELLIGENT_TIERING','GLACIER_IR'].includes(transition.StorageClass))fail('ArchiveTransitionOverlap');
  }
 }
 for(const configuration of configurations){
  if(!object(configuration)||Object.keys(configuration).some(k=>!['Id','Status','Filter','Tierings'].includes(k))||
    typeof configuration.Id!=='string'||!configuration.Id||!Array.isArray(configuration.Tierings))fail('ArchiveAvailabilityInvalid');
  const active=enabled(configuration),configurationPrefix=scope(configuration,{lifecycle:false});
  for(const tier of configuration.Tierings)if(!exact(tier,['Days','AccessTier'])||!Number.isSafeInteger(tier.Days)||tier.Days<1||!['ARCHIVE_ACCESS','DEEP_ARCHIVE_ACCESS'].includes(tier.AccessTier))fail('ArchiveAvailabilityInvalid');
  if(!active||!overlaps(configurationPrefix))continue;
  if(configuration.Tierings.length)fail('ArchiveTieringOverlap');
 }
 return {availabilityHash:hash({lifecycle,intelligentTiering})};
}
