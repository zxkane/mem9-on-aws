/** R16 closed accounting data. No I/O, clock, credential or authority. */
import {copyNonrootJson} from './production-nonroot-contracts.mjs';
import {need,exact,hash,hex,freeze,zero,counter,sha,same} from './ci-smoke-acquisition-format.mjs';
import {buildCiSmokeReadPolicy,ciSmokeArchiveLocation} from './ci-smoke-private-archive.mjs';

/** Reconstruct only the existing code-owned scopes. Role identities are data
 * from the prepaid plan; this verifier cannot create a session or authority. */
function originalIssuerPolicy(p){
 const s=p.scope,ci=p.slot.purpose==='ci-reader';
 exact(s,ci?['account','personalAccount','region','owner','archive','commitment']:['account','personalAccount','region','owner']);
 need(/^\d{12}$/.test(s.account)&&/^\d{12}$/.test(s.personalAccount)&&s.account!==s.personalAccount&&hex(s.owner,32)&&/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(s.region),'OriginalIssuerPlanScope');
 if(ci){const l=ciSmokeArchiveLocation(s.archive,s.commitment);need(l.account===s.account&&l.region===s.region,'OriginalIssuerPlanScope');const r=buildCiSmokeReadPolicy(s.archive,s.commitment);need(r.DurationSeconds===900,'OriginalIssuerDuration');return r.Policy;}
 const components=['llm-proxy','mnemo-server','qwen3-embed'],read=['ecr:BatchGetImage','ecr:GetDownloadUrlForLayer'];
 const destination=[...read,'ecr:BatchCheckLayerAvailability','ecr:InitiateLayerUpload','ecr:UploadLayerPart','ecr:CompleteLayerUpload','ecr:PutImage','ecr:DescribeImageScanFindings','ecr:StartImageScan'];
 const prefix='arn:aws:ecr:'+s.region+':'+s.account+':repository/mem9-on-aws/',dest=components.map(c=>prefix+c),source=components.map(c=>prefix+'preview/'+c),actions=[...destination,'sts:GetCallerIdentity'];
 const policy=JSON.stringify({Version:'2012-10-17',Statement:[{Effect:'Allow',Action:actions,Resource:'*'},{Effect:'Deny',NotAction:actions,Resource:'*'},{Effect:'Deny',Action:'ecr:*',NotResource:[...source,...dest]},{Effect:'Deny',Action:destination.slice(2),Resource:source}]});
 need(policy.length<=2048,'OriginalIssuerPolicySize');return policy;
}

const K=1024,M=K*K;
export const ORIGINAL_ISSUER_LIMITS=freeze({unknownBytes:8*M,localBytes:16*M,cleanupLocalBytes:2*M,sourceFileBytes:256*K,profileFileBytes:64*K,normalFilePasses:28,cleanupFilePasses:4,rawPasses:8,normalRecords:32,cleanupRecords:4,recordBytes:64*K,metadataTimeoutMs:5000,rawTimeoutMs:30000,drainMs:1000});
export function inspectOriginalIssuerSource(value){
 const s=copyNonrootJson(value);exact(s,['profile','provider','configFile','credentialsFile','configHash','credentialsHash']);
 need(s.profile==='default'&&['instance-metadata','static-temporary'].includes(s.provider)&&hex(s.configHash)&&(s.credentialsHash===null||hex(s.credentialsHash)),'OriginalIssuerSource');
 for(const k of ['configFile','credentialsFile'])need(typeof s[k]==='string'&&s[k].startsWith('/')&&s[k].length<=4096&&!s[k].split('/').includes('..'),'OriginalIssuerSourcePath');return s;
}
export function originalIssuerSlot(purpose,provider){
 need(['ci-reader','copy'].includes(purpose)&&['instance-metadata','static-temporary'].includes(provider),'OriginalIssuerPurpose');
 const row=(key,action,requestBytes,responseBytes)=>({key,action,requestBytes,responseBytes,count:1,ecr:false});
 const operations=[...(provider==='instance-metadata'?[row('source-token','ImdsV2Token',0,4*K),row('source-credentials','ImdsV2Credentials',0,64*K)]:[]),row('source-identity','GetCallerIdentity',16*K,16*K),row('assume','AssumeRole',16*K,256*K),row('target-identity','GetCallerIdentity',16*K,16*K)];
 const charge={...zero(),logicalBytes:ORIGINAL_ISSUER_LIMITS.localBytes,httpBodyBytes:operations.reduce((n,r)=>n+r.requestBytes+r.responseBytes,ORIGINAL_ISSUER_LIMITS.unknownBytes)};counter(charge);
 return freeze({version:1,kind:'original-issuer-slot',purpose,provider,mode:purpose==='ci-reader'?'ci-smoke-read':'image-staging',durationSeconds:purpose==='ci-reader'?900:3600,operations,limits:ORIGINAL_ISSUER_LIMITS,charge});
}
export function compileOriginalIssuersBudget({source}){
 source=inspectOriginalIssuerSource(source);const slots=['ci-reader','copy'].map(p=>originalIssuerSlot(p,source.provider)),charge=zero();for(const slot of slots)for(const k of Object.keys(charge))charge[k]+=slot.charge[k];counter(charge);
 return freeze({version:1,kind:'original-issuers-budget',source,sourceHash:hash(source),slots,charge});
}
export function inspectOriginalIssuerPlan(value){
 const p=copyNonrootJson(value);exact(p,['version','kind','slot','source','binding','ledgerStartHash','scope','identities','stsRegion','sourceTags','deadlineMs']);
 need(p.version===1&&p.kind==='original-issuer-plan'&&hex(p.ledgerStartHash)&&Number.isSafeInteger(p.deadlineMs)&&p.deadlineMs>0,'OriginalIssuerPlan');
 const source=inspectOriginalIssuerSource(p.source),slot=originalIssuerSlot(p.slot.purpose,source.provider);need(hash(slot)===hash(p.slot),'OriginalIssuerPlanBudget');
 exact(p.binding,['owner','executionId','planHash','publicationHash']);need(hex(p.binding.owner,32)&&hex(p.binding.executionId,32)&&hex(p.binding.planHash)&&hex(p.binding.publicationHash),'OriginalIssuerPlanBinding');
 need(typeof p.stsRegion==='string'&&/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(p.stsRegion),'OriginalIssuerRegion');
 exact(p.sourceTags,['usage','User','Host','Project']);need(p.sourceTags.usage==='codex-mem9-on-aws'&&p.sourceTags.Project==='mem9-on-aws'&&typeof p.sourceTags.User==='string'&&typeof p.sourceTags.Host==='string','OriginalIssuerTags');
 need(p.scope.owner===p.binding.owner,'OriginalIssuerPlanScope');originalIssuerPolicy(p);
 exact(p.identities,['sourceRoleArn','targetRoleArn']);for(const arn of Object.values(p.identities))need(typeof arn==='string'&&new RegExp('^arn:aws:iam::'+p.scope.account+':role/[A-Za-z0-9_+=,.@-]{1,64}$').test(arn),'OriginalIssuerIdentities');
 if(slot.purpose==='ci-reader')need(p.scope.archive.roleArn===p.identities.targetRoleArn,'OriginalIssuerIdentities');
 return freeze({plan:p,planHash:hash(p),scopeHash:hash({version:1,kind:'original-issuer-slot',purpose:slot.purpose,binding:p.binding}),charge:slot.charge});
}

/** Closed successful-journal replay. The enclosing copy verifier separately
 * replays the original ledger and binds the actual prepayment event hash. */
export function verifyOriginalIssuerJournal(value,expected){
 exact(value,['plan','records']);const {plan:p,planHash}=inspectOriginalIssuerPlan(value.plan),rows=copyNonrootJson(value.records);exact(expected,['binding','sourceHash','deadlineMs','debitEventHash']);
 same(p.binding,expected.binding,'OriginalIssuerReplayBinding');need(hash(p.source)===expected.sourceHash&&p.deadlineMs===expected.deadlineMs&&hex(expected.debitEventHash),'OriginalIssuerReplayBinding');
 const kinds=['opened',...(p.source.provider==='instance-metadata'?['request','response','request','response','source-resolved']:[]),'source-snapshot','request','response','identity','request','response','target-snapshot','request','response','identity','released'];
 need(Array.isArray(rows)&&rows.length===kinds.length&&rows.every((r,i)=>r.kind===kinds[i]),'OriginalIssuerReplayRows');
 const policyJson=originalIssuerPolicy(p),sourceRole=p.identities.sourceRoleArn.split('/').at(-1),targetRole=p.identities.targetRoleArn.split('/').at(-1);let last=null,index=0,active=null,sourceSnapshot,targetSnapshot,targetArn,sourceExpiresMs,sourceIdentity=false,targetIdentity=false,resolved=p.source.provider==='static-temporary',closed=false,requestBytes=0,responseBytes=0,lastMs=0;
 for(const [i,r]of rows.entries()){
  exact(r,['version','sequence','previousHash','planHash','kind','data']);need(!closed&&r.version===1&&r.sequence===i+1&&r.previousHash===last&&r.planHash===planHash&&Buffer.byteLength(JSON.stringify(r)+'\n')<=ORIGINAL_ISSUER_LIMITS.recordBytes,'OriginalIssuerReplayChain');last=hash(r);const d=r.data;
  if(r.kind==='opened'){exact(d,['planHash','debitEventHash']);need(i===0&&d.planHash===planHash&&d.debitEventHash===expected.debitEventHash,'OriginalIssuerReplayDebit');}
  else if(r.kind==='source-resolved'){exact(d,['provider','configHash','expiresMs']);need(!resolved&&index===2&&!active&&d.provider===p.source.provider&&d.configHash===p.source.configHash&&Number.isSafeInteger(d.expiresMs)&&d.expiresMs>lastMs,'OriginalIssuerReplaySource');resolved=true;sourceExpiresMs=d.expiresMs;}
  else if(r.kind==='source-snapshot'){exact(d,['configHash','credentialsHash']);need(resolved&&!sourceSnapshot&&!active&&hex(d.configHash)&&hex(d.credentialsHash),'OriginalIssuerReplaySource');sourceSnapshot=d;}
  else if(r.kind==='target-snapshot'){exact(d,['configHash','credentialsHash','expiresMs','arn']);need(sourceIdentity&&!targetSnapshot&&!active&&index===p.slot.operations.length-1&&hex(d.configHash)&&hex(d.credentialsHash)&&d.arn===targetArn&&Number.isSafeInteger(d.expiresMs)&&d.expiresMs>lastMs,'OriginalIssuerReplayTarget');targetSnapshot=d;}
  else if(r.kind==='identity'){
   exact(d,['profile','account','arn']);need(!active&&d.account===p.scope.account,'OriginalIssuerReplayIdentity');
   if(d.profile==='default'){need(!sourceIdentity&&index===p.slot.operations.length-2&&typeof d.arn==='string'&&d.arn.startsWith('arn:aws:sts::'+p.scope.account+':assumed-role/'+sourceRole+'/'),'OriginalIssuerReplayIdentity');sourceIdentity=true;}
   else{need(d.profile==='cc-tracked'&&!targetIdentity&&index===p.slot.operations.length&&d.arn===targetArn,'OriginalIssuerReplayIdentity');targetIdentity=true;}
  }else if(r.kind==='request'){
   exact(d,['key','ordinal','action','requestHash','snapshotHash','request','wireRequestHash','caps','atMs']);
   const op=p.slot.operations[index];need(!active&&op&&d.ordinal===index+1&&d.key===op.key&&d.action===op.action&&hex(d.requestHash)&&d.requestHash===hash(d.request)&&hex(d.wireRequestHash)&&Number.isSafeInteger(d.atMs)&&d.atMs>=lastMs&&d.atMs<p.deadlineMs,'OriginalIssuerReplayRequest');lastMs=d.atMs;
   same(d.caps,{requestBytes:op.requestBytes,responseBytes:op.responseBytes},'OriginalIssuerReplayCap');
   if(op.key.startsWith('source-')&&op.key!=='source-identity'){
    same(d.request,op.key==='source-token'?{method:'PUT',host:'169.254.169.254',path:'/latest/api/token',ttlSeconds:60}:{method:'GET',host:'169.254.169.254',path:'/latest/meta-data/iam/security-credentials/'+sourceRole},'OriginalIssuerReplayMetadata');need(d.snapshotHash===null&&d.wireRequestHash===sha(''),'OriginalIssuerReplayMetadata');
   }else{
    const snapshot=op.key==='target-identity'?targetSnapshot:sourceSnapshot;need(snapshot&&d.snapshotHash===snapshot.credentialsHash,'OriginalIssuerReplaySnapshot');
    if(op.key==='target-identity')need(d.atMs<snapshot.expiresMs,'OriginalIssuerReplayExpired');else if(sourceExpiresMs)need(d.atMs<sourceExpiresMs,'OriginalIssuerReplayExpired');
    if(op.key==='assume'){
     need(sourceIdentity,'OriginalIssuerReplaySource');exact(d.request,['RoleArn','RoleSessionName','DurationSeconds','Tags','TransitiveTagKeys','Policy']);const q=d.request;
     need(q.RoleArn===p.identities.targetRoleArn&&q.DurationSeconds===p.slot.durationSeconds&&q.Policy===policyJson,'OriginalIssuerReplayAssume');same(q.Tags,Object.entries(p.sourceTags).map(([Key,Value])=>({Key,Value})));same(q.TransitiveTagKeys,Object.keys(p.sourceTags));
     need(typeof q.RoleSessionName==='string'&&q.RoleSessionName.startsWith(p.sourceTags.usage+(p.slot.purpose==='ci-reader'?'-ci-smoke-read-':'-image-staging-'))&&/^[A-Za-z0-9_=,.@-]{1,64}$/.test(q.RoleSessionName),'OriginalIssuerReplayAssume');targetArn='arn:aws:sts::'+p.scope.account+':assumed-role/'+targetRole+'/'+q.RoleSessionName;
    }else exact(d.request,[]);
   }
   active={r,op};index++;
  }else if(r.kind==='response'){
   exact(d,['requestSequence','key','requestBytes','responseBytes','requestHash','responseHash','statusCode','dispatched','complete','atMs']);
   need(active&&d.requestSequence===active.r.sequence&&d.key===active.op.key&&d.complete===true&&d.dispatched===true&&d.statusCode===200&&d.requestHash===active.r.data.wireRequestHash&&hex(d.responseHash)&&Number.isSafeInteger(d.requestBytes)&&d.requestBytes>=0&&d.requestBytes<=active.op.requestBytes&&Number.isSafeInteger(d.responseBytes)&&d.responseBytes>=0&&d.responseBytes<=active.op.responseBytes&&Number.isSafeInteger(d.atMs)&&d.atMs>=lastMs&&d.atMs<p.deadlineMs,'OriginalIssuerReplayResponse');lastMs=d.atMs;requestBytes+=d.requestBytes;responseBytes+=d.responseBytes;active=null;
  }else if(r.kind==='released'){
   exact(d,['cleanupComplete','usageBeforeTerminal']);need(!active&&sourceIdentity&&targetIdentity&&index===p.slot.operations.length&&d.cleanupComplete===true,'OriginalIssuerReplayIncomplete');const u=d.usageBeforeTerminal;
   exact(u,['normalBytes','cleanupBytes','fileNormal','fileCleanup','normalRecords','cleanupRecords','rawBytes','observed','unknownBytes','held','next']);
   for(const key of ['normalBytes','cleanupBytes','fileNormal','fileCleanup','normalRecords','cleanupRecords','rawBytes','unknownBytes','next'])need(Number.isSafeInteger(u[key])&&u[key]>=0,'OriginalIssuerReplayLocal');
   need(u.held===false&&u.normalRecords===i&&u.cleanupRecords===0&&u.rawBytes===requestBytes+responseBytes&&u.normalBytes>=u.rawBytes*ORIGINAL_ISSUER_LIMITS.rawPasses+2*rows.slice(0,i).reduce((sum,row)=>sum+Buffer.byteLength(JSON.stringify(row)+'\n'),0),'OriginalIssuerReplayLocal');
   need(u&&u.unknownBytes===0&&!u.held&&u.next===index&&u.normalBytes<=ORIGINAL_ISSUER_LIMITS.localBytes-ORIGINAL_ISSUER_LIMITS.cleanupLocalBytes&&u.cleanupBytes+2*Buffer.byteLength(JSON.stringify(r)+'\n')<=ORIGINAL_ISSUER_LIMITS.cleanupLocalBytes&&u.fileNormal<=ORIGINAL_ISSUER_LIMITS.normalFilePasses&&u.fileCleanup<=ORIGINAL_ISSUER_LIMITS.cleanupFilePasses&&u.normalRecords<=ORIGINAL_ISSUER_LIMITS.normalRecords&&u.cleanupRecords<ORIGINAL_ISSUER_LIMITS.cleanupRecords,'OriginalIssuerReplayLocal');same(u.observed,{requestBytes,responseBytes});closed=true;
  }else need(false,'OriginalIssuerReplayKind');
 }
 need(closed&&!active,'OriginalIssuerReplayIncomplete');return freeze({authority:false,planHash,debitEventHash:expected.debitEventHash,journalHash:last,requestBytes,responseBytes,charge:p.slot.charge});
}
