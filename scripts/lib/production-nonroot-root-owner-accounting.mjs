import {nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {createRootOwnerPoolReplay,applyRootOwnerPoolEvent} from './production-nonroot-root-pool.mjs';
import {ROOT_PREREQUISITE_PROFILES} from './production-nonroot-prerequisites.mjs';

const freeze=v=>{if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;};
const need=(v,code='NonrootRootOwnerAccounting')=>{if(!v)throw Error(code);};
export const ROOT_OWNER_LIMITS=freeze({runtimeMs:140000,cleanupMs:30000,freshnessMs:300000,pollMs:5000,unknownBytes:8388608,localBytes:134217728});
const row=(service,action,count,requestBytes,responseBytes,lane='normal')=>({service,action,count,requestBytes,responseBytes,lane});
export const ROOT_OWNER_CATALOG=freeze({
 ...ROOT_PREREQUISITE_PROFILES,
 'prerequisite.issuerSourceToken':row('imds','ImdsV2Token',4,0,4096),
 'prerequisite.issuerSourceCredentials':row('imds','ImdsV2Credentials',4,0,65536),
 'prerequisite.issuerIdentity':row('sts','GetCallerIdentity',8,16384,262144),
 'prerequisite.issuerAssume':row('sts','AssumeRole',4,16384,262144),
 'issuer.sourceToken':row('imds','ImdsV2Token',4,0,4096),
 'issuer.sourceCredentials':row('imds','ImdsV2Credentials',4,0,65536),
 'issuer.identity':row('sts','GetCallerIdentity',8,16384,262144),
 'issuer.assume':row('sts','AssumeRole',4,16384,262144),
 'registration.create':row('ecs','RegisterTaskDefinition',1,65536,262144),
 'registration.read':row('ecs','DescribeTaskDefinition',3,16384,262144),
 'platform.definition':row('ecs','DescribeTaskDefinition',1,16384,262144),
 'presence.manifest':row('ecr','BatchGetImage',16,16384,8388608),
 'presence.url':row('ecr','GetDownloadUrlForLayer',1,16384,65536),
 'presence.config':row('blob','S3BlobGet',1,0,4194304),
 'presence.availability':row('ecr','BatchCheckLayerAvailability',10,16384,262144),
 'task.launch':row('ecs','RunTask',1,16384,262144),
 'task.observe':row('ecs','DescribeTasks',28,16384,262144),
 'task.logs':row('logs','GetLogEvents',12,16384,8388608),
 'task.stop':row('ecs','StopTask',1,16384,262144,'cleanup'),
 'task.discover':row('ecs','ListTasks',2,16384,262144,'cleanup'),
 'task.cleanup':row('ecs','DescribeTasks',6,16384,262144,'cleanup'),
 'census.list':row('ecs','ListTasks',24,16384,262144),
 'census.describe':row('ecs','DescribeTasks',20,16384,1048576),
 'scheduler.list':row('scheduler','ListSchedules',12,16384,262144),
 'scheduler.get':row('scheduler','GetSchedule',2,16384,262144),
 'fence.mutex':row('s3','GetObject',2,16384,16384),
});
const cleanupBytes=Object.values(ROOT_OWNER_CATALOG).filter(r=>r.lane==='cleanup').reduce((n,r)=>n+r.count*(r.requestBytes+r.responseBytes),0);
const cleanupCalls=Object.values(ROOT_OWNER_CATALOG).filter(r=>r.lane==='cleanup').reduce((n,r)=>n+r.count,0);
const cleanupLocal=freeze({captureBytes:2*(cleanupBytes+ROOT_OWNER_LIMITS.unknownBytes),journalBytes:(2*cleanupCalls+4)*131072,credentialBytes:16*65536,accountingBytes:96*16384});
export const ROOT_OWNER_POOL_POLICY=freeze({version:1,kind:'root-owner-pool-policy',catalogHash:hash(ROOT_OWNER_CATALOG),normalWireBytes:33554432,cleanupWireBytes:cleanupBytes,normalUnknownBytes:ROOT_OWNER_LIMITS.unknownBytes,cleanupUnknownBytes:ROOT_OWNER_LIMITS.unknownBytes,localBytes:ROOT_OWNER_LIMITS.localBytes,cleanupLocalBytes:Object.values(cleanupLocal).reduce((n,v)=>n+v,0),cleanupLocal});
const normal=new Map(Object.entries(ROOT_OWNER_CATALOG).filter(([,r])=>r.lane==='normal').map(([key,r])=>['RootOwner'+key,r]));
const zero=()=>({ecrRequests:0,logicalBytes:0,httpBodyBytes:0,uncompressedBytes:0,processedEntries:0});

/** Checks only fixed root-owner accounting, never business authorization.
 * The enclosing verifier still checks every chain hash, cumulative counter,
 * request binding and completion. Unknown execution cannot become COMPLETE. */
export function verifyRootOwnerReservations(events){
 need(Array.isArray(events)&&events.length<=200000);
 const accepted=new Set(),counts=new Map(),active=new Map(),knownCaps=new Map(),pool=createRootOwnerPoolReplay();let started=false,closed=false,normalPaid=false,cleanupId;
 for(const e of events){
  const d=e.data;
  if(e.type.startsWith('root-pool-')){need(!started&&!closed&&e.type!=='root-pool-activation','NonrootRootOwnerMixedAccounting');applyRootOwnerPoolEvent(pool,e.type,d);continue;}
  need(!pool.plan||pool.closed,'NonrootRootOwnerUnsettled');
  if(e.type==='cache-begin'||e.type==='combined-pass-start'||e.type==='scan-pool-prepayment'){
   need(active.size===0,'NonrootRootOwnerUnsettled');closed=true;
  }
  if(e.type==='reservation'&&(normal.has(d.action)||d.action==='RootOwnerCleanup')){
   need(!pool.plan,'NonrootRootOwnerMixedAccounting');
   need(!closed,'NonrootRootOwnerAfterCopy');started=true;
   need(Number.isSafeInteger(d.id)&&d.id>0&&!accepted.has(d.id));
   const cleanup=d.action==='RootOwnerCleanup',r=normal.get(d.action);
   const count=(counts.get(d.action)??0)+1;need(count<=(cleanup?1:r.count),'NonrootRootOwnerCount');counts.set(d.action,count);
   need([...active.values()].every(v=>v==='RootOwnerCleanup'),'NonrootRootOwnerConcurrent');
   const bytes=cleanup?cleanupBytes:r.requestBytes+r.responseBytes,ecr=!cleanup&&r.service==='ecr';
   need(d.bound===bytes+ROOT_OWNER_LIMITS.unknownBytes&&d.ecr===ecr,'NonrootRootOwnerExposure');
   const debit={...zero(),ecrRequests:ecr?1:0,httpBodyBytes:bytes+(cleanup||!normalPaid?ROOT_OWNER_LIMITS.unknownBytes:0)};
   need(hash(d.reserveDebit)===hash(debit),'NonrootRootOwnerReserveDebit');
   if(cleanup)cleanupId=d.id;else normalPaid=true;
   if(d.action==='RootOwnertask.launch')need(cleanupId!==undefined&&active.get(cleanupId)==='RootOwnerCleanup','NonrootRootOwnerCleanupNotReserved');
   accepted.add(d.id);active.set(d.id,d.action);knownCaps.set(d.id,bytes);
  }else if(['completed','unknown'].includes(e.type)&&accepted.has(d.id)){
   need(e.type==='completed'&&active.has(d.id),'NonrootRootOwnerUnsettled');
   need(Number.isSafeInteger(d.charged)&&d.charged>=0&&d.charged<=knownCaps.get(d.id),'NonrootRootOwnerKnownCap');active.delete(d.id);
  }
 }
 if(pool.plan)need(pool.closed&&!pool.normal.held&&!pool.cleanup.held,'NonrootRootOwnerIncomplete');
 if(started){
  need(active.size===0&&counts.get('RootOwnertask.launch')===1&&counts.get('RootOwnerregistration.create')===1&&counts.get('RootOwnerCleanup')===1,'NonrootRootOwnerIncomplete');
 }
 return accepted;
}
