import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {parseContinuationInspection} from './lib/production-continuation-inspection.mjs';
import {inspectNonrootCompatibilityCertificate} from './lib/production-nonroot-runtime.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {schemaAdministratorRole} from './lib/production-runtime-config.mjs';
import {rootAuditSourceClosure,auditRootTransaction} from './lib/production-continuation-root.mjs';
import {validateContinuationAbsence,readContinuationAbsence} from './lib/production-continuation-absence.mjs';

const need=(ok,code='ContinuationInspectionInvalid')=>{if(!ok)throw Error(code);};
const exact=(value,keys)=>need(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===keys.toSorted().join());
const hex=(value,n=64)=>typeof value==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(value);
const sha=value=>createHash('sha256').update(value).digest('hex');

export function validateContinuationRootInput(input,{owner,invocation,env,operation='root-audit'}){
 exact(input,['invocation','owner','runtimeNonce','rootBinding','rootConfig','certificate','parent','dependencyHash','deployed',...(operation==='absence-audit'?['absence']:[])]);
 need(input.invocation===invocation&&input.owner===owner&&hex(owner,32)&&hex(invocation,32)&&hex(input.runtimeNonce,32)&&hex(input.dependencyHash));
 const b=input.rootBinding,c=input.certificate,p=input.parent.verification,r=input.rootConfig;
 exact(input.parent,['verification']);exact(b,['parentProofHash','validationId','generation','spent','cap']);
 inspectNonrootCompatibilityCertificate(c);
 need(b.cap===20&&b.spent===p.changedRows&&Number.isInteger(b.spent)&&b.spent>=2&&b.spent<=16,'ContinuationOriginalAllowance');
 need(hash(p)===b.parentProofHash&&b.parentProofHash===c.parentProofHash&&b.validationId===p.validationId&&b.generation===p.generation&&p.generation===c.generation,'ContinuationOriginalRoot');
 exact(input.deployed,['revision','sourceTree']);need(hex(input.deployed.revision,40)&&input.deployed.sourceTree===c.current.release.sourceTree,'ContinuationSource');
 exact(r,['host','port','database','generation','targets','workerImage','sourceTag','acceptance','planner','executor','dataRelease']);
 for(const kind of ['planner','executor']){exact(r[kind],['username']);need(r[kind].username==='mem9_'+kind+'_'+sha('prod').slice(0,12));}
 need(hash(r.targets)===hash(p.targets)&&r.generation===p.generation&&r.workerImage===c.current.release.workerImage&&r.sourceTag===c.current.release.sourceTag&&input.runtimeNonce===c.current.release.runtimeNonce);
 need(r.acceptance.sourceTree===input.deployed.sourceTree&&r.acceptance.coordinatorDigest===c.current.release.coordinatorDigest);
 need(r.dataRelease?.hash===c.dataReleaseHash&&r.dataRelease.data?.version===3);
 if(env){
  need(env.MEM9_STAGE==='prod'&&env.MEM9_PRODUCTION_WORKER_OPERATOR==='control'&&r.host===env.MEM9_DB_HOST&&String(r.port)===env.MEM9_DB_PORT&&r.database===env.MEM9_DB_NAME,'ContinuationDatabaseBinding');
  need(env.MEM9_CONTROL_SOURCE_TAG==='mem9-'+input.deployed.revision.slice(0,7)&&env.MEM9_WORKER_GENERATION===c.generation&&env.MEM9_WORKER_IMAGE===r.workerImage&&env.MEM9_WORKER_SOURCE_TAG===r.sourceTag&&env.MEM9_RETAINED_DATA_RELEASE_HASH===c.dataReleaseHash,'ContinuationSource');
 }
 if(operation==='absence-audit')validateContinuationAbsence(input);
 return input;
}

/** Fixed aggregate-only queries. The surrounding caller holds the same
 * read-only transaction and has already verified the original/continued root. */
export async function captureContinuationCensus(db,input,observedMs){
 const targets=input.rootConfig.targets;
 need(Array.isArray(targets)&&targets.length>0&&targets.length<=32&&new Set(targets).size===targets.length&&targets.every(v=>typeof v==='string'&&v.length>0),'ContinuationCensusTargets');
 const countsByKind=new Map(),candidates={groups:0,rows:0,surplus:0,largest_group:0};let benchmarkRemaining=0;
 const add=(a,b)=>{need(Number.isSafeInteger(b)&&b>=0&&Number.isSafeInteger(a+b),'ContinuationCensusCount');return a+b;};
 // Each application-table statement has one explicit namespace parameter.
 // Aggregate within the same MVCC transaction, preserving the full target set.
 for(const namespace of targets){
  const rows=(await db.query('SELECT memory_type,state,count(*)::int AS count FROM public.memories WHERE namespace_id=$1 GROUP BY memory_type,state ORDER BY memory_type,state',[namespace])).rows;
  for(const row of rows){const key=JSON.stringify([row.memory_type,row.state]),prior=countsByKind.get(key)??{memory_type:row.memory_type,state:row.state,count:0};prior.count=add(prior.count,row.count);countsByKind.set(key,prior);}
  const result=(await db.query("SELECT count(*)::int AS groups,coalesce(sum(n),0)::int AS rows,coalesce(sum(n-1),0)::int AS surplus,coalesce(max(n),0)::int AS largest_group FROM (SELECT count(*) AS n FROM public.memories m WHERE m.namespace_id=$1 AND m.state='active' AND m.memory_type='insight' GROUP BY m.namespace_id,m.content,mem9_maintenance.material_context(jsonb_build_object('memory_type',m.memory_type,'app_id',m.app_id,'source',m.source,'agent_id',m.agent_id,'tags',m.tags,'metadata',m.metadata)) HAVING count(*)>1) groups",[namespace])).rows[0];
  for(const key of ['groups','rows','surplus'])candidates[key]=add(candidates[key],result?.[key]);
  candidates.largest_group=Math.max(candidates.largest_group,add(0,result?.largest_group));
  benchmarkRemaining=add(benchmarkRemaining,Number((await db.query('SELECT count(*)::int AS count FROM public.memories WHERE namespace_id=$1 AND agent_id=$2',[namespace,'mem9-canary-'+input.rootBinding.validationId])).rows[0]?.count));
 }
 const counts=[...countsByKind.values()].sort((a,b)=>a.memory_type.localeCompare(b.memory_type)||a.state.localeCompare(b.state));
 const controls=(await db.query("SELECT enabled,(SELECT enabled FROM mem9_maintenance.dispatcher_settings WHERE singleton) AS dispatcher_enabled,cardinality(retired_roles) AS retired_roles,(SELECT count(*)::int FROM mem9_maintenance.receipts WHERE namespace_id=ANY($1)) AS execution_receipts FROM mem9_maintenance.execution_control WHERE singleton",[targets])).rows[0];
 const row=(await db.query('SELECT generation,validation_id,targets,phase,canary_used,receipt_verification FROM mem9_maintenance.production_worker_setup WHERE singleton')).rows[0];
 need(row&&row.generation===input.certificate.generation&&row.validation_id===input.rootBinding.validationId&&hash(row.targets)===hash(targets),'ContinuationCensusRoot');
 need(Number.isSafeInteger(benchmarkRemaining)&&benchmarkRemaining>=0&&controls?.enabled===false&&controls.dispatcher_enabled===false,'ContinuationCensusState');
 return {event:'backlog_census',at:new Date(observedMs).toISOString(),targetNamespaces:targets.length,targetsHash:hash(targets.toSorted()),counts,exactCandidateUpperBound:candidates,controls,benchmarkRemaining,
  workerSetup:{generation:row.generation,validationId:row.validation_id,targetsHash:hash(row.targets.toSorted()),phase:row.phase,canaryUsed:row.canary_used,receiptVerificationHash:row.receipt_verification?hash(row.receipt_verification):null}};
}

export async function runContinuationInspection(env=process.env){
 const operation=env.MEM9_CONTINUATION_OPERATION;
 need(env.MEM9_STAGE==='prod'&&env.MEM9_PRODUCTION_WORKER_OPERATOR==='control');
 if(operation==='parse-begin'){
  need(env.MEM9_DB_SECRET===undefined&&env.MEM9_DB_HOST===undefined,'ContinuationParserCredentials');
  const {parseProductionConsolidationRequest}=await import('./production-consolidation-operator.mjs');
  const raw=env.MEM9_PRODUCTION_CONSOLIDATION_REQUEST,request=parseProductionConsolidationRequest(raw);
  need(request.operation==='begin-continuation'&&request.invocation===env.MEM9_OPERATOR_INVOCATION&&request.compatibility?.version===5,'ContinuationParserBinding');
  console.log(JSON.stringify({event:'begin_transport_acceptance',version:1,invocation:request.invocation,requestHash:sha(raw),bytes:Buffer.byteLength(raw),status:'parsed'}));return;
 }
 if(['publication-audit','publication-probe'].includes(operation)){
  const raw=env.MEM9_PUBLICATION_REQUEST;need(typeof raw==='string'&&Buffer.byteLength(raw)<=32768);
  const {parseNonrootJson}=await import('./lib/production-nonroot-contracts.mjs');
  const input=parseNonrootJson(raw);need(input.kind===(operation==='publication-audit'?'audit':'probe'));
  if(input.kind==='audit')need(input.mode==='paused-canary'&&input.compatibility?.version===5,'ContinuationPublicationVersion');
  const {taskMain}=await import('./lib/production-continuation-publication.mjs');return taskMain(env);
 }
 const envelope=parseContinuationInspection(env.MEM9_CONTINUATION_INSPECTION_REQUEST,{operation,invocation:env.MEM9_OPERATOR_INVOCATION});
 const remainingInspectionTime=()=>{const remaining=envelope.deadline-Date.now();need(remaining>0,'ContinuationInspectionDeadline');return remaining;};
 const input=validateContinuationRootInput(envelope.input,{owner:envelope.owner,invocation:envelope.invocation,env,operation});
 need(await rootAuditSourceClosure(name=>readFile(new URL('../'+name,import.meta.url),'utf8'))===input.dependencyHash,'RootSourceClosureChanged');
 const {auditPausedCanary}=await import('./lib/production-canary-paused-audit.mjs');
 const continuation=await import('./lib/production-canary-continuation.mjs'),snapshot=await import('./lib/production-canary-snapshot.mjs');
 const {readRolloutState}=await import('./lib/production-runtime-state.mjs'),{verifyWorkerPrivileges}=await import('./production-consolidation-operator.mjs');
 const pg=(await import('pg')).default;
 remainingInspectionTime();
 const credential=JSON.parse(env.MEM9_DB_SECRET);need(credential.username===schemaAdministratorRole('prod')&&typeof credential.password==='string'&&credential.password.length>0,'ContinuationCredential');
 const db=new pg.Client({host:env.MEM9_DB_HOST,port:Number(env.MEM9_DB_PORT),database:env.MEM9_DB_NAME,user:credential.username,password:credential.password,ssl:{rejectUnauthorized:true},connectionTimeoutMillis:10000,options:'-c default_transaction_read_only=on -c statement_timeout=30000 -c lock_timeout=3000 -c idle_in_transaction_session_timeout=15000 -c idle_session_timeout=30000'});
 const key=createHash('sha256').update('prod').digest().readInt32BE(0);
 let locked=false,transaction=false,result,error,timer;
 try{
  timer=setTimeout(()=>process.exit(1),Math.min(140000,remainingInspectionTime()));
  await db.connect();remainingInspectionTime();need((await db.query('SELECT pg_try_advisory_lock($1,$2) AS owned',[197570,key])).rows[0]?.owned===true,'RootLeaseBusy');locked=true;
  await db.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');transaction=true;
  result=await auditRootTransaction(db,input,{auditPausedCanary,...continuation,...snapshot,readRolloutState,verifyWorkerPrivileges,hash});
  if(operation==='capacity-census')result.census=await captureContinuationCensus(db,input,result.observedMs);
  if(operation==='absence-audit')result.absence=await readContinuationAbsence(db,input,{...continuation,...snapshot,readRolloutState,schemaAdministratorRole,hash,now:Date.now,connection:{host:env.MEM9_DB_HOST,database:env.MEM9_DB_NAME}},{deadlineMs:envelope.deadline});
 }catch(cause){error=cause;}
 finally{
  try{if(transaction)await db.query('ROLLBACK');}catch(cause){error=cause;}
  try{if(locked)need((await db.query('SELECT pg_advisory_unlock($1,$2) AS released',[197570,key])).rows[0]?.released===true,'RootUnlockFailed');}catch(cause){error=cause;}
  try{await db.end();}catch(cause){error=cause;}clearTimeout(timer);
 }
 if(error)throw error;
 console.log(JSON.stringify({event:'continuation_inspection',version:1,operation,invocation:envelope.invocation,inputHash:sha(env.MEM9_CONTINUATION_INSPECTION_REQUEST),cleanupComplete:true,...result}));
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)runContinuationInspection().catch(()=>{console.log(JSON.stringify({event:'continuation_inspection_failed',errorClass:'ContinuationInspectionFailed'}));process.exitCode=1;});
