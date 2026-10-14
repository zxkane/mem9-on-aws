import {it,expect} from 'vitest';
import {readContinuationAbsence,validateContinuationAbsence} from './lib/production-continuation-absence.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';

function fixture(defect){
 const now=1800000000000,proof={validationId:'a'.repeat(32),generation:'b'.repeat(64),targets:['namespace-a','namespace-b'],changedRows:6,receipts:3},projection={synthetic:'original-full-projection'};
 const identity={stage:'prod',administratorRoleOid:10,legacyRoleOid:11,runtimeRoleOid:12,database:'mem9',databaseOid:13,writerEndpoint:'example.com'};
 const state={identity,operation_nonce:'c'.repeat(32),epoch:2,last_hash:'d'.repeat(64),phase:'complete',status:'running',proofs:{administrator:true,retired_credentials:true}};
 const setup={phase:'canary',canary_used:proof.changedRows,canary_started_at:'synthetic',promotion_verification:null,targets:proof.targets,validation_id:proof.validationId,generation:proof.generation,receipt_verification:proof,backend_binding:{synthetic:true}};
 const input={invocation:'e'.repeat(32),runtimeNonce:state.operation_nonce,parent:{verification:proof},certificate:{previous:{release:{sourceTree:'f'.repeat(40)}}},absence:{rejectedAttemptId:'1'.repeat(32),runtimeEpoch:state.epoch,runtimeHistoryHash:state.last_hash,identityHash:hash(identity),rootIdentity:'2'.repeat(64),projectionHash:hash(projection)}};
 if(defect==='parent-counter')setup.canary_used++;
 if(defect==='epoch')state.epoch++;
 if(defect==='projection')projection.changed=true;
 const calls=[],db={query:async(sql,args=[])=>{
  calls.push({sql,args});expect(sql).toMatch(/^(SELECT|SET LOCAL) /);expect(sql).not.toMatch(/\b(?:INSERT|UPDATE|DELETE|CREATE TABLE|DROP TABLE|TRUNCATE)\b/);
  if(sql.startsWith('SET LOCAL'))return {rows:[]};
  if(sql.startsWith('SELECT current_user'))return {rows:[{direct:true,readonly:defect!=='write-session',repeatable:true,oid:10,name:'fixture_admin',database:'mem9',database_oid:13,snapshot_ms:String(now)}]};
  if(sql.startsWith('SELECT NOT rolcanlogin'))return {rows:[{safe:defect!=='legacy-login'}]};
  if(sql.startsWith('SELECT * FROM mem9_maintenance.production_worker_setup'))return {rows:[setup]};
  if(sql.startsWith('SELECT enabled,epoch'))return {rows:[{enabled:defect==='enabled',retired_roles:[11]}]};
  if(sql.startsWith('SELECT enabled FROM'))return {rows:[{enabled:false}]};
  if(sql.startsWith('SELECT to_regclass'))return {rows:[{present:defect!=='absent-tables'}]};
  if(sql.includes('production_canary_validation_')){
   const name=sql.match(/production_canary_validation_([a-z]+)/)[1];expect(['attempts','events','current','admissions','receipts']).toContain(name);
   if(sql.includes('WHERE attempt_id'))expect(args).toEqual([input.absence.rejectedAttemptId]);
   return {rows:[{count:defect===name?1:0}]};
  }
  if(sql==='SELECT count(*)::int AS count FROM mem9_maintenance.receipts')return {rows:[{count:proof.receipts}]};
  if(sql.startsWith('SELECT count(*)::int AS count FROM public.memories')){expect(proof.targets).toContain(args[0]);expect(args[1]).toBe('mem9-canary-'+proof.validationId);return {rows:[{count:defect==='benchmark'?1:0}]};}
  if(sql.startsWith('SELECT count(*)::int AS total')){expect(args).toEqual([proof.targets]);return {rows:[{total:12,active:10,fingerprint:'3'.repeat(64)}]};}
  throw Error('Unexpected query');
 }};
 const modules={now:()=>now,readRolloutState:async()=>state,schemaAdministratorRole:()=> 'fixture_admin',hash,connection:{host:'example.com',database:'mem9'},captureCanarySnapshot:async()=>({verification:proof,projection}),canaryRootIdentity:async()=>input.absence.rootIdentity};
 return {db,input,modules,deadlineMs:now+60000,calls};
}
it.each(['existing-empty-tables','absent-tables'])('verifies all original absence controls with %s',async defect=>{
 const f=fixture(defect),out=await readContinuationAbsence(f.db,f.input,f.modules,f);
 expect(out.rejectedAttemptAbsent).toBe(true);expect(out.storage.map(s=>s.name)).toEqual(['attempts','events','current','admissions','receipts']);
 expect(out.canaryUsed).toBe(6);expect(out.receipts).toBe(3);expect(out.liveBaseline).toEqual({total:12,active:10,fingerprint:'3'.repeat(64)});
 expect(f.calls.filter(c=>c.sql.includes('public.memories'))).toHaveLength(3);
 expect(f.calls.some(c=>/^(BEGIN|COMMIT|ROLLBACK)/.test(c.sql))).toBe(false);
});
it.each(['attempts','events','current','admissions','receipts','write-session','legacy-login','enabled','parent-counter','epoch','projection','benchmark'])('rejects %s without initializing or changing continuation storage',async defect=>{
 const f=fixture(defect);await expect(readContinuationAbsence(f.db,f.input,f.modules,f)).rejects.toThrow('ContinuationAbsenceRejected');
});
it.each(['missing-epoch','wrong-id','extra-query'])('rejects %s before any query',async defect=>{
 const f=fixture();if(defect==='missing-epoch')delete f.input.absence.runtimeEpoch;if(defect==='wrong-id')f.input.absence.rejectedAttemptId='bad';if(defect==='extra-query')f.input.absence.sql='SELECT 1';
 expect(()=>validateContinuationAbsence(f.input)).toThrow('ContinuationAbsenceInput');
 await expect(readContinuationAbsence(f.db,f.input,f.modules,f)).rejects.toThrow();expect(f.calls).toHaveLength(0);
});
