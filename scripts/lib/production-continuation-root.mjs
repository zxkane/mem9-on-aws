/** Fixed read-only continuation inspection. This is not a continuation admission. */
export async function rootAuditSourceClosure(read){
 const {createHash}=await import('node:crypto'),{posix}=await import('node:path');
 const digest=v=>createHash('sha256').update(v).digest('hex');
 const pending=['scripts/lib/production-canary-paused-audit.mjs','scripts/lib/production-canary-continuation.mjs','scripts/lib/production-continuation-absence.mjs'],files=new Map();
 while(pending.length){
  const name=pending.pop();if(files.has(name))continue;
  if(files.size>=256||name.startsWith('../')||!/^[-A-Za-z0-9_./]+\.(?:mjs|js)$/.test(name))throw Error('RootSourceClosureInvalid');
  const text=await read(name);if(typeof text!=='string'||Buffer.byteLength(text)>2097152)throw Error('RootSourceClosureInvalid');files.set(name,digest(text));
  for(const match of text.matchAll(/(?:from\s+|import\s*\(?\s*)['"](\.[^'"]+)['"]/g)){
   const target=posix.normalize(posix.join(posix.dirname(name),match[1]));if(target.startsWith('../')||!/^[-A-Za-z0-9_./]+\.(?:mjs|js)$/.test(target))throw Error('RootSourceClosureInvalid');pending.push(target);
  }
 }
 return digest(JSON.stringify([...files].sort(([a],[b])=>a<b?-1:a>b?1:0)));
}

/** SQL helper shared by the fixed payload and offline database fixtures. */
export async function auditRootTransaction(db,input,modules){
 const observedMs=Number((await db.query('SELECT floor(extract(epoch FROM transaction_timestamp())*1000)::bigint AS observed_ms')).rows[0]?.observed_ms);
 if(!Number.isSafeInteger(observedMs)||observedMs<=0)throw Error('RootTransactionTimeInvalid');
 const active=await modules.currentCanaryAttempt(db),parent=input.parent.verification;
 const present=(await db.query("SELECT to_regclass('mem9_maintenance.production_canary_validation_attempts') IS NOT NULL AS present")).rows[0]?.present;
 if(typeof present!=='boolean')throw Error('RootInventoryInvalid');
 if(present){
  const rows=(await db.query('SELECT attempt_id FROM mem9_maintenance.production_canary_validation_attempts WHERE validation_id=$1 ORDER BY ordinal LIMIT 1001',[parent.validationId])).rows;
  if(!Array.isArray(rows)||rows.length>1000||new Set(rows.map(r=>r.attempt_id)).size!==rows.length)throw Error('RootInventoryInvalid');
  for(const row of rows){const other=await modules.readCanaryAttempt(db,row.attempt_id);
   if(other.row.validation_id!==parent.validationId||other.row.ordinal>0&&!other.frozen&&other.phase!=='failed'&&(other.row.attempt_id!==input.owner||active?.row.attempt_id!==input.owner))throw Error('RootForeignAttempt');
  }
 }
 if(!active||active.row.ordinal===0){
  const audit=await modules.auditPausedCanary(db,input.rootConfig,input.certificate);
  if(audit.changedRows!==parent.changedRows||audit.receipts!==parent.receipts||audit.conservationHash!==parent.conservationHash||audit.parentProofHash!==input.rootBinding.parentProofHash||audit.executionEnabled!==false||audit.dispatcherEnabled!==false||audit.benchmarkRemaining!==0)throw Error('RootChanged');
  return {rootEvidence:{kind:'paused',observedMs,audit},rootHash:audit.rootIdentity,observedMs,dependencyHash:input.dependencyHash};
 }
 if(active.row.attempt_id!==input.owner||active.row.header.parentProofHash!==input.rootBinding.parentProofHash||active.row.header.certificateHash!==modules.hash(input.certificate))throw Error('RootAttemptChanged');
 const state=await modules.readRolloutState(db),setup=(await db.query('SELECT * FROM mem9_maintenance.production_worker_setup WHERE singleton')).rows[0];
 const identity=(await db.query("SELECT current_user=session_user AS direct,session_user::regrole::oid::bigint AS oid,current_setting('transaction_read_only')='on' AS readonly")).rows[0];
 if(!identity?.direct||!identity.readonly||Number(identity.oid)!==state.identity.administratorRoleOid||state.operation_nonce!==input.runtimeNonce||state.identity.writerEndpoint!==input.rootConfig.host||state.identity.database!==input.rootConfig.database||setup.validation_id!==parent.validationId||setup.generation!==parent.generation)throw Error('RootIdentityChanged');
 for(const kind of ['planner','executor'])await modules.verifyWorkerPrivileges(db,input.rootConfig[kind].username,kind);
 const rootHash=await modules.canaryRootIdentity(db,state);if(rootHash!==active.row.header.rootIdentity)throw Error('RootChanged');
 const snapshot=modules.bindAttemptProof(await modules.captureCanarySnapshot(db,input.rootConfig,state,setup,{lock:false,backend:active.row.header.backendBinding}),active);
 await modules.verifyCanaryMembership(db,setup,active,snapshot.projection.receiptIds);
 const {verification,replayActions,backendBinding,receiptWindow}=snapshot;
 return {rootEvidence:{kind:'continuation',attemptId:input.owner,observedMs,report:{verification,replayActions,backendBinding,receiptWindow}},rootHash,observedMs,dependencyHash:input.dependencyHash};
}
