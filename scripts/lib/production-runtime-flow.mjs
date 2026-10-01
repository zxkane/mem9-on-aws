// The AWS adapter supplies verified targets and bounded operations. Database
// receipts, not successful process exits, determine which step resumes next.
export async function applyProductionCutover(actions,{now=Date.now}={}){
  let state=await actions.read();
  if(state.phase==='complete')return state;
  if(state.status!=='running')throw Error('ExplicitRecoveryRequired');
  const invoke=async(operation,extra={})=>{
    state=await actions.invoke(operation,state,extra);
    await actions.mirror(state);return state;
  };
  if(state.phase==='prepared')await invoke('begin');
  const cutoff=state.started_ms+45*60000;
  const admit=()=>{if(now()>=cutoff)throw Error('ProductionRecoveryRequired');};
  if(state.phase==='maintenance'){
    admit();await actions.freezeLegacy(state,cutoff);
    await invoke('runtime');
  }
  if(state.phase==='runtime_prepared'){
    admit();await actions.beforeFence?.(state);await invoke('fence');
    await actions.afterFence?.(state);
  }
  if(state.phase==='password_fenced'){
    admit();await invoke('verify-fence');await actions.verifyLegacySessions(state);await invoke('transfer');
  }
  if(state.phase==='transferred'){
    admit();await invoke('revoke');
    await actions.verifyAdministrator(state,cutoff);
    await actions.restoreRuntime(state,cutoff);
    const evidence=await actions.verifyForeground(state,cutoff);
    await invoke('runtime-ready',evidence);
  }
  if(state.phase==='runtime_ready'){
    admit();await actions.verifyLegacySessions(state);
    await invoke('retire');
  }
  if(state.phase==='retired'&&!state.proofs?.retired_credentials)await invoke('verify-fence');
  // IaC convergence and final IAM verification run after a fresh CI credential
  // setup, while the restricted runtime already serves reads and writes.
  return state;
}

export async function finalizeProductionCutover(actions){
  let state=await actions.read();
  if(state.phase==='complete')return state;
  if(state.phase!=='retired'||state.status!=='running')throw Error('ProductionRetirementRequired');
  if(!state.proofs?.retired_credentials){state=await actions.invoke('verify-fence',state);await actions.mirror(state);}
  await actions.convergeActive(state);
  const evidence=await actions.verifyRetirement(state);
  state=await actions.invoke('complete',state,evidence);await actions.mirror(state);return state;
}

export async function recoverProductionCutover(actions,{now=Date.now,deadline=now()+45*60000}={}){
  // One command-wide budget: reconciliation/repair gets at most 25 minutes;
  // reserve ten minutes each for task restoration and foreground verification.
  const repairDeadline=deadline-20*60000,restoreDeadline=deadline-10*60000;
  const admit=until=>{if(now()>=until)throw Error('RecoveryPhaseDeadline');};
  admit(repairDeadline);
  let state=await actions.read({deadline:repairDeadline});
  const interrupted={...state};
  if(state.phase==='complete')return state;
  const pending=await actions.stopInvocations(state,repairDeadline);
  await actions.cancelBackend(state,repairDeadline);
  admit(repairDeadline);
  state=await actions.invoke('recover',state,{}, {deadline:repairDeadline});await actions.mirror(state);
  await actions.acknowledgeStopped(pending,state);
  if(state.phase==='prepared'&&state.started_ms===null){
    // Preparatory failure has not opened a maintenance window or changed the
    // serving credential. Leave that healthy service on its existing path.
    state=await actions.invoke('restored',state,{}, {deadline});await actions.mirror(state);return state;
  }
  // Repair first verifies readiness; it replays bootstrap only when necessary,
  // including a failed administrator replay after ownership has transferred.
  admit(repairDeadline);
  state=await actions.invoke('repair',state,{}, {deadline:repairDeadline});await actions.mirror(state);
  admit(restoreDeadline);
  await actions.restoreRuntime(state,restoreDeadline);
  const verification=await actions.verifyForeground(state,deadline);
  state=await actions.invoke('restored',state,{}, {deadline});await actions.mirror(state);
  await actions.afterRestoration?.(interrupted,state,verification);
  return state;
}
