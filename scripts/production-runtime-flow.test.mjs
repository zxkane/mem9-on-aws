import {describe,it,expect} from 'vitest';
import {applyProductionCutover,finalizeProductionCutover,recoverProductionCutover} from './lib/production-runtime-flow.mjs';

function fixture(initial='prepared'){
  let state={phase:initial,status:'running',epoch:1,started_ms:initial==='prepared'?null:1000,deadline_ms:initial==='prepared'?null:7201000};
  const events=[],record=name=>async()=>{events.push(name);return {};};
  const moves={begin:'maintenance',runtime:'runtime_prepared',fence:'password_fenced',transfer:'transferred',
    'runtime-ready':'runtime_ready',retire:'retired',complete:'complete'};
  const actions={read:async()=>({...state}),mirror:record('mirror'),invoke:async op=>{
    events.push(op);if(moves[op])state.phase=moves[op];
    if(op==='begin'){state.started_ms=1000;state.deadline_ms=7201000;}
    if(op==='verify-fence'&&state.phase==='retired')state.proofs={retired_credentials:true};
    if(op==='recover'){state.status='recovering';state.epoch++;}
    if(op==='restored'){state.status='restored';state.epoch++;}
    return {...state};
  }};
  for(const name of ['freezeLegacy','verifyLegacySessions','verifyAdministrator','restoreRuntime','verifyForeground',
    'convergeActive','verifyRetirement','stopInvocations','cancelBackend','acknowledgeStopped'])actions[name]=record(name);
  return {actions,events,getState:()=>state};
}
describe('bounded production cutover sequencing',()=>{
  it('restores and verifies runtime before retiring the actual legacy credential',async()=>{
    const f=fixture();expect((await applyProductionCutover(f.actions,{now:()=>1001})).phase).toBe('retired');
    expect(f.events.indexOf('runtime')).toBeLessThan(f.events.indexOf('fence'));
    expect(f.events.indexOf('verifyForeground')).toBeLessThan(f.events.indexOf('retire'));
    expect(f.events).not.toContain('convergeActive');
    expect((await finalizeProductionCutover(f.actions)).phase).toBe('complete');
    expect(f.events.indexOf('verifyRetirement')).toBeLessThan(f.events.indexOf('complete'));
  });
  it('resumes committed phases without replaying password rotation',async()=>{
    const f=fixture('transferred');await applyProductionCutover(f.actions,{now:()=>1001});
    expect(f.events).not.toContain('fence');expect(f.events).not.toContain('transfer');
  });
  it('pauses only after the real password fence and its mirror, before transfer',async()=>{
    const f=fixture('runtime_prepared');
    f.actions.beforeFence=async state=>{expect(state.phase).toBe('runtime_prepared');f.events.push('admit-drill');};
    f.actions.afterFence=async state=>{
      expect(state.phase).toBe('password_fenced');expect(f.events.slice(-2)).toEqual(['fence','mirror']);
      f.events.push('await-cancellation');throw Error('SyntheticCheckpointPause');
    };
    await expect(applyProductionCutover(f.actions,{now:()=>1001})).rejects.toThrow('SyntheticCheckpointPause');
    expect(f.events.indexOf('admit-drill')).toBeLessThan(f.events.indexOf('fence'));
    expect(f.events).not.toContain('transfer');expect(f.events).not.toContain('verify-fence');
  });
  it('preserves time for credential refresh and recovery instead of beginning another step at minute45',async()=>{
    const f=fixture('password_fenced');
    await expect(applyProductionCutover(f.actions,{now:()=>2701000})).rejects.toThrow('ProductionRecoveryRequired');
    expect(f.events).toEqual([]);
  });
  it('stops old tasks and fences their database backend before restoring service',async()=>{
    const f=fixture('runtime_prepared');const state=await recoverProductionCutover(f.actions);
    expect(state.phase).toBe('runtime_prepared');expect(state.status).toBe('restored');
    expect(f.events.indexOf('stopInvocations')).toBeLessThan(f.events.indexOf('cancelBackend'));
    expect(f.events.indexOf('recover')).toBeLessThan(f.events.indexOf('acknowledgeStopped'));
    expect(f.events.indexOf('recover')).toBeLessThan(f.events.indexOf('restoreRuntime'));
    expect(f.events).toContain('repair');expect(state.deadline_ms).toBe(7201000);
  });
  it('does not switch a serving credential during recovery before maintenance begins',async()=>{
    const f=fixture();const state=await recoverProductionCutover(f.actions);
    expect(state).toMatchObject({phase:'prepared',status:'restored',started_ms:null,deadline_ms:null});
    expect(f.events).not.toContain('repair');expect(f.events).not.toContain('restoreRuntime');
  });
  it('rechecks a committed password fence when resuming before ownership transfer',async()=>{
    const f=fixture('password_fenced');await applyProductionCutover(f.actions,{now:()=>1001});
    expect(f.events.indexOf('verify-fence')).toBeLessThan(f.events.indexOf('transfer'));
    expect(f.events.indexOf('verifyLegacySessions')).toBeLessThan(f.events.indexOf('transfer'));
  });
  it('repairs after a failed administrator replay and gives overdue recovery a bounded observation budget',async()=>{
    const f=fixture('transferred');let observedDeadline;
    f.actions.restoreRuntime=async(_state,deadline)=>{f.events.push('restoreRuntime');observedDeadline=deadline;};
    const state=await recoverProductionCutover(f.actions,{now:()=>9000000});
    expect(f.events.indexOf('repair')).toBeLessThan(f.events.indexOf('restoreRuntime'));
    expect(observedDeadline).toBe(11100000);expect(state.deadline_ms).toBe(7201000);
  });
  it('reserves restoration time before repair instead of starting another full budget afterward',async()=>{
    const f=fixture('maintenance');let time=1000,repairDeadline,restoreDeadline,verificationDeadline;
    const invoke=f.actions.invoke;
    f.actions.invoke=async(op,state,extra,limits)=>{
      if(op==='repair'){repairDeadline=limits.deadline;time=repairDeadline-1;}
      return invoke(op,state,extra);
    };
    f.actions.restoreRuntime=async(_state,deadline)=>{restoreDeadline=deadline;};
    f.actions.verifyForeground=async(_state,deadline)=>{verificationDeadline=deadline;};
    await recoverProductionCutover(f.actions,{now:()=>time,deadline:2701000});
    expect(repairDeadline).toBe(1501000);expect(restoreDeadline).toBe(2101000);expect(verificationDeadline).toBe(2701000);
  });
});
