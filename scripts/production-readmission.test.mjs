import {readFileSync} from 'node:fs';
import {describe,it,expect,vi} from 'vitest';
import {parse} from 'yaml';
import {readmitProductionRelease,productionReadmissionRecord} from './run-production-canary.mjs';
import {classifyChangedPaths} from './classify-infra-changes.mjs';

const region='ap-northeast-1',revision='a'.repeat(40),admission='b'.repeat(64);
function fixture({promoted=true,enabled=true}={}){
  const targets=['planner','executor'].map(kind=>({kind,template:{Target:{Input:JSON.stringify({containerOverrides:[{
    environment:[{name:'MEM9_WORKER_ADMISSION',value:promoted?admission:'unverified'}],
  }]})}}}));
  const status={phase:'status',setupPhase:promoted?'promote':'prepared',enabled,dispatcherEnabled:enabled,admission};
  const deps={readRevision:vi.fn(()=>revision),currentMain:vi.fn(async()=>revision),
    loadWorker:vi.fn(async(_clients,{kind})=>targets.find(t=>t.kind===kind)),
    administer:vi.fn(async(_clients,{operation})=>operation==='status'?{...status}:{admission,changed:true,enabled}),
    verify:vi.fn(async()=>({taskDefinitions:['private-task-reference']}))};
  return {deps,targets,status,run:()=>readmitProductionRelease({}, {region,ifPromoted:true},deps)};
}

describe('production deployment readmission',()=>{
  it('TC-CONS-WORKER-131 re-admits promoted work and verifies SQL and schedules',async()=>{
    const f=fixture();
    await expect(f.run()).resolves.toMatchObject({phase:'readmitted',changed:true,enabled:true});
    expect(f.deps.administer.mock.calls.map(([,o])=>o.operation)).toEqual(['status','readmit','status']);
    expect(f.deps.administer).toHaveBeenCalledWith({}, {region,operation:'readmit',expectedAdmission:admission});
    expect(f.deps.verify).toHaveBeenLastCalledWith({},f.targets,{enabled:true,admission});
  });
  it('TC-CONS-WORKER-132 leaves unpromoted, disabled workers disabled',async()=>{
    const f=fixture({promoted:false,enabled:false});
    await expect(f.run()).resolves.toEqual({phase:'not-promoted',changed:false,enabled:false});
    expect(f.deps.administer.mock.calls.map(([,o])=>o.operation)).toEqual(['status','install-planner-upgrade']);
    expect(f.deps.verify).toHaveBeenCalledWith({},f.targets,{enabled:false});
  });
  it('accepts absent setup only when neither SQL control is enabled',async()=>{
    const f=fixture({promoted:false,enabled:false});
    delete f.status.setupPhase;delete f.status.dispatcherEnabled;
    await expect(f.run()).resolves.toMatchObject({phase:'not-promoted',enabled:false});
  });
  it('does not skip an unpromoted deployment with an enabled or invalid schedule',async()=>{
    const f=fixture({promoted:false,enabled:false});
    f.deps.verify.mockRejectedValue(Error('ProductionSchedulingNotVerified'));
    await expect(f.run()).rejects.toThrow('ProductionSchedulingNotVerified');
    expect(f.deps.administer.mock.calls.map(([,o])=>o.operation)).toEqual(['status']);
  });
  it('rejects a changed main revision before installing on an unpromoted deployment',async()=>{
    const f=fixture({promoted:false,enabled:false});
    f.deps.currentMain.mockResolvedValueOnce(revision).mockResolvedValue('c'.repeat(40));
    await expect(f.run()).rejects.toThrow('ProductionReadmissionRequiresMain');
    expect(f.deps.administer.mock.calls.map(([,o])=>o.operation)).toEqual(['status']);
  });
  it('propagates an unpromoted installation failure after verifying disabled schedules',async()=>{
    const f=fixture({promoted:false,enabled:false});
    f.deps.administer.mockImplementation(async(_,{operation})=>{
      if(operation==='status')return f.status;
      throw Error('PlannerUpgradeCatalogMismatch');
    });
    await expect(f.run()).rejects.toThrow('PlannerUpgradeCatalogMismatch');
    expect(f.deps.verify).toHaveBeenCalledWith({},f.targets,{enabled:false});
    expect(f.deps.administer.mock.calls.map(([,o])=>o.operation)).toEqual(['status','install-planner-upgrade']);
  });
  it('keeps explicit operator readmission available without a conditional skip',async()=>{
    const f=fixture();
    await expect(readmitProductionRelease({}, {region},f.deps)).resolves.toMatchObject({phase:'readmitted'});
    expect(f.deps.administer.mock.calls.map(([,o])=>o.operation)).toEqual(['readmit']);
  });
  it('TC-CONS-WORKER-133 preserves a promoted pause',async()=>{
    const f=fixture({enabled:false});
    await expect(f.run()).resolves.toMatchObject({phase:'readmitted',enabled:false});
    expect(f.deps.verify).toHaveBeenLastCalledWith({},f.targets,{enabled:false,admission});
  });
  it.each([{enabled:true},{dispatcherEnabled:true},{enabled:'false'},{dispatcherEnabled:null}])(
    'TC-CONS-WORKER-134 rejects unsafe unpromoted control state %j',async patch=>{
      const f=fixture({promoted:false,enabled:false});Object.assign(f.status,patch);
      await expect(f.run()).rejects.toThrow('ProductionReadmissionStateMismatch');
      expect(f.deps.administer).toHaveBeenCalledTimes(1);
    });
  it('rejects divergent promoted execution and dispatcher controls before mutation',async()=>{
    const f=fixture();f.status.enabled=false;
    await expect(f.run()).rejects.toThrow('ProductionReadmissionStateMismatch');
    expect(f.deps.administer).toHaveBeenCalledTimes(1);
  });
  it.each([{admission:'c'.repeat(64)},{enabled:false},{dispatcherEnabled:false},{setupPhase:'canary'}])(
    'TC-CONS-WORKER-135 rejects a failed SQL readback %j',async patch=>{
    const f=fixture();let reads=0;
    f.deps.administer.mockImplementation(async(_,{operation})=>operation==='readmit'
      ?{admission,enabled:true,changed:true}:{...f.status,...(++reads===1?{}:patch)});
    await expect(f.run()).rejects.toThrow('ProductionReadmissionStateMismatch');
  });
  it('checks main again after loading deployment state and before mutation',async()=>{
    const f=fixture();f.deps.currentMain.mockResolvedValueOnce(revision).mockResolvedValue('c'.repeat(40));
    await expect(f.run()).rejects.toThrow('ProductionReadmissionRequiresMain');
    expect(f.deps.administer.mock.calls.map(([,o])=>o.operation)).toEqual(['status']);
  });
  it.each(['administer','verify'])('does not suppress %s failures',async method=>{
    const f=fixture();f.deps[method].mockRejectedValue(Error('synthetic failure'));
    await expect(f.run()).rejects.toThrow('synthetic failure');
  });
  it('TC-CONS-WORKER-136 rejects a different main revision and mismatched schedule admissions',async()=>{
    const f=fixture();f.deps.currentMain.mockResolvedValue('c'.repeat(40));
    await expect(f.run()).rejects.toThrow('ProductionReadmissionRequiresMain');
    expect(f.deps.administer).not.toHaveBeenCalled();
    f.deps.currentMain.mockResolvedValue(revision);
    f.targets[1].template.Target.Input=f.targets[1].template.Target.Input.replace(admission,'d'.repeat(64));
    await expect(f.run()).rejects.toThrow('ProductionReadmissionScheduleMismatch');
    expect(f.deps.administer.mock.calls.every(([,o])=>o.operation==='status')).toBe(true);
  });
  it('TC-CONS-WORKER-137 emits only content-free CI status',()=>{
    const result=productionReadmissionRecord({phase:'readmitted',changed:true,enabled:true,
      admission,activationSeed:'private-seed',taskDefinitions:['private-task-reference'],content:'private-content'});
    expect(result).toEqual({event:'production_canary',phase:'readmitted',changed:true,enabled:true});
    expect(JSON.stringify(result)).not.toMatch(/private|bbbbbbbb/);
    for(const patch of [{phase:admission},{enabled:admission},{changed:{private:'secret'}}])
      expect(()=>productionReadmissionRecord({...result,...patch})).toThrow('InvalidProductionReadmissionResult');
  });
  it('TC-CONS-WORKER-138 makes readmission a hard production gate after bootstrap',()=>{
    const workflow=parse(readFileSync(new URL('../.github/workflows/infra-ci.yml',import.meta.url),'utf8'));
    const prod=workflow.jobs['deploy-prod'],steps=prod.steps;
    const at=steps.findIndex(s=>s.name==='Re-admit production consolidation');
    expect(at).toBeGreaterThan(steps.findIndex(s=>s.name==='Run schema-bootstrap task (prod)'));
    expect(at).toBeLessThan(steps.findIndex(s=>s.name==='MCP write-search E2E (prod, hard)'));
    expect(steps[at]).toMatchObject({if:"env.MEM9_PRODUCTION_RUNTIME_MODE == 'active' && needs.changes.outputs.workload_changed == 'true'",
      run:'node scripts/run-production-canary.mjs readmit-if-promoted',env:{STAGE:'prod',GH_TOKEN:'${{ github.token }}'},'timeout-minutes':20});
    expect(steps[at]['continue-on-error']).toBeUndefined();
    expect(prod['timeout-minutes']).toBeGreaterThanOrEqual(95);
    expect(prod['runs-on']).toBe("${{ vars.RUNNER_LABEL && fromJSON(vars.RUNNER_LABEL) || 'ubuntu-latest' }}");
    for(const [name,job] of Object.entries(workflow.jobs))if(name!=='deploy-prod')
      expect(job.steps?.some(s=>s.run?.includes('readmit-if-promoted'))??false).toBe(false);
  });
  it('TC-CONS-WORKER-139 preserves infrastructure-only image reuse',()=>{
    const workflow=parse(readFileSync(new URL('../.github/workflows/infra-ci.yml',import.meta.url),'utf8'));
    const step=workflow.jobs['deploy-prod'].steps.find(s=>s.name==='Re-admit production consolidation');
    const shouldRun=new Function('env','needs',`return (${step.if});`);
    const eligible=(paths,mode='active')=>shouldRun({MEM9_PRODUCTION_RUNTIME_MODE:mode},
      {changes:{outputs:{workload_changed:String(classifyChangedPaths(paths).workloadChanged)}}});
    expect(eligible(['infra/observability.ts'])).toBe(false);
    expect(eligible(['scripts/run-production-canary.mjs'])).toBe(true);
    expect(eligible(['docker/llm-proxy/server.mjs'])).toBe(true);
    expect(eligible(['docker/llm-proxy/server.mjs'],'prepare')).toBe(false);
  });
});
