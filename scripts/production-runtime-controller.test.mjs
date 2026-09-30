import {describe,it,expect} from 'vitest';
import {runProductionRuntime} from './run-production-runtime.mjs';

const stage='pr-7',region='ap-northeast-1',account='123456789012';
function fixture({plan,manifest}={}){
  const processes=[],calls=[],writes=[];
  const send=async command=>{
    const name=command.constructor.name;calls.push(name);
    if(name==='GetCallerIdentityCommand')return {Account:account};
    if(name==='DeleteParameterCommand')return {};
    if(name==='PutParameterCommand'){writes.push(command.input);return {};}
    if(name==='GetParametersCommand'){
      const key=command.input.Names[0],value=key.endsWith('/production-plan')?plan:key.endsWith('/production-manifest')?manifest:undefined;
      return value?{Parameters:[{Name:key,Value:JSON.stringify(value)}]}:{InvalidParameters:[key]};
    }
    throw Error('UnexpectedCommand');
  };
  return {processes,calls,writes,clients:{ssm:{send},sts:{send}},execute:async(...args)=>{processes.push(args);return {};}};
}
describe('partial preparation cleanup',()=>{
  it.each(['prepare','apply','resume','finalize'])('blocks production %s without matching completed rehearsal evidence',async command=>{
    const f=fixture();await expect(runProductionRuntime({...f,stage:'prod',region,command,env:{}})).rejects.toThrow('ProductionRehearsalRequired');
    expect(f.calls.every(name=>['GetCallerIdentityCommand','GetParametersCommand'].includes(name))).toBe(true);
    expect(f.processes).toEqual([]);
  });
  it('removes a verified disposable stage even if image validation failed before creating a plan',async()=>{
    const f=fixture();await runProductionRuntime({...f,stage,region,command:'cleanup-preview',env:{}});
    expect(f.processes).toHaveLength(1);
    expect(f.processes[0][1]).toEqual(['-C','infra','exec','sst','remove','--stage',stage,'--print-logs']);
    expect(f.processes[0][2].env.MEM9_PRODUCTION_RUNTIME_MODE).toBe('off');
  });
  it('retains the prepared graph shape when deployment failed before the manifest was published',async()=>{
    const plan={version:1,stage,region,account,nonce:'a'.repeat(32),fallbackImages:{synthetic:'image'}};
    const f=fixture({plan});await runProductionRuntime({...f,stage,region,command:'cleanup-preview',env:{}});
    expect(f.processes[0][2].env.MEM9_PRODUCTION_RUNTIME_MODE).toBe('prepare');
    expect(f.processes[0][2].env.MEM9_RUNTIME_FALLBACK_IMAGES).toBe(JSON.stringify(plan.fallbackImages));
  });
  it('never removes production or assumes off when a manifest lost its routing plan',async()=>{
    const f=fixture();await expect(runProductionRuntime({...f,stage:'prod',region,command:'cleanup-preview',env:{}})).rejects.toThrow('PreviewCleanupOnly');
    expect(f.processes).toEqual([]);
    const g=fixture({manifest:{mode:'active'}});
    await expect(runProductionRuntime({...g,stage,region,command:'cleanup-preview',env:{}})).rejects.toThrow('ProductionPlanMissing');
    expect(g.processes).toEqual([]);
  });
  it('does not let a stale cancellation wake a newer operation or a deleted preview',async()=>{
    const plan={version:1,stage,region,account,nonce:'a'.repeat(32),sourceRunId:'1234'};
    for(const f of [fixture({plan}),fixture()]){
      await runProductionRuntime({...f,stage,region,command:'recover',env:{MEM9_RUNTIME_RECOVERY_RUN_ID:'999'}});
      expect(f.calls.every(name=>['GetCallerIdentityCommand','GetParametersCommand'].includes(name))).toBe(true);
      expect(f.processes).toEqual([]);
    }
  });
  it('claims a saved plan for the current run even when the previous attempt created no manifest',async()=>{
    const plan={version:1,stage,region,account,nonce:'a'.repeat(32),sourceRunId:'111'};
    const f=fixture({plan});
    f.clients.rds={send:async()=>{expect(f.writes).toHaveLength(1);throw Error('SyntheticPreflightFailure');}};
    await expect(runProductionRuntime({...f,stage,region,command:'prepare',env:{GITHUB_RUN_ID:'222'}})).rejects.toThrow('SyntheticPreflightFailure');
    expect(JSON.parse(f.writes[0].Value)).toMatchObject({sourceRunId:'222',nonce:plan.nonce});
    expect(f.processes).toEqual([]);
  });
});
