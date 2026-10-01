import {describe,it,expect} from 'vitest';
import {runProductionRuntime,verifyRuntimeImage,safeProductionCommandFailure} from './run-production-runtime.mjs';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

const stage='pr-7',region='ap-northeast-1',account='123456789012';
describe('preview cutover image provenance',()=>{
  it('reports only bounded command diagnostics, excluding raw output and credentials',()=>{
    const diagnostic=safeProductionCommandFailure({code:1,stdout:'private-memory-content',stderr:'secret-value AccessDenied reasons=task_definition_mismatch,secret_value'});
    expect(diagnostic).toEqual({exitCode:1,signals:['AccessDenied'],reasons:['task_definition_mismatch']});
    expect(JSON.stringify(diagnostic)).not.toContain('secret');
    expect(safeProductionCommandFailure({code:'ERR_CHILD_PROCESS_STDIO_MAXBUFFER'}).signals).toEqual(['ERR_CHILD_PROCESS_STDIO_MAXBUFFER']);
  });
  const revision='a'.repeat(40),merge='b'.repeat(40),sourceTree='c'.repeat(40);
  const image=(namespace,tag)=>`${account}.dkr.ecr.${region}.amazonaws.com/${namespace}/mnemo-server:${tag}`;
  const options={account,region,stage,revision,sourceTree,readCommit:async()=>({sha:merge,parents:[{sha:revision},{sha:'d'.repeat(40)}],commit:{tree:{sha:sourceTree}}})};
  it('accepts the actual preview repository and an identical GitHub merge tree',async()=>{
    expect(await verifyRuntimeImage(image('mem9-on-aws/preview','pr-bbbbbbb'),options)).toEqual({namespace:'mem9-on-aws/preview',tag:'pr-bbbbbbb',commit:merge});
  });
  it('rejects a different merged tree or a merge unrelated to the selected head',async()=>{
    for(const merged of [
      {sha:merge,parents:[{sha:revision},{sha:'d'.repeat(40)}],commit:{tree:{sha:'e'.repeat(40)}}},
      {sha:merge,parents:[{sha:'d'.repeat(40)},{sha:'e'.repeat(40)}],commit:{tree:{sha:sourceTree}}},
    ])await expect(verifyRuntimeImage(image('mem9-on-aws/preview','pr-bbbbbbb'),{...options,readCommit:async()=>merged})).rejects.toThrow('RuntimeImageRevisionMismatch');
  });
  it('keeps production and unrelated repositories out of the preview exception',async()=>{
    await expect(verifyRuntimeImage(image('mem9-on-aws-other','pr-aaaaaaa'),options)).rejects.toThrow('RuntimeImageRevisionMismatch');
    await expect(verifyRuntimeImage(image('mem9-on-aws/preview','pr-aaaaaaa'),{...options,stage:'prod'})).rejects.toThrow('RuntimeImageRevisionMismatch');
    await expect(verifyRuntimeImage(image('mem9-on-aws','mem9-bbbbbbb'),{...options,stage:'prod'})).rejects.toThrow('RuntimeImageRevisionMismatch');
    expect(await verifyRuntimeImage(image('mem9-on-aws','mem9-aaaaaaa'),{...options,stage:'prod'})).toMatchObject({commit:revision});
  });
});
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
    const f=fixture();await runProductionRuntime({...f,stage,region,command:'cleanup-preview',env:{MEM9_CONSOLIDATION_SCHEDULE_ENABLED:'1'}});
    expect(f.processes).toHaveLength(1);
    expect(f.processes[0][1]).toEqual(['-C','infra','exec','sst','remove','--stage',stage,'--print-logs']);
    expect(f.processes[0][2].env.MEM9_PRODUCTION_RUNTIME_MODE).toBe('off');
    expect(f.processes[0][2].env.MEM9_CONSOLIDATION_SCHEDULE_ENABLED).toBe('0');
    expect(f.processes[0][2].env.SST_SECRET_MaintenanceNamespaceIds).toBe('[]');
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
    await expect(runProductionRuntime({...f,stage,region,command:'prepare',env:{GITHUB_RUN_ID:'222',GITHUB_RUN_ATTEMPT:'2',GITHUB_SHA:'a'.repeat(40)}})).rejects.toThrow('SyntheticPreflightFailure');
    expect(JSON.parse(f.writes[0].Value)).toMatchObject({sourceRunId:'222',sourceRunAttempt:2,sourceSha:'a'.repeat(40),nonce:plan.nonce});
    expect(f.processes).toEqual([]);
  });
  it('ignores a stale attempt or source revision before any recovery mutation',async()=>{
    const dir=await mkdtemp(join(tmpdir(),'mem9-runtime-event-'));
    try{
      const path=join(dir,'event.json'),repository='example/project';
      const plan={version:1,stage,region,account,nonce:'a'.repeat(32),sourceRunId:'42',sourceRunAttempt:2,sourceSha:'a'.repeat(40)};
      for(const patch of [{run_attempt:1},{id:43},{head_sha:'b'.repeat(40)}]){
        await writeFile(path,JSON.stringify({repository:{full_name:repository},workflow_run:{id:42,run_attempt:2,head_sha:plan.sourceSha,
          event:'workflow_dispatch',path:'.github/workflows/infra-ci.yml',head_repository:{full_name:repository},...patch}}),{mode:0o600});
        const f=fixture({plan});
        await runProductionRuntime({...f,stage,region,command:'recover',env:{MEM9_RUNTIME_RECOVERY_RUN_ID:'42',GITHUB_EVENT_NAME:'workflow_run',
          GITHUB_EVENT_PATH:path,GITHUB_REPOSITORY:repository}});
        expect(f.writes).toEqual([]);expect(f.processes).toEqual([]);
        expect(f.calls.every(name=>['GetCallerIdentityCommand','GetParametersCommand'].includes(name))).toBe(true);
      }
    }finally{await rm(dir,{recursive:true,force:true});}
  });
});
