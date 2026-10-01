import {describe,it,expect,vi} from 'vitest';

vi.mock('./lib/production-runtime-aws.mjs',async importOriginal=>({...await importOriginal(),
  captureProductionService:async()=>({stage:'pr-7',region:'ap-northeast-1',account:'123456789012',host:'db.example.com',database:'mem9',
    clusterArn:'synthetic-cluster',fallbackImages:{synthetic:'image'},definition:{largeSyntheticDescriptor:'x'.repeat(10000)}}),
  inventoryLegacyRoles:async()=>({definitions:['synthetic'],roles:['role'],families:['family'],clusters:['cluster']}),
  auditAdditionalCredentialReaders:async()=>{},
}));
vi.mock('./lib/production-runtime-backup.mjs',async importOriginal=>({...await importOriginal(),
  inspectProductionDatabase:async()=>({databaseClusterId:'synthetic',databaseResourceId:'synthetic-id',masterUsername:'original',engineVersion:'17.4'}),
  ensureProductionSnapshot:async()=>{throw Error('SyntheticStopAfterPlan');},
}));
import {runProductionRuntime,cutoverDeploymentEnvironment} from './run-production-runtime.mjs';

describe('fresh runtime preparation plan',()=>{
  it('preserves the deployed namespace targets when a manual rehearsal has no SST secret override',async()=>{
    const target='60000000-0000-4000-8000-000000000001',path='/mem9-on-aws/pr-7/maintenance/targets',calls=[];
    const clients={ssm:{send:async command=>{calls.push(command.input);return {Parameters:[{Name:path,Value:JSON.stringify([target])}]};}}};
    const env={MEM9_CONSOLIDATION_SCHEDULE_ENABLED:'1',UNRELATED:'unchanged'};
    expect(await cutoverDeploymentEnvironment(clients,'pr-7',env)).toEqual({...env,SST_SECRET_MaintenanceNamespaceIds:JSON.stringify([target])});
    expect(calls).toEqual([{Names:[path],WithDecryption:true}]);
    await expect(cutoverDeploymentEnvironment(clients,'pr-7',{...env,SST_SECRET_MaintenanceNamespaceIds:'[]'})).rejects.toThrow('CutoverMaintenanceTargetsConflict');
  });
  it.each(['null','["foreign"]','[]','["60000000-0000-4000-8000-000000000001","60000000-0000-4000-8000-000000000001"]'])('rejects invalid or empty enabled namespace targets: %s',async value=>{
    const clients={ssm:{send:async command=>({Parameters:[{Name:command.input.Names[0],Value:value}]})}};
    await expect(cutoverDeploymentEnvironment(clients,'prod',{MEM9_CONSOLIDATION_SCHEDULE_ENABLED:'1'})).rejects.toThrow();
  });
  it('allows missing targets only for a disabled schedule without an explicit override',async()=>{
    const clients={ssm:{send:async command=>({InvalidParameters:command.input.Names})}};
    await expect(cutoverDeploymentEnvironment(clients,'prod',{MEM9_CONSOLIDATION_SCHEDULE_ENABLED:'1'})).rejects.toThrow('CutoverMaintenanceTargetsMissing');
    expect((await cutoverDeploymentEnvironment(clients,'prod',{})).SST_SECRET_MaintenanceNamespaceIds).toBe('[]');
  });
  it('persists workflow attempt provenance and compact source metadata without the task descriptor',async()=>{
    const writes=[];
    const send=async command=>{
      if(command.constructor.name==='GetCallerIdentityCommand')return {Account:'123456789012'};
      if(command.constructor.name==='GetParametersCommand')return {InvalidParameters:command.input.Names};
      if(command.constructor.name==='PutParameterCommand'){writes.push(command.input);return {};}
      throw Error('UnexpectedCommand');
    };
    await expect(runProductionRuntime({clients:{ssm:{send},sts:{send}},stage:'pr-7',region:'ap-northeast-1',command:'prepare',
      env:{GITHUB_RUN_ID:'101',GITHUB_RUN_ATTEMPT:'2',GITHUB_SHA:'a'.repeat(40)}})).rejects.toThrow('SyntheticStopAfterPlan');
    expect(writes).toHaveLength(1);expect(Buffer.byteLength(writes[0].Value)).toBeLessThan(4096);
    const plan=JSON.parse(writes[0].Value);
    expect(plan).toMatchObject({sourceRunId:'101',sourceRunAttempt:2,sourceSha:'a'.repeat(40),host:'db.example.com'});
    expect(plan).not.toHaveProperty('definition');expect(writes[0].Value).not.toContain('largeSyntheticDescriptor');
  });
});
