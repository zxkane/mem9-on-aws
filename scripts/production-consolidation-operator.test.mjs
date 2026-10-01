import {describe,it,expect} from 'vitest';
import {parseProductionConsolidationRequest,productionConsolidationConfig,canaryPolicy} from './production-consolidation-operator.mjs';
import {schemaAdministratorRole} from './lib/production-runtime-config.mjs';

const request=operation=>({operation,invocation:'a'.repeat(32),deadline:Date.now()+60000});
describe('production worker administration request boundary',()=>{
  it('uses the approved slow lossless-only twenty-row canary policy',()=>{
    expect(canaryPolicy()).toMatchObject({limits:{total:20,rewrite:20,delete:20,archive:0,mark:0},rate:0.05,burst:1});
  });
  it('permits bounded control operations without credentials in request data',()=>{
    expect(parseProductionConsolidationRequest(JSON.stringify(request('pause'))).operation).toBe('pause');
    expect(parseProductionConsolidationRequest(JSON.stringify({...request('promote'),dailyRows:6000,basisPoints:3500,canaryReportHash:'a'.repeat(64)})).dailyRows).toBe(6000);
    expect(()=>parseProductionConsolidationRequest(JSON.stringify({...request('promote'),dailyRows:6000,basisPoints:3500}))).toThrow('VerifiedProductionCanaryRequired');
  });
  it.each([{operation:'sql'},{invocation:'invalid'},{deadline:0},{password:'forbidden'},
    {operation:'promote',dailyRows:50001,basisPoints:10000},{dailyRows:20}])('rejects unsafe or unexpected input %o',patch=>{
    expect(()=>parseProductionConsolidationRequest(JSON.stringify({...request('pause'),...patch}))).toThrow();
  });
  it('keeps pause/status independent of worker credentials and acceptance availability',()=>{
    const env={MEM9_STAGE:'prod',MEM9_DB_HOST:'mem9-on-aws-prod-fixture.cluster-example.ap-northeast-1.'+['rds','amazonaws','com'].join('.'),
      AWS_REGION:'ap-northeast-1',MEM9_DB_NAME:'mem9',MEM9_DB_PORT:'5432',MEM9_WORKER_GENERATION:'a'.repeat(64),
      MEM9_DB_SECRET:JSON.stringify({username:schemaAdministratorRole('prod'),password:'synthetic-administrator'}),MEM9_PRODUCTION_WORKER_OPERATOR:'control'};
    const config=productionConsolidationConfig(env,request('pause'));
    expect(config.targets).toEqual([]);expect(config.acceptance).toEqual({});
    expect(()=>productionConsolidationConfig({...env,MEM9_STAGE:'pr-7'},request('pause'))).toThrow('InvalidProductionWorkerTarget');
    expect(()=>productionConsolidationConfig(env,request('prepare'))).toThrow();
    expect(()=>productionConsolidationConfig({...env,MEM9_DB_PORT:'NaN'},request('pause'))).toThrow();
  });
});
