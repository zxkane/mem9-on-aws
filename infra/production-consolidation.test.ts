import {describe,it,expect,vi,afterEach} from 'vitest';
const out=(value:any):any=>({value,apply(fn:any){const next=fn(value);return next?.apply?next:out(next);}});
const unwrap=(value:any):any=>value?.apply?unwrap(value.value):Array.isArray(value)?value.map(unwrap):value&&typeof value==='object'?Object.fromEntries(Object.entries(value).map(([k,v])=>[k,unwrap(v)])):value;
vi.mock('./ecr',()=>({accountId:()=>out('123456789012'),applicationRegion:()=>out('ap-northeast-1'),
  selectedDataSourceTag:vi.fn((tag:string)=>tag),selectedDataRelease:vi.fn(()=>undefined),
  pinnedProductionImage:(name:string)=>out('123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/'+name+'@sha256:'+'a'.repeat(64))}));
vi.mock('./vpc',()=>({resolveVpc:()=>({privateSubnetIds:out(['subnet-abcd'])})}));
function setup(stage='prod',enabled='0',admission='unverified'){
  const resources:any[]=[];vi.stubGlobal('$app',{stage});
  vi.stubEnv('MEM9_IMAGE_TAG','mem9-aaaaaaa');
  vi.stubGlobal('$jsonStringify',(value:any)=>out(JSON.stringify(unwrap(value))));
  vi.stubGlobal('$interpolate',(parts:TemplateStringsArray,...values:any[])=>out(parts.reduce((result,p,i)=>result+p+(i<values.length?unwrap(values[i]):''),'')));
  vi.stubGlobal('random',{RandomId:class{hex=out('a'.repeat(64));constructor(name:string,args:any){resources.push({kind:'generation',name,args});}},
    RandomPassword:class{result;constructor(name:string,args:any){this.result=out(name.padEnd(args.length,'x'));resources.push({kind:'password',name,args});}}});
  vi.stubGlobal('sst',{Secret:class{value;constructor(name:string,fallback:string){this.value=out(name==='ProductionConsolidationAdmission'?admission:enabled);resources.push({kind:'secret',name,fallback});}},
    aws:{Task:class{taskDefinition;constructor(name:string,args:any){
      this.taskDefinition=out('arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-on-aws-prod-fixture-'+name+':1');
      const taskRole:any={},executionRole:any={},definition:any={};
      args.transform.taskRole(taskRole);args.transform.executionRole(executionRole);args.transform.taskDefinition(definition);
      resources.push({kind:'task',name,args,taskRole,executionRole,definition});
    }}}});
  vi.stubGlobal('aws',{ssm:{Parameter:class{arn;constructor(name:string,args:any){this.arn=out('arn:aws:ssm:ap-northeast-1:123456789012:parameter'+args.name);resources.push({kind:'parameter',name,args});}}}});
  return {resources,identity:{tenantSecretArn:out('tenant-secret'),tenantId:out('synthetic-tenant-value')},
    db:{database:out('mem9'),host:out('database.example.com'),port:out(5432),taskSecurityGroupId:out('sg-abcd')}};
}
afterEach(()=>{vi.unstubAllGlobals();vi.unstubAllEnvs();vi.resetModules();});
describe('production continuous-consolidation configuration',()=>{
  it.each([undefined,'prepare','paused','ready'])('creates no workers before active runtime: %s',async mode=>{
    const f=setup();const {productionConsolidationConfig}=await import('./production-consolidation');
    expect(productionConsolidationConfig(mode?{mode} as any:undefined,f.identity as any,f.db as any)).toBeUndefined();expect(f.resources).toEqual([]);
  });
  it('never provisions production credentials in a preview',async()=>{
    const f=setup('pr-7');const {productionConsolidationConfig}=await import('./production-consolidation');
    expect(productionConsolidationConfig({mode:'active'} as any,f.identity as any,f.db as any)).toBeUndefined();expect(f.resources).toEqual([]);
  });
  it('defaults off and separates worker credentials while reusing tenant and targets',async()=>{
    const f=setup();const {productionConsolidationConfig}=await import('./production-consolidation');
    const cfg=productionConsolidationConfig({mode:'active'} as any,f.identity as any,f.db as any)!;
    expect(unwrap(cfg.enabled)).toBe(false);expect(unwrap(cfg.database)).toBe('mem9');
    expect(cfg.executionEnabled).toBe(true);expect(unwrap(cfg.admission)).toBe('unverified');
    expect(unwrap(cfg.arns.tenant)).toMatch(/\/consolidation-runtime\/tenant$/);expect(unwrap(cfg.arns.targets)).toMatch(/\/maintenance\/targets$/);
    expect(unwrap(f.resources.find(r=>r.name==='ProductionExecutorTenant').args.value)).toBe('synthetic-tenant-value');
    expect(unwrap(cfg.arns.planner)).not.toBe(unwrap(cfg.arns.executor));
    expect(f.resources.filter(r=>r.kind==='parameter').every(r=>r.args.type==='SecureString')).toBe(true);
    expect(f.resources.filter(r=>r.kind==='secret')).toEqual([{kind:'secret',name:'ProductionConsolidationEnabled',fallback:'0'},
      {kind:'secret',name:'ProductionConsolidationAdmission',fallback:'unverified'}]);
  });
  it('requires an exact persistent opt-in value',async()=>{
    const f=setup('prod','true');const {productionConsolidationConfig}=await import('./production-consolidation');
    expect(()=>productionConsolidationConfig({mode:'active'} as any,f.identity as any,f.db as any)).toThrow('InvalidProductionConsolidationOptIn');
  });
  it('binds enabled scheduling to a valid seed and immutable release artifact',async()=>{
    const f=setup('prod','1','b'.repeat(64));const {productionConsolidationConfig}=await import('./production-consolidation');
    const cfg=productionConsolidationConfig({mode:'active'} as any,f.identity as any,f.db as any)!;
    expect(unwrap(cfg.enabled)).toBe(true);expect(unwrap(cfg.admission)).toMatch(/^[a-f0-9]{64}$/);expect(unwrap(cfg.admission)).not.toBe('b'.repeat(64));
  });
  it('keeps current control identity separate from a retained data admission',async()=>{
    const f=setup('prod','1','b'.repeat(64)),ecr=await import('./ecr');
    vi.mocked(ecr.selectedDataSourceTag).mockReturnValue(out('mem9-bbbbbbb'));
    vi.mocked(ecr.selectedDataRelease).mockReturnValue(out({hash:'c'.repeat(64),data:{expiresMs:1800000600000}}));
    const {productionConsolidationConfig}=await import('./production-consolidation');
    const cfg=productionConsolidationConfig({mode:'active'} as any,f.identity as any,f.db as any)!;
    expect(cfg.controlSourceTag).toBe('mem9-aaaaaaa');expect(unwrap(cfg.sourceTag)).toBe('mem9-bbbbbbb');
    const {productionArtifactAdmission}=await import('../scripts/lib/production-artifacts.mjs');
    expect(unwrap(cfg.admission)).toBe(productionArtifactAdmission('b'.repeat(64),'mem9-bbbbbbb',unwrap(cfg.image)));
  });
  it.each(['1','0'])('rejects an invalid persisted admission for enabled=%s',async enabled=>{
    const f=setup('prod',enabled,'invalid');const {productionConsolidationConfig}=await import('./production-consolidation');
    expect(()=>productionConsolidationConfig({mode:'active'} as any,f.identity as any,f.db as any)).toThrow('InvalidProductionConsolidationAdmission');
  });
  it('isolates promotion report fragments from emergency control and provisioning',async()=>{
    const f=setup();const {productionConsolidationConfig,productionConsolidationOperators}=await import('./production-consolidation');
    const runtime={mode:'active',administratorArn:out('arn:aws:ssm:ap-northeast-1:123456789012:parameter/mem9-on-aws/prod/runtime/schema-administrator-credential')};
    const cfg=productionConsolidationConfig(runtime as any,f.identity as any,f.db as any)!;
    const ecs={clusterName:out('mem9-on-aws-prod-fixture'),cluster:{nodes:{cluster:{arn:out('arn:aws:ecs:ap-northeast-1:123456789012:cluster/mem9-on-aws-prod-fixture')}}}};
    productionConsolidationOperators(ecs as any,f.db as any,runtime as any,cfg);
    const tasks=f.resources.filter(r=>r.kind==='task');expect(tasks).toHaveLength(3);
    expect(Object.keys(tasks.find(t=>t.name==='ControlMem9Bootstrap').args.ssm)).toEqual(['MEM9_DB_SECRET']);
    expect(Object.keys(tasks.find(t=>t.name==='ProdMem9Bootstrap').args.ssm).sort()).toEqual(['MEM9_DB_SECRET','MEM9_EXECUTOR_DB_SECRET','MEM9_PLANNER_DB_SECRET','MEM9_WORKER_TARGETS']);
    expect(Object.keys(tasks.find(t=>t.name==='PromoteMem9Bootstrap').args.ssm).sort()).toEqual(['MEM9_CANARY_REPORT_0','MEM9_CANARY_REPORT_1','MEM9_CANARY_REPORT_2','MEM9_CANARY_REPORT_3','MEM9_DB_SECRET']);
    for(const task of tasks){
      expect(task.args.permissions).toEqual([]);expect(unwrap(task.args.image)).toMatch(/@sha256:[a-f0-9]{64}$/);
      expect(JSON.parse(unwrap(task.taskRole.assumeRolePolicy)).Statement[0].Principal).toEqual({Service:'ecs-tasks.amazonaws.com'});
      const policy=JSON.parse(unwrap(task.executionRole.inlinePolicies[0].policy));
      expect(policy.Statement[0].Action).toEqual(['ssm:GetParameters']);
      expect(policy.Statement[0].Resource.sort()).toEqual(Object.values(unwrap(task.args.ssm)).sort());
      expect(task.definition.tags).toMatchObject({Project:'mem9-on-aws',Stage:'prod'});
    }
    expect(()=>productionConsolidationOperators(ecs as any,f.db as any,{...runtime,mode:'prepare'} as any,cfg)).toThrow('ProductionWorkerOperatorRequiresRuntime');
  });
});
