import {describe,it,expect,vi,afterEach} from 'vitest';
const out=(value:any):any=>({value,apply(fn:any){const next=fn(value);return next?.apply?next:out(next);}});
const unwrap=(value:any):any=>value?.apply?unwrap(value.value):Array.isArray(value)?value.map(unwrap):value&&typeof value==='object'?Object.fromEntries(Object.entries(value).map(([k,v])=>[k,unwrap(v)])):value;
vi.mock('./ecr',()=>({accountId:()=>out('123456789012'),applicationRegion:()=>out('ap-northeast-1'),
  pinnedProductionImage:(name:string)=>out('123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/'+name+'@sha256:'+'a'.repeat(64))}));
function setup(stage='prod',enabled='0'){
  const resources:any[]=[];vi.stubGlobal('$app',{stage});
  vi.stubEnv('MEM9_IMAGE_TAG','mem9-aaaaaaa');
  vi.stubGlobal('$jsonStringify',(value:any)=>out(JSON.stringify(unwrap(value))));
  vi.stubGlobal('$interpolate',(parts:TemplateStringsArray,...values:any[])=>out(parts.reduce((result,p,i)=>result+p+(i<values.length?unwrap(values[i]):''),'')));
  vi.stubGlobal('random',{RandomId:class{hex=out('a'.repeat(64));constructor(name:string,args:any){resources.push({kind:'generation',name,args});}},
    RandomPassword:class{result;constructor(name:string,args:any){this.result=out(name.padEnd(args.length,'x'));resources.push({kind:'password',name,args});}}});
  vi.stubGlobal('sst',{Secret:class{value;constructor(name:string,fallback:string){this.value=out(name==='ProductionConsolidationAdmission'?'unverified':enabled);resources.push({kind:'secret',name,fallback});}}});
  vi.stubGlobal('aws',{ssm:{Parameter:class{arn;constructor(name:string,args:any){this.arn=out('arn:aws:ssm:ap-northeast-1:123456789012:parameter'+args.name);resources.push({kind:'parameter',name,args});}}}});
  return {resources,identity:{tenantSecretArn:out('tenant-secret'),tenantId:out('synthetic-tenant-value')},db:{database:out('mem9')}};
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
});
