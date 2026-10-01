import {describe,it,expect,vi,afterEach} from 'vitest';

const output=(value:any):any=>({value,apply(fn:any){const next=fn(value);return next?.apply?next:output(next);}});
const unwrap=(value:any):any=>value?.apply?unwrap(value.value):value;
function setup(digest='sha256:'+'a'.repeat(64)){
  const calls:any[]=[];vi.stubGlobal('$app',{stage:'prod'});vi.stubEnv('MEM9_ECR_NAMESPACE','mem9-on-aws');
  vi.stubGlobal('$interpolate',(parts:TemplateStringsArray,...values:any[])=>output(parts.reduce((s,p,i)=>s+p+(i<values.length?unwrap(values[i]):''),'')));
  vi.stubGlobal('aws',{getCallerIdentityOutput:()=>({accountId:output('123456789012')}),getRegionOutput:()=>({name:output('ap-northeast-1')}),
    ecr:{getImageOutput:(args:any)=>{calls.push(args);return {imageDigest:output(digest)};}}});return calls;
}
afterEach(()=>{vi.unstubAllGlobals();vi.unstubAllEnvs();vi.resetModules();});
describe('production ECR artifact pinning',()=>{
  it('resolves the explicit release tag in the application account and region and emits a digest URI',async()=>{
    const calls=setup(),{pinnedProductionImage}=await import('./ecr');
    expect(unwrap(pinnedProductionImage('llm-proxy','mem9-abcdef0'))).toBe('123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/llm-proxy@sha256:'+'a'.repeat(64));
    expect(calls).toHaveLength(1);expect(calls[0].imageTag).toBe('mem9-abcdef0');expect(calls[0].repositoryName).toBe('mem9-on-aws/llm-proxy');
    expect(unwrap(calls[0].registryId)).toBe('123456789012');expect(unwrap(calls[0].region)).toBe('ap-northeast-1');
  });
  it('rejects unversioned tags and foreign namespaces before registry access',async()=>{
    const calls=setup(),{pinnedProductionImage}=await import('./ecr');
    expect(()=>pinnedProductionImage('bootstrap','latest')).toThrow('ProductionImageRevisionRequired');
    vi.stubEnv('MEM9_ECR_NAMESPACE','foreign');expect(()=>pinnedProductionImage('bootstrap','mem9-abcdef0')).toThrow('ProductionImageRevisionRequired');expect(calls).toEqual([]);
  });
  it('rejects a registry response without a usable immutable digest',async()=>{
    setup('invalid');const {pinnedProductionImage}=await import('./ecr');
    expect(()=>pinnedProductionImage('bootstrap','mem9-abcdef0')).toThrow('ProductionImageDigestRequired');
  });
});
