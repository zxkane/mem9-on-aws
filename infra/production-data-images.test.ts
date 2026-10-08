import {afterEach,it,expect,vi} from 'vitest';
import {inspectDataRelease} from '../scripts/lib/production-data-release.mjs';
const canaryEvidenceHash=(data:any)=>inspectDataRelease(data,{stage:data.stage,account:data.account,region:data.region,controlSourceTree:data.controlSourceTree}).hash;
const tree='a'.repeat(40),now=1800000000000;
vi.mock('node:child_process',()=>({execFileSync:()=>tree+'\n'}));
const bundle=vi.hoisted(()=>({readImageDeploymentBundle:vi.fn(),restoreImageDeploymentBundle:vi.fn()}));
vi.mock('../scripts/lib/production-image-deployment-bundle.mjs',()=>bundle);
const out=(value:any):any=>({value,apply(fn:any){const next=value instanceof Promise?value.then(fn):fn(value);return next?.apply?next:out(next);}});
const unwrap=(v:any):any=>v instanceof Promise?v.then(unwrap):v?.apply?unwrap(v.value):v;
function setup(retained=true){
  vi.stubGlobal('$app',{stage:'prod'});vi.stubEnv('MEM9_PRODUCTION_RUNTIME_MODE','active');vi.spyOn(Date,'now').mockReturnValue(now);
  vi.stubGlobal('$interpolate',(parts:TemplateStringsArray,...values:any[])=>out(parts.reduce((s,p,i)=>s+p+(i<values.length?unwrap(values[i]):''),'')));
  const lookup=vi.fn((_args:Record<string,unknown>)=>({imageDigest:out('sha256:'+'9'.repeat(64))}));
  vi.stubGlobal('aws',{getCallerIdentityOutput:()=>({accountId:out('123456789012')}),getRegionOutput:()=>({name:out('ap-northeast-1')}),ecr:{getImageOutput:lookup},
    ssm:{getParameterOutput:({name}:any)=>out({name,arn:'arn:aws:ssm:ap-northeast-1:123456789012:parameter'+name,type:'SecureString',version:1,value:JSON.stringify(data)})}});
  const data={version:1,stage:'prod',account:'123456789012',region:'ap-northeast-1',controlSourceTree:tree,
    dataRevision:'b'.repeat(40),dataSourceTree:'c'.repeat(40),dataSourceTag:'mem9-bbbbbbb',
    images:Object.fromEntries(['llm-proxy','mnemo-server','qwen3-embed'].map((name,i)=>[name,{rootDigest:'sha256:'+String(i+1).repeat(64),arm64Digest:'sha256:'+String(i+4).repeat(64)}])),
    parentProofHash:'1'.repeat(64),backendBindingHash:'2'.repeat(64),runtimeNonce:'d'.repeat(32),generation:'3'.repeat(64),targetsHash:'4'.repeat(64),
    schemaDigest:'5'.repeat(64),operatorDigest:'6'.repeat(64),buildInputsHash:'7'.repeat(64),securityEvidenceHash:'8'.repeat(64),policyHash:'9'.repeat(64),
    authorizationId:'e'.repeat(32),issuedMs:now-1000,expiresMs:now+3600000};
  if(retained){vi.stubEnv('MEM9_RETAINED_DATA_RELEASE',JSON.stringify(data));vi.stubEnv('MEM9_RETAINED_DATA_RELEASE_HASH',canaryEvidenceHash(data));vi.stubEnv('MEM9_RETAINED_DATA_RELEASE_VERSION','1');}
  else{vi.stubEnv('MEM9_RETAINED_DATA_RELEASE','none');vi.stubEnv('MEM9_RETAINED_DATA_RELEASE_HASH','none');vi.stubEnv('MEM9_RETAINED_DATA_RELEASE_VERSION','0');}
  return {data,lookup};
}
afterEach(()=>{vi.restoreAllMocks();vi.resetAllMocks();vi.unstubAllGlobals();vi.unstubAllEnvs();vi.resetModules();});
it('selects exact data roots while bootstrap remains on the current control build',async()=>{
  const f=setup();const ecr=await import('./ecr');
  expect(await unwrap(ecr.workloadImage('mnemo-server','mem9-aaaaaaa'))).toBe('123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/mnemo-server@'+f.data.images['mnemo-server'].rootDigest);
  expect(await unwrap(ecr.pinnedProductionImage('llm-proxy','mem9-aaaaaaa'))).toContain('@'+f.data.images['llm-proxy'].rootDigest);
  expect(unwrap(ecr.pinnedProductionImage('bootstrap','mem9-aaaaaaa'))).toContain('@sha256:'+'9'.repeat(64));
  expect(f.lookup).toHaveBeenCalledTimes(1);expect(f.lookup.mock.calls[0][0]).toMatchObject({repositoryName:'mem9-on-aws/bootstrap',imageTag:'mem9-aaaaaaa'});
  expect(await unwrap(ecr.selectedDataSourceTag('mem9-aaaaaaa'))).toBe('mem9-bbbbbbb');
});
it('keeps ordinary image selection when no retention is configured',async()=>{
  setup(false);const ecr=await import('./ecr');
  expect(unwrap(ecr.workloadImage('mnemo-server','mem9-aaaaaaa'))).toBe('123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/mnemo-server:mem9-aaaaaaa');
  expect(ecr.selectedDataSourceTag('mem9-aaaaaaa')).toBe('mem9-aaaaaaa');
});
function imageTarget(){
 const f=setup();Object.assign(f.data,{version:2,transition:{version:1,kind:'image-security-upgrade',proofHash:'1'.repeat(64),predecessorHash:'2'.repeat(64),limitsHash:'59a5bf6d08f4e1a787d1f016a320c625fd43bb973bb924d6999427dfcfe71ced'}});
 vi.stubEnv('MEM9_RETAINED_DATA_RELEASE',JSON.stringify(f.data));vi.stubEnv('MEM9_RETAINED_DATA_RELEASE_HASH',canaryEvidenceHash(f.data));
 vi.stubEnv('MEM9_IMAGE_TRANSITION_BUNDLE_FILE','/private/fixture/bundle.local.json');vi.stubEnv('MEM9_IMAGE_TRANSITION_BUNDLE_HASH','3'.repeat(64));
 return f;
}
it('waits for current protected image authorization before selecting upgraded data images',async()=>{
 const f=imageTarget(),record={synthetic:true};bundle.readImageDeploymentBundle.mockResolvedValue(record);bundle.restoreImageDeploymentBundle.mockResolvedValue({});
 const ecr=await import('./ecr');expect(await unwrap(ecr.workloadImage('mnemo-server','mem9-aaaaaaa'))).toContain('@'+f.data.images['mnemo-server'].rootDigest);
 expect(bundle.restoreImageDeploymentBundle).toHaveBeenCalledWith(record,expect.objectContaining({parameter:expect.objectContaining({Version:1,Value:JSON.stringify(f.data)}),expected:expect.objectContaining({controlSourceTree:tree}),controlRevision:tree}));
});
it('rejects image selection when the archive bundle no longer matches protected authorization',async()=>{
 imageTarget();bundle.readImageDeploymentBundle.mockResolvedValue({});bundle.restoreImageDeploymentBundle.mockRejectedValue(Error('ImageDeploymentBundleInvalid'));
 const ecr=await import('./ecr');await expect(unwrap(ecr.workloadImage('mnemo-server','mem9-aaaaaaa'))).rejects.toThrow('ImageDeploymentBundleInvalid');
});
it('rejects a protected image target with no verified deployment bundle',async()=>{
 imageTarget();delete process.env.MEM9_IMAGE_TRANSITION_BUNDLE_FILE;const ecr=await import('./ecr');await expect(Promise.resolve().then(()=>unwrap(ecr.workloadImage('mnemo-server','mem9-aaaaaaa')))).rejects.toThrow('VerifiedImageTransitionRequired');
});
it('pins the image-transition bootstrap to the actual successful control build digest',async()=>{
 imageTarget();bundle.readImageDeploymentBundle.mockResolvedValue({});bundle.restoreImageDeploymentBundle.mockResolvedValue({});
 vi.stubEnv('MEM9_EXPECTED_BOOTSTRAP_DIGEST','sha256:'+'9'.repeat(64));const ecr=await import('./ecr');
 expect(await unwrap(ecr.workloadImage('bootstrap','mem9-aaaaaaa'))).toBe('123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/bootstrap@sha256:'+'9'.repeat(64));
});
it('cannot fall back to a tagged bootstrap when the image-transition build output is absent',async()=>{
 imageTarget();bundle.readImageDeploymentBundle.mockResolvedValue({});bundle.restoreImageDeploymentBundle.mockResolvedValue({});delete process.env.MEM9_EXPECTED_BOOTSTRAP_DIGEST;
 const ecr=await import('./ecr');await expect(unwrap(ecr.workloadImage('bootstrap','mem9-aaaaaaa'))).rejects.toThrow('VerifiedControlBuildRequired');
});
it.each(['0','2','missing'])('rejects a stale or absent expected parameter version: %s',async version=>{
 setup();if(version==='missing')delete process.env.MEM9_RETAINED_DATA_RELEASE_VERSION;else vi.stubEnv('MEM9_RETAINED_DATA_RELEASE_VERSION',version);
 const ecr=await import('./ecr');await expect(Promise.resolve().then(()=>unwrap(ecr.selectedDataRelease()))).rejects.toThrow();
});
it('rejects an internally consistent environment descriptor absent from protected storage',async()=>{
  const f=setup(),forged=structuredClone(f.data);forged.images['mnemo-server'].rootDigest='sha256:'+'f'.repeat(64);
  vi.stubEnv('MEM9_RETAINED_DATA_RELEASE',JSON.stringify(forged));vi.stubEnv('MEM9_RETAINED_DATA_RELEASE_HASH',canaryEvidenceHash(forged));
  const ecr=await import('./ecr');await expect(Promise.resolve().then(()=>unwrap(ecr.workloadImage('mnemo-server','mem9-aaaaaaa')))).rejects.toThrow('DataReleaseSelectionChanged');
});
it.each(['hash','expired','account','control','runtime'])('rejects retained %s drift instead of silently selecting a new image',async kind=>{
  const f=setup();
  if(kind==='hash')vi.stubEnv('MEM9_RETAINED_DATA_RELEASE_HASH','0'.repeat(64));
  if(kind==='expired')f.data.expiresMs=now;
  if(kind==='account')f.data.account='0'.repeat(12);
  if(kind==='control')f.data.controlSourceTree='f'.repeat(40);
  if(kind==='runtime')vi.stubEnv('MEM9_PRODUCTION_RUNTIME_MODE','prepare');
  if(['expired','account','control'].includes(kind)){vi.stubEnv('MEM9_RETAINED_DATA_RELEASE',JSON.stringify(f.data));vi.stubEnv('MEM9_RETAINED_DATA_RELEASE_HASH',canaryEvidenceHash(f.data));}
  const ecr=await import('./ecr');await expect(Promise.resolve().then(()=>unwrap(ecr.workloadImage('mnemo-server','mem9-aaaaaaa')))).rejects.toThrow();
});
