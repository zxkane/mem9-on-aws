import {it,expect,vi,afterEach} from 'vitest';
import {loadDeploymentDataRelease} from './lib/production-data-release-loader.mjs';
import {inspectDataRelease} from './lib/production-data-release.mjs';
import {retainedDeploymentEnvironment} from './run-production-runtime.mjs';
import {imageTransitionFixture,imageTransitionServingFixture} from './production-image-transition.fixture.mjs';
import {buildImageTransitionProof,imageTransitionContextBindings} from './lib/production-image-transition-proof.mjs';
const now=1800000000000,h=c=>c.repeat(64);
afterEach(()=>vi.restoreAllMocks());
function fixture(){
  const data={version:1,stage:'prod',account:'123456789012',region:'ap-northeast-1',controlSourceTree:'a'.repeat(40),dataRevision:'b'.repeat(40),dataSourceTree:'c'.repeat(40),dataSourceTag:'mem9-bbbbbbb',
    images:Object.fromEntries(['llm-proxy','mnemo-server','qwen3-embed'].map((name,i)=>[name,{rootDigest:'sha256:'+h(String(i+1)),arm64Digest:'sha256:'+h(String(i+4))}])),
    parentProofHash:h('1'),backendBindingHash:h('2'),runtimeNonce:'d'.repeat(32),generation:h('3'),targetsHash:h('4'),schemaDigest:h('5'),operatorDigest:h('6'),
    buildInputsHash:h('7'),securityEvidenceHash:h('8'),policyHash:h('9'),authorizationId:'e'.repeat(32),issuedMs:now-1000,expiresMs:now+60000};
  const options={stage:data.stage,account:data.account,region:data.region,controlSourceTree:data.controlSourceTree,now,
    runtime:{stage:'prod',phase:'complete',status:'running',nonce:data.runtimeNonce,schemaDigest:data.schemaDigest,operatorDigest:data.operatorDigest}};
  const selected=inspectDataRelease(data,{stage:data.stage,account:data.account,region:data.region,controlSourceTree:data.controlSourceTree}),base='/mem9-on-aws/prod/',values=new Map([[base+'consolidation-runtime/data-release',data]]);
  const calls=[],clients={ssm:{send:async c=>{calls.push(c.input);return {Parameters:c.input.Names.filter(name=>values.has(name)).map(Name=>({Name,Value:JSON.stringify(values.get(Name)),Type:'SecureString',Version:2,ARN:'arn:aws:ssm:ap-northeast-1:123456789012:parameter'+Name})),InvalidParameters:c.input.Names.filter(name=>!values.has(name))};}}};
  return {data,options,selected,base,values,calls,clients};
}
it('loads the fixed protected snapshot and preserves its observed version',async()=>{
  const f=fixture();expect((await loadDeploymentDataRelease(f.clients,f.options)).parameterVersion).toBe(2);
  expect(f.calls[0].Names).toEqual([f.base+'consolidation-runtime/data-release',f.base+'ecs/image-selection',f.base+'consolidation-runtime/operator-manifest']);
});
it('allows an explicitly absent initial selector but never falls back after retention',async()=>{
  const f=fixture();f.values.clear();expect(await loadDeploymentDataRelease(f.clients,f.options)).toBeUndefined();
  f.values.set(f.base+'ecs/image-selection',{version:1,mode:'retained',controlTag:'mem9-aaaaaaa',dataTag:f.data.dataSourceTag,images:f.selected.images,dataReleaseHash:f.selected.hash,arm64Digests:Object.fromEntries(Object.entries(f.data.images).map(([n,v])=>[n,v.arm64Digest]))});
  await expect(loadDeploymentDataRelease(f.clients,f.options)).rejects.toThrow('ProductionDataReleaseMissing');
});
it('rejects environment-only descriptors, expired authorizations and runtime drift',async()=>{
  const f=fixture();f.values.clear();await expect(loadDeploymentDataRelease(f.clients,{...f.options,env:{MEM9_RETAINED_DATA_RELEASE:JSON.stringify(f.data)}})).rejects.toThrow('ProductionDataReleaseMissing');
  f.values.set(f.base+'consolidation-runtime/data-release',f.data);
  await expect(loadDeploymentDataRelease(f.clients,{...f.options,env:{MEM9_RETAINED_DATA_RELEASE_HASH:h('0')}})).rejects.toThrow('ProductionDataReleaseOverrideConflict');
  await expect(loadDeploymentDataRelease(f.clients,{...f.options,now:f.data.expiresMs})).rejects.toThrow('DataReleaseAuthorizationExpired');
  await expect(loadDeploymentDataRelease(f.clients,{...f.options,runtime:{...f.options.runtime,nonce:'f'.repeat(32)}})).rejects.toThrow('DataReleaseBindingMismatch');
});
it('requires complete, nonduplicated, same-account SSM responses',async()=>{
  for(const alter of [r=>{r.InvalidParameters.pop();},r=>{r.InvalidParameters.push(r.Parameters[0].Name);},r=>{r.Parameters[0].ARN=r.Parameters[0].ARN.replace('123456789012','0'.repeat(12));},r=>{r.Parameters[0].Type='String';}]){
    const f=fixture(),send=f.clients.ssm.send;f.clients.ssm.send=async c=>{const r=await send(c);alter(r);return r;};
    await expect(loadDeploymentDataRelease(f.clients,f.options)).rejects.toThrow('ProductionDataReleaseMetadataInvalid');
  }
});
it('exports a snapshot only after build verification and an unchanged protected readback',async()=>{
  vi.spyOn(Date,'now').mockReturnValue(now);const f=fixture();
  const captureBuild=vi.fn(async()=>({buildInputsHash:f.data.buildInputsHash}));
  const env=await retainedDeploymentEnvironment(f.clients,{...f.options,controlRevision:'a'.repeat(40)},{captureBuild});
  expect(env.MEM9_RETAINED_DATA_RELEASE_HASH).toBe(f.selected.hash);expect(env.MEM9_RETAINED_DATA_RELEASE_VERSION).toBe('2');expect(f.calls).toHaveLength(2);expect(captureBuild).toHaveBeenCalledOnce();
  await expect(retainedDeploymentEnvironment(f.clients,f.options,{captureBuild:async()=>({buildInputsHash:h('0')})})).rejects.toThrow('DataReleaseBuildEvidenceMismatch');
});
it('rejects authorization revocation or expiry during predeployment evidence capture',async()=>{
  const clock=vi.spyOn(Date,'now').mockReturnValue(now);
  for(const change of ['delete','expire','replace']){
    clock.mockReturnValue(now);const f=fixture();
    const captureBuild=async()=>{
      if(change==='delete')f.values.clear();
      if(change==='expire')clock.mockReturnValue(f.data.expiresMs);
      if(change==='replace')f.data.authorizationId='f'.repeat(32);
      return {buildInputsHash:f.data.buildInputsHash};
    };
    await expect(retainedDeploymentEnvironment(f.clients,f.options,{captureBuild})).rejects.toThrow();
  }
});

async function imageDeploymentFixture(){
 const f=await imageTransitionFixture(),built=await buildImageTransitionProof(f.input,f),s=imageTransitionServingFixture(f,built),b=imageTransitionContextBindings(s.authorizationContext),data=s.data;
 const base='/mem9-on-aws/prod/',name=base+'consolidation-runtime/data-release';
 const selector={version:1,mode:'retained',controlTag:b.previousControlTag,dataTag:b.previousSelection.dataSourceTag,
  images:b.previousSelection.images,arm64Digests:b.previousSelection.arm64Digests,dataReleaseHash:b.previousSelection.dataReleaseHash};
 const operator={version:2,stage:'prod',account:data.account,region:data.region,generation:data.generation,
  sourceTag:selector.dataTag,workerImage:selector.images['llm-proxy'],dataReleaseParameter:name,dataReleaseHash:selector.dataReleaseHash};
 const values=new Map([[name,data],[base+'ecs/image-selection',selector],[base+'consolidation-runtime/operator-manifest',operator]]);
 const clients={ssm:{send:async command=>({Parameters:command.input.Names.filter(n=>values.has(n)).map(Name=>({Name,Type:'SecureString',Version:2,ARN:`arn:aws:ssm:${data.region}:${data.account}:parameter${Name}`,Value:JSON.stringify(values.get(Name))})),InvalidParameters:command.input.Names.filter(n=>!values.has(n))})}};
 const options={stage:'prod',account:data.account,region:data.region,controlRevision:s.current.revision,controlSourceTree:data.controlSourceTree,imageTransition:s.authorizationContext,now:f.now,
  runtime:{stage:'prod',phase:'complete',status:'running',nonce:data.runtimeNonce,schemaDigest:data.schemaDigest,operatorDigest:data.operatorDigest}};
 return {f,s,b,data,base,name,selector,operator,values,clients,options};
}
it('allows the exact authorized target while the whole predecessor selection still exists',async()=>{
 const f=await imageDeploymentFixture(),r=await loadDeploymentDataRelease(f.clients,f.options);
 expect(r.data.version).toBe(2);expect(r.currentSelection.dataReleaseHash).toBe(f.b.previousSelection.dataReleaseHash);expect(r.images).toEqual(f.s.current.dataRelease?Object.fromEntries(Object.entries(f.data.images).map(([n,v])=>[n,`${f.data.account}.dkr.ecr.${f.data.region}.amazonaws.com/mem9-on-aws/${n}@${v.rootDigest}`])):{});
});
it('rejects an image-target deployment without an authenticated proof/review context',async()=>{
 const f=await imageDeploymentFixture();await expect(loadDeploymentDataRelease(f.clients,{...f.options,imageTransition:undefined})).rejects.toThrow('ImageTransitionProofRequired');
 await expect(loadDeploymentDataRelease(f.clients,{...f.options,imageTransition:{...f.s.authorizationContext}})).rejects.toThrow();
});
it('accepts exact target metadata after deployment without treating it as serving proof',async()=>{
 const f=await imageDeploymentFixture(),selected=inspectDataRelease(f.data,{stage:'prod',account:f.data.account,region:f.data.region,controlSourceTree:f.data.controlSourceTree});
 Object.assign(f.selector,{controlTag:'mem9-'+f.options.controlRevision.slice(0,7),dataTag:f.data.dataSourceTag,images:selected.images,dataReleaseHash:selected.hash,arm64Digests:Object.fromEntries(Object.entries(f.data.images).map(([n,v])=>[n,v.arm64Digest]))});
 Object.assign(f.operator,{version:3,sourceTag:f.data.dataSourceTag,workerImage:selected.images['llm-proxy'],dataReleaseHash:selected.hash,dataReleaseParameterVersion:2});
 expect((await loadDeploymentDataRelease(f.clients,f.options)).hash).toBe(selected.hash);
});
it.each(['mixed-images','missing-selector','wrong-operator-hash','wrong-control-tag'])('rejects ambiguous image-transition metadata: %s',async kind=>{
 const f=await imageDeploymentFixture();
 if(kind==='mixed-images')f.selector.images={...f.selector.images,'mnemo-server':f.s.current.backendTask.containers.find(c=>c.name==='mnemo-server').image};
 if(kind==='missing-selector')f.values.delete(f.base+'ecs/image-selection');
 if(kind==='wrong-operator-hash')f.operator.dataReleaseHash=h('f');
 if(kind==='wrong-control-tag')f.selector.controlTag='mem9-0000000';
 await expect(loadDeploymentDataRelease(f.clients,f.options)).rejects.toThrow('ProductionDataReleaseMetadataInvalid');
});
