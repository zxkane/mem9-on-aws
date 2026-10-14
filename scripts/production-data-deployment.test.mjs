import {it,expect,vi,afterEach} from 'vitest';
import {loadDeploymentDataRelease,retireDataRelease} from './lib/production-data-release-loader.mjs';
import {inspectDataRelease} from './lib/production-data-release.mjs';
import {retainedDeploymentEnvironment} from './run-production-runtime.mjs';
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
  const calls=[],versions=new Map([[base+'consolidation-runtime/data-release',2]]),clients={ssm:{send:async c=>{
    calls.push(c.input);
    if(c.constructor.name==='PutParameterCommand'){
      if(values.has(c.input.Name)&&!c.input.Overwrite)throw Error('ParameterAlreadyExists');
      versions.set(c.input.Name,(versions.get(c.input.Name)??0)+1);values.set(c.input.Name,JSON.parse(c.input.Value));return {Version:versions.get(c.input.Name)};
    }
    return {Parameters:c.input.Names.filter(name=>values.has(name)).map(Name=>({Name,Value:JSON.stringify(values.get(Name)),Type:'SecureString',Version:versions.get(Name)??2,ARN:'arn:aws:ssm:ap-northeast-1:123456789012:parameter'+Name})),InvalidParameters:c.input.Names.filter(name=>!values.has(name))};
  }}};
  return {data,options,selected,base,values,versions,calls,clients};
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
  expect(env.MEM9_RETAINED_DATA_RELEASE_HASH).toBe(f.selected.hash);expect(f.calls).toHaveLength(2);expect(captureBuild).toHaveBeenCalledOnce();
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

const retainedSelection=f=>({version:1,mode:'retained',controlTag:'mem9-aaaaaaa',dataTag:f.data.dataSourceTag,images:f.selected.images,dataReleaseHash:f.selected.hash,
  arm64Digests:Object.fromEntries(Object.entries(f.data.images).map(([n,v])=>[n,v.arm64Digest]))});
const context=f=>({stage:'prod',account:f.data.account,region:f.data.region});
it('retires only an expired authorization, inside the same protected parameter, and repeats idempotently',async()=>{
  const f=fixture(),name=f.base+'consolidation-runtime/data-release';
  await expect(retireDataRelease(f.clients,{...context(f),now:()=>f.data.expiresMs-1})).rejects.toThrow('DataReleaseAuthorizationActive');
  expect(f.values.get(name)).toEqual(f.data);
  expect(await retireDataRelease(f.clients,{...context(f),now:()=>f.data.expiresMs})).toEqual({retired:f.selected.hash,repeated:false});
  expect(f.values.get(name)).toEqual({version:1,kind:'retirement',...context(f),dataReleaseHash:f.selected.hash,parameterVersion:2,expiresMs:f.data.expiresMs,retiredMs:f.data.expiresMs});
  expect(f.versions.get(name)).toBe(3);
  expect(f.calls.filter(c=>c.Name).map(c=>[c.Name,c.Overwrite])).toEqual([[name,true]]);
  expect(await retireDataRelease(f.clients,{...context(f),now:()=>f.data.expiresMs})).toEqual({retired:f.selected.hash,repeated:true});
  expect(f.versions.get(name)).toBe(3);
  await expect(retireDataRelease(f.clients,{...context(f),stage:'pr-1',now:()=>f.data.expiresMs})).rejects.toThrow('ProductionDataReleaseMetadataInvalid');
  f.values.clear();await expect(retireDataRelease(f.clients,{...context(f),now:()=>f.data.expiresMs})).rejects.toThrow('ProductionDataReleaseMissing');
});
it('detects a concurrent descriptor write during retirement',async()=>{
  const f=fixture(),name=f.base+'consolidation-runtime/data-release',send=f.clients.ssm.send;
  f.clients.ssm.send=async c=>{
    if(c.constructor.name==='PutParameterCommand'){await send(c);f.versions.set(name,f.versions.get(name)+1);f.values.set(name,{...f.data,authorizationId:'f'.repeat(32)});return {Version:3};}
    return send(c);
  };
  await expect(retireDataRelease(f.clients,{...context(f),now:()=>f.data.expiresMs})).rejects.toThrow('DataReleaseRetirementConflict');
});
it('returns a retained selection to tag images only after retiring its exact release',async()=>{
  const f=fixture(),name=f.base+'consolidation-runtime/data-release';
  f.values.set(f.base+'ecs/image-selection',retainedSelection(f));
  f.values.set(f.base+'consolidation-runtime/operator-manifest',{version:2,stage:'prod',account:f.data.account,region:f.data.region,dataReleaseHash:f.selected.hash});
  const record={version:1,kind:'retirement',...context(f),dataReleaseHash:f.selected.hash,parameterVersion:1,expiresMs:f.data.expiresMs,retiredMs:f.data.expiresMs};
  f.values.set(name,record);
  const options={...f.options,now:f.data.expiresMs};
  expect(await loadDeploymentDataRelease(f.clients,options)).toBeUndefined();
  await expect(loadDeploymentDataRelease(f.clients,{...options,env:{MEM9_RETAINED_DATA_RELEASE_HASH:f.selected.hash}})).rejects.toThrow('ProductionDataReleaseMissing');
  f.values.set(name,{...record,dataReleaseHash:h('0')});
  await expect(loadDeploymentDataRelease(f.clients,options)).rejects.toThrow('ProductionDataReleaseMissing');
  f.values.set(name,record);f.versions.set(name,4);expect(await loadDeploymentDataRelease(f.clients,options)).toBeUndefined();
  f.versions.set(name,2);
  for(const forged of [{...record,parameterVersion:2},{...record,retiredMs:record.expiresMs-1},{...record,stage:'pr-1'},{...record,extra:true}]){
    f.values.set(name,forged);await expect(loadDeploymentDataRelease(f.clients,options)).rejects.toThrow('ProductionDataReleaseMetadataInvalid');
  }
  f.values.set(name,record);
  expect(await loadDeploymentDataRelease(f.clients,{...options,now:record.retiredMs-1000})).toBeUndefined();
  await expect(loadDeploymentDataRelease(f.clients,{...options,now:record.retiredMs-300001})).rejects.toThrow('ProductionDataReleaseMetadataInvalid');
  f.values.delete(name);await expect(loadDeploymentDataRelease(f.clients,options)).rejects.toThrow('ProductionDataReleaseMissing');
  // Both retained selectors must name the retired release; one match is not enough.
  f.values.set(name,record);
  f.values.set(f.base+'consolidation-runtime/operator-manifest',{version:2,stage:'prod',account:f.data.account,region:f.data.region,dataReleaseHash:h('0')});
  await expect(loadDeploymentDataRelease(f.clients,options)).rejects.toThrow('ProductionDataReleaseMissing');
  f.values.set(f.base+'consolidation-runtime/operator-manifest',{version:1,stage:'prod',account:f.data.account,region:f.data.region});
  expect(await loadDeploymentDataRelease(f.clients,options)).toBeUndefined();
  f.values.set(f.base+'ecs/image-selection',{...retainedSelection(f),dataReleaseHash:h('0')});
  await expect(loadDeploymentDataRelease(f.clients,options)).rejects.toThrow('ProductionDataReleaseMissing');
});
it('accepts a retried overwrite of the same retirement record',async()=>{
  const f=fixture(),name=f.base+'consolidation-runtime/data-release',send=f.clients.ssm.send;
  f.clients.ssm.send=async c=>{if(c.constructor.name==='PutParameterCommand'){await send(c);return send(c);}return send(c);};
  expect(await retireDataRelease(f.clients,{...context(f),now:()=>f.data.expiresMs})).toEqual({retired:f.selected.hash,repeated:false});
  expect(f.versions.get(name)).toBe(4);
  expect(await retireDataRelease(f.clients,{...context(f),now:()=>f.data.expiresMs})).toEqual({retired:f.selected.hash,repeated:true});
});
