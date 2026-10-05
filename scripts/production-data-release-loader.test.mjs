import {it,expect} from 'vitest';
import {loadWorkerDataRelease} from './lib/production-data-release-loader.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
const now=1800000000000,hex=n=>n.toString(16).padStart(64,'0');
function fixture(){
 const data={version:1,stage:'prod',account:'123456789012',region:'ap-northeast-1',controlSourceTree:'a'.repeat(40),dataRevision:'b'.repeat(40),dataSourceTree:'c'.repeat(40),dataSourceTag:'mem9-bbbbbbb',
  images:Object.fromEntries(['llm-proxy','mnemo-server','qwen3-embed'].map((name,i)=>[name,{rootDigest:'sha256:'+hex(i+1),arm64Digest:'sha256:'+hex(i+10)}])),
  parentProofHash:hex(20),backendBindingHash:hex(21),runtimeNonce:'d'.repeat(32),generation:hex(22),targetsHash:hex(23),schemaDigest:hex(24),operatorDigest:hex(25),buildInputsHash:hex(26),securityEvidenceHash:hex(27),policyHash:hex(28),authorizationId:'e'.repeat(32),issuedMs:now-1000,expiresMs:now+1000};
 const name='/mem9-on-aws/prod/consolidation-runtime/data-release',parameter={Name:name,Type:'SecureString',Version:1,Value:JSON.stringify(data)};
 const meta={version:2,stage:'prod',account:data.account,region:data.region,generation:data.generation,sourceTag:data.dataSourceTag,controlSourceTag:'mem9-aaaaaaa',dataReleaseHash:hash(data),dataReleaseParameter:name,
  workerImage:'123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/llm-proxy@'+data.images['llm-proxy'].rootDigest};
 const calls=[],clients={ssm:{send:async command=>{calls.push(command.input);return {Parameters:[parameter]};}}};
 return {data,meta,parameter,calls,clients,options:{controlRevision:'a'.repeat(40),controlSourceTree:data.controlSourceTree,now}};
}
it('loads only the fixed protected data record and binds it to the current control release',async()=>{
 const f=fixture(),selected=await loadWorkerDataRelease(f.clients,f.meta,{...f.options,mode:'admission'});
 expect(selected.data.dataSourceTag).toBe('mem9-bbbbbbb');expect(selected.parameterVersion).toBe(1);expect(f.calls[0].WithDecryption).toBe(true);
});
it('keeps historical inspection possible while expiry prevents new admission',async()=>{
 const f=fixture();expect(await loadWorkerDataRelease(f.clients,f.meta,{...f.options,now:f.data.expiresMs})).toBeDefined();
 await expect(loadWorkerDataRelease(f.clients,f.meta,{...f.options,mode:'admission',now:f.data.expiresMs})).rejects.toThrow('DataReleaseAuthorizationExpired');
});
it('rejects swapped references, control identity, hash, generation and selected images',async()=>{
 for(const patch of [{dataReleaseParameter:'/foreign'},{controlSourceTag:'mem9-bbbbbbb'},{dataReleaseHash:hex(90)},{generation:hex(90)},{workerImage:'foreign'}]){
  const f=fixture();await expect(loadWorkerDataRelease(f.clients,{...f.meta,...patch},f.options)).rejects.toThrow();
 }
});
it('preserves the legacy single-release path without reading another parameter',async()=>{
 const f=fixture();expect(await loadWorkerDataRelease(f.clients,{version:1,sourceTag:'mem9-aaaaaaa'},f.options)).toBeUndefined();expect(f.calls).toEqual([]);
});
it('loads a manifest-pinned successor version exactly',async()=>{
 const f=fixture();f.meta.version=3;f.meta.dataReleaseParameterVersion=2;f.parameter.Version=2;
 const selected=await loadWorkerDataRelease(f.clients,f.meta,{...f.options,mode:'admission'});expect(selected.parameterVersion).toBe(2);
});
it.each([1,3,undefined])('rejects observed version %s despite identical descriptor bytes',async version=>{
 const f=fixture();f.meta.version=3;f.meta.dataReleaseParameterVersion=2;f.parameter.Version=version;
 await expect(loadWorkerDataRelease(f.clients,f.meta,{...f.options,mode:'admission'})).rejects.toThrow();
});
it.each([undefined,0,'2',-1])('rejects invalid version binding %s in the new manifest',async version=>{
 const f=fixture();f.meta.version=3;f.meta.dataReleaseParameterVersion=version;f.parameter.Version=2;
 await expect(loadWorkerDataRelease(f.clients,f.meta,{...f.options,mode:'admission'})).rejects.toThrow();
});
it('a legacy retained manifest cannot admit a later same-byte parameter version',async()=>{
 const f=fixture();f.parameter.Version=2;
 await expect(loadWorkerDataRelease(f.clients,f.meta,{...f.options,mode:'admission'})).rejects.toThrow();
 expect((await loadWorkerDataRelease(f.clients,f.meta,{...f.options,mode:'inspection'})).parameterVersion).toBe(2);
});
