import {it,expect} from 'vitest';
import {createHash} from 'node:crypto';
import {verifyDataReleaseArtifact,captureDataReleaseScans} from './lib/production-data-evidence.mjs';
const digest=c=>'sha256:'+c.repeat(64),account='123456789012',now=1800000000000;
function artifact(){
  const repositoryName='mem9-on-aws/llm-proxy';
  const child={schemaVersion:2,mediaType:'application/vnd.oci.image.manifest.v1+json',config:{mediaType:'application/vnd.oci.image.config.v1+json',size:20,digest:digest('a')},layers:[{mediaType:'application/vnd.oci.image.layer.v1.tar+gzip',size:100,digest:digest('b')}]};
  const response=value=>{const imageManifest=JSON.stringify(value),imageDigest='sha256:'+createHash('sha256').update(imageManifest).digest('hex');return {images:[{registryId:account,repositoryName,imageId:{imageDigest},imageManifest}]};};
  const childResponse=response(child),arm64Digest=childResponse.images[0].imageId.imageDigest;
  const root={schemaVersion:2,mediaType:'application/vnd.oci.image.index.v1+json',manifests:[{mediaType:child.mediaType,platform:{os:'linux',architecture:'arm64'},digest:arm64Digest}]};
  const rootResponse=response(root),rootDigest=rootResponse.images[0].imageId.imageDigest;
  return {rootResponse,childResponse,expected:{account,repositoryName,rootDigest,arm64Digest},child};
}
it('binds selected root and actual ARM64 manifest to config and layer descriptors',()=>{
  const f=artifact(),result=verifyDataReleaseArtifact(f.rootResponse,f.childResponse,f.expected);expect(result.config).toEqual(f.child.config);expect(result.layers).toEqual(f.child.layers);
});
it('rejects substituted children, mutated bytes and foreign repositories',()=>{
  for(const mutate of [f=>{f.expected.arm64Digest=digest('c');},f=>{f.childResponse.images[0].imageManifest+=' ';},f=>{f.rootResponse.images[0].repositoryName='other';}]){
    const f=artifact();mutate(f);expect(()=>verifyDataReleaseArtifact(f.rootResponse,f.childResponse,f.expected)).toThrow('DataReleaseArtifactUnverified');
  }
});
function scanFixture(){
  const data={version:1,stage:'prod',account,region:'ap-northeast-1',controlSourceTree:'a'.repeat(40),dataRevision:'b'.repeat(40),dataSourceTree:'c'.repeat(40),dataSourceTag:'mem9-bbbbbbb',
    images:Object.fromEntries(['llm-proxy','mnemo-server','qwen3-embed'].map((name,i)=>[name,{rootDigest:digest(String(i+1)),arm64Digest:digest(String(i+4))}])),
    runtimeNonce:'d'.repeat(32),authorizationId:'e'.repeat(32),issuedMs:now-1000,expiresMs:now+1000,
    ...Object.fromEntries(['parentProofHash','backendBindingHash','generation','targetsHash','schemaDigest','operatorDigest','buildInputsHash','securityEvidenceHash','policyHash'].map(n=>[n,'f'.repeat(64)]))};
  const finding={name:'CVE-example',severity:'HIGH',attributes:[{key:'package_name',value:'example'},{key:'package_version',value:'1'}]};
  const readEcr=async(_op,input)=>({registryId:account,repositoryName:input.repositoryName,imageId:{imageDigest:input.imageDigest},imageScanStatus:{status:'COMPLETE'},imageScanFindings:{imageScanCompletedAt:new Date(now-1000).toISOString(),findings:[finding],findingSeverityCounts:{HIGH:1}}});
  return {data,readEcr};
}
it('retains open HIGH findings as evidence rather than treating a scan as acceptance',async()=>{
  const f=scanFixture(),record=await captureDataReleaseScans({...f,now});expect(record.scans['llm-proxy'].findings[0].severity).toBe('HIGH');expect(record).not.toHaveProperty('approved');
});
it('rejects stale scans, truncated counts and changed image identity',async()=>{
  for(const mutate of [r=>{r.imageScanFindings.imageScanCompletedAt=new Date(now-86400001).toISOString();},r=>{r.imageScanFindings.findingSeverityCounts.HIGH=2;},r=>{r.imageId.imageDigest=digest('0');}]){
    const f=scanFixture(),read=f.readEcr;f.readEcr=async(...args)=>{const r=await read(...args);mutate(r);return r;};
    await expect(captureDataReleaseScans({...f,now})).rejects.toThrow('DataReleaseScanUnverified');
  }
});
it('exhausts scan pages and rejects a scan that changes between pages',async()=>{
  const f=scanFixture(),read=f.readEcr;
  let drift=false;
  f.readEcr=async(op,input)=>{
    const r=await read(op,input);r.imageScanFindings.findingSeverityCounts.HIGH=2;
    if(!input.nextToken)r.nextToken='second';
    else{
      r.imageScanFindings.findings=[{...r.imageScanFindings.findings[0],name:'CVE-second'}];
      if(drift)r.imageScanFindings.imageScanCompletedAt=new Date(now-500).toISOString();
    }
    return r;
  };
  expect((await captureDataReleaseScans({...f,now})).scans['llm-proxy'].findings).toHaveLength(2);
  drift=true;await expect(captureDataReleaseScans({...f,now})).rejects.toThrow('DataReleaseScanChanged');
});
