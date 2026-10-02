import {it,expect,vi,afterEach} from 'vitest';
import {prepareDataReleaseAuthorization} from './lib/production-data-authorization.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
import * as producer from './lib/production-canary-producer.mjs';
afterEach(()=>vi.restoreAllMocks());
const h=c=>c.repeat(64),now=1800000000000;
function fixture(){
  const names=['llm-proxy','mnemo-server','qwen3-embed'],account='123456789012',region='ap-northeast-1';
  const components=Object.fromEntries(names.map((name,i)=>[name,{registryId:account,repositoryName:'mem9-on-aws/'+name,rootDigest:'sha256:'+h(String(i+1)),arm64Digest:'sha256:'+h(String(i+4))}]));
  const previous={account,region},observed={version:2,account,region,observedAt:new Date(now-1000).toISOString(),revision:'a'.repeat(40),sourceTree:'b'.repeat(40),sourceTag:'mem9-aaaaaaa',components,
    generation:h('a'),runtime:{runtimeNonce:'c'.repeat(32),schemaDigest:h('b'),operatorDigest:h('c')}};
  observed.components.worker=structuredClone(components['llm-proxy']);
  observed.workerImage=`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/llm-proxy@${components['llm-proxy'].rootDigest}`;
  const parent={verification:{changedRows:10,targets:['namespace'],backendBindingHash:h('d')}},control={revision:'d'.repeat(40),sourceTree:'e'.repeat(40),sourceEvidenceHash:h('e'),freshDataImages:Object.fromEntries(names.map(n=>[n,{rootDigest:'sha256:'+h('8'),arm64Digest:'sha256:'+h('9')}]))};
  const recipe={version:1,kind:'synthetic-declared-build-inputs'},recipeHash=hash(recipe),artifacts=Object.fromEntries(names.map(name=>[name,{...components[name],config:{},layers:[]}])) ;
  const build={version:1,controlRevision:control.revision,controlSourceTree:control.sourceTree,dataRevision:observed.revision,dataSourceTree:observed.sourceTree,
    recipe,recipeHash,artifacts,buildInputsHash:hash({version:1,recipeHash,artifacts})};
  const scans=Object.fromEntries(names.map(name=>[name,{repositoryName:'mem9-on-aws/'+name,imageDigest:components[name].arm64Digest,findings:[{name:'CVE-example',severity:'HIGH'}]}]));
  const security={version:1,observedMs:now-1000,scans,securityEvidenceHash:hash(scans)},freshBuildSecurity=structuredClone(security);
  for(const name of names){freshBuildSecurity.scans[name].repositoryName='mem9-on-aws/preview/'+name;freshBuildSecurity.scans[name].imageDigest='sha256:'+h('9');}
  freshBuildSecurity.securityEvidenceHash=hash(freshBuildSecurity.scans);
  const expiresMs=now+3600000,review={version:1,kind:'retained-data-policy-review',decision:'within-existing-policy',controlSourceTree:control.sourceTree,sourceEvidenceHash:control.sourceEvidenceHash,
    parentProofHash:hash(parent.verification),buildInputsHash:build.buildInputsHash,securityEvidenceHash:security.securityEvidenceHash,freshBuildSecurityHash:freshBuildSecurity.securityEvidenceHash,
    policySourcesHash:h('f'),reviewedMs:now-500,expiresMs};
  const compare=vi.spyOn(producer,'buildCanaryCompatibility').mockReturnValue({});
  return {input:{previous,observed,parent,control,build,security,freshBuildSecurity,review,authorizationId:'f'.repeat(32),issuedMs:now-100,expiresMs},compare};
}
it('binds the independent policy review and exact retained artifacts without replacing the old source tag',()=>{
  const f=fixture(),result=prepareDataReleaseAuthorization(f.input,{now});
  expect(result.data.dataSourceTag).toBe('mem9-aaaaaaa');expect(result.data.controlSourceTree).toBe(f.input.control.sourceTree);expect(result.data.policyHash).toBe(hash(f.input.review));
  expect(f.compare).toHaveBeenCalledWith(f.input.previous,f.input.observed,f.input.parent.verification,{now});
});
it('rejects a missing review, unverified material, stale observations or substituted evidence',()=>{
  for(const mutate of [f=>{delete f.input.review;},f=>{f.input.observed.observedAt=new Date(now-300001).toISOString();},
    f=>{f.input.review.parentProofHash=h('0');},f=>{f.input.build.recipe.changed=true;},f=>{f.input.expiresMs=now;},f=>{f.input.review.decision='automatic-waiver';}]){
    const f=fixture();mutate(f);expect(()=>prepareDataReleaseAuthorization(f.input,{now})).toThrow();vi.restoreAllMocks();
  }
  const f=fixture();f.compare.mockImplementation(()=>{throw Error('CanaryMaterialCaptureFailed');});expect(()=>prepareDataReleaseAuthorization(f.input,{now})).toThrow('CanaryMaterialCaptureFailed');
});
it('rejects a fresh build with a different vulnerability inventory rather than silently waiving old findings',()=>{
  const f=fixture();f.input.freshBuildSecurity.scans['llm-proxy'].findings=[];f.input.freshBuildSecurity.securityEvidenceHash=hash(f.input.freshBuildSecurity.scans);
  f.input.review.freshBuildSecurityHash=f.input.freshBuildSecurity.securityEvidenceHash;
  expect(()=>prepareDataReleaseAuthorization(f.input,{now})).toThrow('DataReleaseAuthorizationUnverified');
});
it('rejects worker/proxy observations that one shared retained artifact cannot represent',()=>{
  for(const mutate of [f=>{f.input.observed.components.worker.rootDigest='sha256:'+h('7');},
    f=>{f.input.observed.components.worker.arm64Digest='sha256:'+h('8');},
    f=>{f.input.observed.workerImage=f.input.observed.workerImage.replace(/1{64}$/,'7'.repeat(64));}]){
    const f=fixture();mutate(f);expect(()=>prepareDataReleaseAuthorization(f.input,{now})).toThrow('DataReleaseAuthorizationUnverified');vi.restoreAllMocks();
  }
});
