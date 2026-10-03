import {DATA_COMPONENTS,requireActiveDataRelease} from './production-data-release.mjs';
import {buildCanaryCompatibility} from './production-canary-producer.mjs';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';

const fail=()=>{throw Error('DataReleaseAuthorizationUnverified');};
const hex=(v,n=64)=>typeof v==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(v);
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===[...keys].sort().join();

/** Construct a descriptor after independent source/material/security review.
 * This function never writes an authorization, changes clocks, or accepts a
 * scanner inventory as a policy decision. The operator protocol owns issuance.
 */
export function prepareDataReleaseAuthorization({previous,observed,parent,control,build,security,freshBuildSecurity,review,
  authorizationId,issuedMs,expiresMs},{now=Date.now()}={}){
  if(!exact(control,['revision','sourceTree','sourceEvidenceHash','freshDataImages'])||!hex(control.revision,40)||!hex(control.sourceTree,40)||!hex(control.sourceEvidenceHash)||!exact(control.freshDataImages,DATA_COMPONENTS)||
    !hex(authorizationId,32)||!Number.isSafeInteger(now)||!Number.isSafeInteger(issuedMs)||!Number.isSafeInteger(expiresMs)||
    issuedMs>now||now-issuedMs>300000||expiresMs<=now||expiresMs-issuedMs>86400000||
    !parent?.verification||!Number.isSafeInteger(parent.verification.changedRows)||parent.verification.changedRows<2||parent.verification.changedRows>=20)fail();
  const observedMs=Date.parse(observed?.observedAt);
  if(!Number.isSafeInteger(observedMs)||observedMs>now||now-observedMs>300000)fail();
  // Before deployment, the current production data/control release must still
  // match the archived frozen parent. This is independent of the future witness.
  buildCanaryCompatibility(previous,observed,parent.verification,{now});
  const proxy=observed.components?.['llm-proxy'],worker=observed.components?.worker;
  if(!proxy||!worker||worker.registryId!==observed.account||worker.repositoryName!=='mem9-on-aws/llm-proxy'||
    worker.rootDigest!==proxy.rootDigest||worker.arm64Digest!==proxy.arm64Digest||
    observed.workerImage!==`${observed.account}.dkr.ecr.${observed.region}.amazonaws.com/mem9-on-aws/llm-proxy@${proxy.rootDigest}`)fail();
  if(build?.version!==1||build.controlRevision!==control.revision||build.controlSourceTree!==control.sourceTree||
    build.dataRevision!==(observed.dataRelease?.data.dataRevision??observed.revision)||
    build.dataSourceTree!==(observed.dataRelease?.data.dataSourceTree??observed.sourceTree)||hash(build.recipe)!==build.recipeHash||
    build.buildInputsHash!==hash({version:1,recipeHash:build.recipeHash,artifacts:build.artifacts})||
    !exact(build.artifacts,DATA_COMPONENTS))fail();
  for(const evidence of [security,freshBuildSecurity]){
    if(evidence?.version!==1||!Number.isSafeInteger(evidence.observedMs)||evidence.observedMs>now||now-evidence.observedMs>300000||
      !exact(evidence.scans,DATA_COMPONENTS)||evidence.securityEvidenceHash!==hash(evidence.scans))fail();
  }
  const images={};
  for(const component of DATA_COMPONENTS){
    const selected=observed.components[component],artifact=build.artifacts[component],scan=security.scans[component],fresh=freshBuildSecurity.scans[component];
    const freshImage=control.freshDataImages[component];
    const repositoryName='mem9-on-aws/'+component;
    if(selected?.registryId!==observed.account||selected.repositoryName!==repositoryName||artifact.repositoryName!==repositoryName||
      artifact.rootDigest!==selected.rootDigest||artifact.arm64Digest!==selected.arm64Digest||
      scan.repositoryName!==repositoryName||scan.imageDigest!==selected.arm64Digest||!Array.isArray(scan.findings)||
      ![repositoryName,'mem9-on-aws/preview/'+component].includes(fresh?.repositoryName)||!Array.isArray(fresh.findings)||
      !exact(freshImage,['rootDigest','arm64Digest'])||!/^sha256:[a-f0-9]{64}$/.test(freshImage.rootDigest??'')||
      !/^sha256:[a-f0-9]{64}$/.test(freshImage.arm64Digest??'')||freshImage.rootDigest===freshImage.arm64Digest||fresh.imageDigest!==freshImage.arm64Digest||
      hash(scan.findings)!==hash(fresh.findings))fail();
    images[component]={rootDigest:selected.rootDigest,arm64Digest:selected.arm64Digest};
  }
  const reviewKeys=['version','kind','decision','controlSourceTree','sourceEvidenceHash','parentProofHash','buildInputsHash',
    'securityEvidenceHash','freshBuildSecurityHash','policySourcesHash','reviewedMs','expiresMs'];
  if(!exact(review,reviewKeys)||review.version!==1||review.kind!=='retained-data-policy-review'||review.decision!=='within-existing-policy'||
    review.controlSourceTree!==control.sourceTree||review.sourceEvidenceHash!==control.sourceEvidenceHash||review.parentProofHash!==hash(parent.verification)||
    review.buildInputsHash!==build.buildInputsHash||review.securityEvidenceHash!==security.securityEvidenceHash||
    review.freshBuildSecurityHash!==freshBuildSecurity.securityEvidenceHash||!hex(review.policySourcesHash)||
    !Number.isSafeInteger(review.reviewedMs)||review.reviewedMs>now||now-review.reviewedMs>300000||review.expiresMs!==expiresMs)fail();
  const data={version:1,stage:'prod',account:observed.account,region:observed.region,controlSourceTree:control.sourceTree,
    dataRevision:observed.dataRelease?.data.dataRevision??observed.revision,
    dataSourceTree:observed.dataRelease?.data.dataSourceTree??observed.sourceTree,dataSourceTag:observed.sourceTag,images,
    parentProofHash:hash(parent.verification),backendBindingHash:parent.verification.backendBindingHash,
    runtimeNonce:observed.runtime.runtimeNonce,generation:observed.generation,targetsHash:hash([...parent.verification.targets].sort()),
    schemaDigest:observed.runtime.schemaDigest,operatorDigest:observed.runtime.operatorDigest,
    buildInputsHash:build.buildInputsHash,securityEvidenceHash:security.securityEvidenceHash,policyHash:hash(review),authorizationId,issuedMs,expiresMs};
  return {...requireActiveDataRelease(data,{stage:'prod',account:data.account,region:data.region,controlSourceTree:control.sourceTree},{now}),review:structuredClone(review)};
}
