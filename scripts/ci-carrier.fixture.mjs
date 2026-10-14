// Reproducible synthetic carrier data, never a production grant or ledger.
import {createHash} from 'node:crypto';
import {CARRIER_PROFILE_ACTIONS,CARRIER_CI_JOB,carrierHash as hash,carrierOwnerSourceProfiles,measureCarrierBeforeCopyBudget,carrierObjectKeys} from './lib/ci-carrier-before-copy.mjs';
import {CARRIER_JOB} from './lib/ci-carrier-source.mjs';
import {CARRIER_CONTEXT_MAGIC,CARRIER_OPERATOR_FILES,carrierDockerfile} from './lib/ci-carrier-context.mjs';
export const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
export const zero=()=>({ecrRequests:0,logicalBytes:0,httpBodyBytes:0,uncompressedBytes:0,processedEntries:0});
export function carrierFixture(){
 const image={account:'123456789012',region:'ap-northeast-1',repositoryName:'mem9-on-aws/bootstrap',rootDigest:'sha256:'+sha('base-root'),arm64Digest:'sha256:'+sha('base-arm'),configDigest:'sha256:'+sha('base-config')};
 const profiles=Object.fromEntries(Object.keys(CARRIER_PROFILE_ACTIONS).filter(key=>!/^owner(?:Publisher)?Source(?:Token|Credentials)$/.test(key)).map(key=>[key,{count:key==='ownerIdentity'?3:key==='ownerIssuerIdentity'?2:1,requestBytes:1048576,responseBytes:1048576}]));
 profiles.ownerIssuerIdentity={count:2,requestBytes:16384,responseBytes:16384};
 profiles.ownerAssume={count:1,requestBytes:16384,responseBytes:262144};
 profiles.ownerPublisherIssuerIdentity={count:2,requestBytes:16384,responseBytes:16384};
 profiles.ownerPublisherAssume={count:1,requestBytes:16384,responseBytes:262144};
 profiles.fixturePut={count:1,requestBytes:155746816,responseBytes:16384};profiles.fixtureGet={count:1,requestBytes:0,responseBytes:155746816};
 for(const key of ['baseBlob','ownerBlob'])profiles[key]={kind:'carrier-blob-aggregate',maxRequests:8,aggregateResponseBytes:1048576,maxObjectBytes:1048576,descriptorSource:key==='baseBlob'?'authenticated-base-graph':'verified-output-graph'};
 const ownerSource={profile:'default',provider:'static-temporary',configFile:'/synthetic/config',credentialsFile:'/synthetic/credentials',configHash:sha('source-config'),credentialsHash:sha('source-credentials')};Object.assign(profiles,carrierOwnerSourceProfiles(ownerSource));
 const template={version:1,kind:'carrier-before-copy-template',purpose:'premerge-carrier-build',owner:'a'.repeat(32),executionId:'b'.repeat(32),slotNonce:'c'.repeat(32),ownerSource,
  source:{repository:'example/project',prNumber:7,candidateRevision:'a'.repeat(40),candidateTree:'b'.repeat(40),baseRevision:'c'.repeat(40),candidateRef:'refs/heads/codex/carrier',workflowPath:CARRIER_JOB.workflowPath,workflowSha:'a'.repeat(40),jobKey:CARRIER_JOB.key,jobName:CARRIER_JOB.name,jobDefinitionHash:sha('job-definition'),roleDefinitionHash:sha('role-definition')},
  scope:{account:image.account,region:image.region,previewRoleArn:'arn:aws:iam::123456789012:role/'+CARRIER_CI_JOB.previewRoleName,ownerRoleArn:'arn:aws:iam::123456789012:role/example-owner',repositoryName:'mem9-on-aws/preview/bootstrap',bucket:'example-carrier-artifacts',prefix:'decisions/pr-7/carrier',kmsKeyArn:'arn:aws:kms:ap-northeast-1:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',bucketKeyEnabled:true},
  anchors:{oldImage:image,oldImageEvidenceHash:sha('old'),hostCodeHash:sha('host'),hostSourceHash:sha('host-source'),hostEvidenceHash:sha('host-proof'),sourceCiHash:sha('ci'),baseEvidenceHash:sha('base-proof')},base:image,
  sqlFixture:{version:1,kind:'carrier-sql-fixture',archive:{sha256:'1670f7d35f612edc7f8ce8f052cfc0b26d0a8a44e84688fb94ebc1485f78d3b3',bytesLength:155746816},rootDigest:'sha256:cf134a767f474095eeba57e0117be8e568e011a63f33fbf252f14c9b760f8e6f',arm64Digest:'sha256:de5bb95ded567f98e342a29f188f8053b2e8d344cb9ccd52cbdfe15f720cfde7',configDigest:'sha256:9f6f5e8f6bf64903df0a7743c4580477c14139cdaac1c17056b21721cf34369e',attestationDigest:'sha256:7437603444d52ea934149e4553e9dd2694d0de22ad9dd26023905bf46f2f039b',uncompressedBytes:471413760,processedEntries:50000,oldSource:{revision:'d'.repeat(40),tree:'e'.repeat(40)}},
  recipe:{dockerfileHash:sha('recipe'),guardHash:sha('guard'),sourceClosureHash:sha('closure')},bounds:{contextBytes:1048576,contextFiles:1000,grantBytes:1048576,resultBytes:1048576,manifestNodes:8,blobNodes:8,compressedBytes:1048576,uncompressedBytes:16777216,processedEntries:1000,scanPages:1},profiles,
  preFundingPreparation:{...zero(),logicalBytes:16777216},fundedLocal:{owner:{...zero(),logicalBytes:33554432},ci:{...zero(),logicalBytes:16777216,uncompressedBytes:16777216,processedEntries:1000}},ownerGithubActorId:79};
 const now=Date.now(),plan={version:1,kind:'carrier-before-copy-funding-plan',purpose:'premerge-carrier-build',template,templateHash:hash(template),configHash:sha('config'),ledgerStartHash:sha('ledger-start'),ledgerBinding:{owner:template.owner,executionId:template.executionId,planHash:sha('config'),publicationHash:sha('publication')},context:{key:carrierObjectKeys(template).context,manifestHash:sha('manifest'),sha256:sha('context'),bytesLength:1000},issuedMs:now-1000,deadlineMs:now+120000,budget:measureCarrierBeforeCopyBudget(template).fundedRemaining};
 const s=template.source,env={GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:s.repository,GITHUB_JOB:s.jobKey,GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_REF:s.candidateRef,GITHUB_SHA:s.candidateRevision,GITHUB_WORKFLOW_SHA:s.workflowSha,GITHUB_WORKFLOW_REF:s.repository+'/'+s.workflowPath+'@'+s.candidateRef,GITHUB_RUN_ID:'71',GITHUB_RUN_ATTEMPT:'1',AWS_PREVIEW_ROLE_ARN:template.scope.previewRoleArn};
 const observations={run:{id:71,run_attempt:1,status:'in_progress',event:'workflow_dispatch',head_sha:s.candidateRevision,head_branch:s.candidateRef.slice(11),repository:{full_name:s.repository},path:s.workflowPath},job:{id:73,run_id:71,run_attempt:1,head_sha:s.candidateRevision,name:s.jobName,status:'in_progress'},commit:{sha:s.candidateRevision,tree:{sha:s.candidateTree}},pullRequest:{number:7,state:'open',merged:false,head:{sha:s.candidateRevision,repo:{full_name:s.repository}},base:{sha:s.baseRevision,ref:'main'}}};
 return {template,plan,sourceInput:{plan,grantHash:sha('grant'),env,observations,checkout:{revision:s.candidateRevision,tree:s.candidateTree}},rebind(){for(const k of ['baseBlob','ownerBlob'])Object.assign(template.profiles[k],{aggregateResponseBytes:template.bounds.compressedBytes,maxObjectBytes:template.bounds.compressedBytes,maxRequests:template.bounds.blobNodes});plan.templateHash=hash(template);plan.budget=measureCarrierBeforeCopyBudget(template).fundedRemaining;}};
}
export function carrierContextFixture({mutateFiles,mutateRuntime,mutateDockerfile,baseImage,nativePins}={}){
 const f=carrierFixture(),t=f.template,members=new Map(CARRIER_OPERATOR_FILES.map(path=>['rootfs/bootstrap/operator/'+path,Buffer.from(path.endsWith('.json')?'{}':'// synthetic old-image member\n')]));
 if(baseImage)t.base=baseImage;
 const baseEvidence={version:1,kind:'carrier-secure-base-evidence',image:t.base,native:nativePins??{nodeSha256:sha('node'),setprivSha256:sha('setpriv')},ca:{present:false}};
 t.anchors.baseEvidenceHash=hash(baseEvidence);
 for(const [path,bytes]of [['Dockerfile',mutateDockerfile?.(carrierDockerfile(t.base))??carrierDockerfile(t.base)],['rootfs/carrier/guard-first.mjs','// synthetic guard\n'],['rootfs/carrier/supplemental-readonly.mjs','// synthetic supplement\n'],['rootfs/carrier/legacy-audit.mjs','// authenticated synthetic host\n']])members.set(path,Buffer.from(bytes));
 t.anchors.hostCodeHash=sha(members.get('rootfs/carrier/legacy-audit.mjs'));t.recipe.dockerfileHash=sha(members.get('Dockerfile'));t.recipe.guardHash=sha(members.get('rootfs/carrier/guard-first.mjs'));
 const row=(path,bytes)=>({path,type:'file',mode:0o444,sha256:sha(bytes),bytesLength:bytes.length});
 t.recipe.sourceClosureHash=hash(['Dockerfile','rootfs/carrier/guard-first.mjs','rootfs/carrier/supplemental-readonly.mjs'].map(path=>{const r=row(path,members.get(path));return {path,sha256:r.sha256,bytesLength:r.bytesLength};}).sort((a,b)=>a.path.localeCompare(b.path)));
 const runtime={version:1,legacyCodeHash:t.anchors.hostCodeHash,expandedSourceHash:t.anchors.hostSourceHash,minifiedSourceHash:sha('minified'),dependencyHash:sha('dependency'),operatorInventoryHash:sha('operator-inventory'),runtime:baseEvidence.native,files:[...members].filter(([path])=>path!=='Dockerfile').map(([path,bytes])=>{const {bytesLength,...r}=row(path.slice(6),bytes);return {...r,bytes:bytesLength};}),caPath:null};
 mutateRuntime?.(runtime);members.set('rootfs/carrier/manifest.json',Buffer.from(JSON.stringify(runtime)));
 const files=[...members].map(([path,bytes])=>row(path,bytes));mutateFiles?.(files,members);
 files.sort((a,b)=>a.path.localeCompare(b.path));f.rebind();
 const manifest={version:1,kind:'carrier-build-context',templateHash:f.plan.templateHash,sourceTree:t.source.candidateTree,provenance:{oldImageHash:hash(t.anchors.oldImage),oldImageEvidenceHash:t.anchors.oldImageEvidenceHash,hostEvidenceHash:t.anchors.hostEvidenceHash,sourceCiHash:t.anchors.sourceCiHash,baseEvidenceHash:t.anchors.baseEvidenceHash},files};
 const header=Buffer.from(JSON.stringify(manifest)),size=Buffer.alloc(4);size.writeUInt32BE(header.length);
 const bytes=Buffer.concat([CARRIER_CONTEXT_MAGIC,size,header,...files.map(r=>members.get(r.path)??Buffer.from(r.target??''))]);
 Object.assign(f.plan.context,{manifestHash:hash(manifest),sha256:sha(bytes),bytesLength:bytes.length});
 return {...f,baseEvidence,members,manifest,runtime,bytes,stream:()=> (async function*(){for(let i=0;i<bytes.length;i+=137)yield bytes.subarray(i,i+137);})()};
}
/** Synthetic R13 supplied-only packet: deliberately no native/CA observations. */
export function carrierSourceContextFixture({mutateFiles,mutateHeader,baseImage,material}={}){
 const f=carrierContextFixture({baseImage}),t=f.template;
 const runtimeSource=Object.fromEntries(['legacyCodeHash','expandedSourceHash','minifiedSourceHash','dependencyHash','operatorInventoryHash'].map(k=>[k,f.runtime[k]]));
 if(material){
  t.sqlFixture.oldSource={...material.oldSource};
  for(const row of material.members)f.members.set(row.path,Buffer.from(row.bytesBase64,'base64'));
  Object.assign(runtimeSource,material.runtimeSource);t.anchors.hostCodeHash=runtimeSource.legacyCodeHash;t.anchors.hostSourceHash=runtimeSource.expandedSourceHash;
  t.recipe.guardHash=sha(f.members.get('rootfs/carrier/guard-first.mjs'));
 }
 f.members.delete('rootfs/carrier/manifest.json');f.members.delete('rootfs/bootstrap/global-bundle.pem');
 f.members.set('Dockerfile',Buffer.from(carrierDockerfile(t.base,{derived:true,caPresent:true})));
 t.anchors.baseEvidenceHash=hash({kind:'synthetic-existing-base-ci',image:t.base,sourceCiHash:t.anchors.sourceCiHash});
 const files=[...f.members].map(([path,bytes])=>({path,type:'file',mode:0o444,sha256:sha(bytes),bytesLength:bytes.length}));
 mutateFiles?.(files,f.members);files.sort((a,b)=>a.path.localeCompare(b.path));
 t.recipe.dockerfileHash=sha(f.members.get('Dockerfile'));
 t.recipe.sourceClosureHash=hash(['Dockerfile','rootfs/carrier/guard-first.mjs','rootfs/carrier/supplemental-readonly.mjs'].map(path=>({path,sha256:sha(f.members.get(path)),bytesLength:f.members.get(path).length})).sort((a,b)=>a.path.localeCompare(b.path)));
 f.rebind();const manifest={version:2,kind:'carrier-build-source-context',templateHash:f.plan.templateHash,sourceTree:t.source.candidateTree,provenance:{oldImageHash:hash(t.anchors.oldImage),oldImageEvidenceHash:t.anchors.oldImageEvidenceHash,hostEvidenceHash:t.anchors.hostEvidenceHash,sourceCiHash:t.anchors.sourceCiHash,baseEvidenceHash:t.anchors.baseEvidenceHash},runtimeSource,files};
 mutateHeader?.(manifest);const header=Buffer.from(JSON.stringify(manifest)),size=Buffer.alloc(4);size.writeUInt32BE(header.length);
 const bytes=Buffer.concat([CARRIER_CONTEXT_MAGIC,size,header,...files.map(r=>f.members.get(r.path)??Buffer.from(r.target??''))]);
 Object.assign(f.plan.context,{manifestHash:hash(manifest),sha256:sha(bytes),bytesLength:bytes.length});
 delete f.baseEvidence;delete f.runtime;
 return {...f,manifest,bytes,stream:()=> (async function*(){for(let at=0;at<bytes.length;at+=137)yield bytes.subarray(at,at+137);})()};
}
