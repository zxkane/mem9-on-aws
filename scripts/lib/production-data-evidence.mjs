import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createHash} from 'node:crypto';
import {DATA_COMPONENTS,inspectDataRelease} from './production-data-release.mjs';
import {captureDataBuildInputs,compareDataBuildInputs} from './production-data-build-inputs.mjs';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';

const execute=promisify(execFile),digest=v=>typeof v==='string'&&/^sha256:[a-f0-9]{64}$/.test(v);
const fail=()=>{throw Error('DataReleaseArtifactUnverified');};
const bodyHash=text=>'sha256:'+createHash('sha256').update(text).digest('hex');
const imageTypes=['application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json'];
function manifest(response,{account,repositoryName,imageDigest}){
  if(response?.failures?.length||!Array.isArray(response.images)||!response.images.length||response.images.length>100)fail();
  const bodies=new Set();
  for(const image of response.images){
    if(image.registryId!==account||image.repositoryName!==repositoryName||image.imageId?.imageDigest!==imageDigest||
      typeof image.imageManifest!=='string'||Buffer.byteLength(image.imageManifest)>4194304||bodyHash(image.imageManifest)!==imageDigest)fail();
    bodies.add(image.imageManifest);
  }
  if(bodies.size!==1)fail();try{return JSON.parse([...bodies][0]);}catch{fail();}
}
export function verifyDataReleaseArtifact(rootResponse,childResponse,expected){
  const {account,repositoryName,rootDigest,arm64Digest}=expected;
  if(!/^\d{12}$/.test(account??'')||!/^mem9-on-aws\/(?:preview\/)?(?:llm-proxy|mnemo-server|qwen3-embed)$/.test(repositoryName??'')||
    !digest(rootDigest)||!digest(arm64Digest)||rootDigest===arm64Digest)fail();
  const root=manifest(rootResponse,{account,repositoryName,imageDigest:rootDigest});
  if(root.schemaVersion!==2||!['application/vnd.oci.image.index.v1+json','application/vnd.docker.distribution.manifest.list.v2+json'].includes(root.mediaType)||!Array.isArray(root.manifests))fail();
  const children=root.manifests.filter(m=>m?.platform?.os==='linux'&&m.platform.architecture==='arm64');
  if(children.length!==1||children[0].digest!==arm64Digest||!imageTypes.includes(children[0].mediaType))fail();
  const child=manifest(childResponse,{account,repositoryName,imageDigest:arm64Digest});
  if(child.schemaVersion!==2||!imageTypes.includes(child.mediaType)||!digest(child.config?.digest)||
    !Number.isSafeInteger(child.config.size)||child.config.size<1||child.config.urls||
    !Array.isArray(child.layers)||!child.layers.length||child.layers.length>1000||child.layers.some(l=>!digest(l?.digest)||
      !Number.isSafeInteger(l.size)||l.size<1||typeof l.mediaType!=='string'||l.urls))fail();
  // Config and layer descriptors record the exact selected artifact's resolved
  // bytes. This does not assert that every build-time network fetch has source
  // provenance, or that a future rebuild would resolve the same bytes.
  return {repositoryName,rootDigest,arm64Digest,config:child.config,layers:child.layers};
}

export function dataReleaseEcrReader({account,region,profile=process.env.AWS_PROFILE}){
  if(!/^\d{12}$/.test(account??'')||!/^[a-z]{2}(?:-[a-z]+)+-[0-9]+$/.test(region??''))fail();
  return async(operation,input)=>{
    if(!['batch-get-image','describe-image-scan-findings'].includes(operation)||
      !/^mem9-on-aws\/(?:preview\/)?(?:llm-proxy|mnemo-server|qwen3-embed)$/.test(input.repositoryName??'')||!digest(input.imageDigest))fail();
    const args=['ecr',operation,'--region',region,'--registry-id',account,'--repository-name',input.repositoryName,
      operation==='batch-get-image'?'--image-ids':'--image-id','imageDigest='+input.imageDigest,'--output','json',...(profile?['--profile',profile]:[])];
    if(operation==='describe-image-scan-findings'){
      args.push('--no-paginate','--max-results','1000');
      if(input.nextToken!==undefined){if(typeof input.nextToken!=='string'||!input.nextToken||input.nextToken.length>8192)fail();args.push('--next-token',input.nextToken);}
    }else if(input.nextToken!==undefined)fail();
    try{return JSON.parse((await execute('aws',args,{timeout:30000,maxBuffer:8*1024*1024})).stdout);}catch{fail();}
  };
}

export async function captureDataReleaseBuild({data,repository=process.cwd(),controlRevision,readEcr=dataReleaseEcrReader(data)}){
  const selected=inspectDataRelease(data,{stage:data.stage,account:data.account,region:data.region,controlSourceTree:data.controlSourceTree});
  const previous=await captureDataBuildInputs({repository,revision:data.dataRevision,sourceTree:data.dataSourceTree});
  const current=await captureDataBuildInputs({repository,revision:controlRevision,sourceTree:data.controlSourceTree});
  const recipeHash=compareDataBuildInputs(previous,current),artifacts={};
  for(const component of DATA_COMPONENTS){
    const repositoryName=(data.stage==='prod'?'mem9-on-aws/':'mem9-on-aws/preview/')+component;
    const image=data.images[component];
    const root=await readEcr('batch-get-image',{repositoryName,imageDigest:image.rootDigest});
    const child=await readEcr('batch-get-image',{repositoryName,imageDigest:image.arm64Digest});
    artifacts[component]=verifyDataReleaseArtifact(root,child,{account:data.account,repositoryName,...image});
  }
  return {version:1,recipe:current.recipe,recipeHash,artifacts,buildInputsHash:hash({version:1,recipeHash,artifacts}),dataReleaseHash:selected.hash};
}

export async function captureDataReleaseScans({data,readEcr=dataReleaseEcrReader(data),now=Date.now()}){
  inspectDataRelease(data,{stage:data.stage,account:data.account,region:data.region,controlSourceTree:data.controlSourceTree});
  const scans={};
  for(const component of DATA_COMPONENTS){
    const repositoryName=(data.stage==='prod'?'mem9-on-aws/':'mem9-on-aws/preview/')+component,imageDigest=data.images[component].arm64Digest;
    const findings=[],tokens=new Set();let nextToken,identity;
    for(let page=0;page<100;page++){
      const response=await readEcr('describe-image-scan-findings',{repositoryName,imageDigest,...(nextToken?{nextToken}:{})}),scan=response.imageScanFindings;
      const completedMs=new Date(scan?.imageScanCompletedAt).getTime();
      if(response.registryId!==data.account||response.repositoryName!==repositoryName||response.imageId?.imageDigest!==imageDigest||
        response.imageScanStatus?.status!=='COMPLETE'||!Number.isSafeInteger(completedMs)||completedMs>now||now-completedMs>86400000||
        !Array.isArray(scan?.findings)||scan.enhancedFindings?.length||!scan.findingSeverityCounts)throw Error('DataReleaseScanUnverified');
      const current={repositoryName,imageDigest,completedMs,counts:scan.findingSeverityCounts};
      if(identity&&hash(identity)!==hash(current))throw Error('DataReleaseScanChanged');identity=current;
      findings.push(...scan.findings);if(findings.length>10000)throw Error('DataReleaseScanUnverified');
      if(!response.nextToken){nextToken=null;break;}
      if(tokens.has(response.nextToken))throw Error('DataReleaseScanUnverified');tokens.add(response.nextToken);nextToken=response.nextToken;
    }
    if(nextToken)throw Error('DataReleaseScanUnverified');
    const counts={};
    const normalized=findings.map(f=>{
      if(!f||typeof f.name!=='string'||!['INFORMATIONAL','LOW','MEDIUM','HIGH','CRITICAL','UNDEFINED'].includes(f.severity)||
        !Array.isArray(f.attributes)||f.attributes.some(a=>typeof a?.key!=='string'||typeof a.value!=='string'))throw Error('DataReleaseScanUnverified');
      counts[f.severity]=(counts[f.severity]??0)+1;
      return {...f,attributes:[...f.attributes].sort((a,b)=>hash(a).localeCompare(hash(b)))};
    }).sort((a,b)=>hash(a).localeCompare(hash(b)));
    const nonzero=Object.fromEntries(Object.entries(identity.counts).filter(([,value])=>value!==0));
    if(Object.values(identity.counts).some(n=>!Number.isSafeInteger(n)||n<0)||hash(counts)!==hash(nonzero))throw Error('DataReleaseScanUnverified');
    scans[component]={repositoryName,imageDigest,findings:normalized};
  }
  // This is a complete scan inventory, never a risk-acceptance verdict. The
  // operator must review open findings under the applicable existing policy.
  return {version:1,observedMs:now,scans,securityEvidenceHash:hash(scans)};
}
