import {GetParametersCommand} from '@aws-sdk/client-ssm';
import {inspectDataRelease,requireActiveDataRelease} from './production-data-release.mjs';

const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===[...keys].sort().join();
const fail=()=>{throw Error('ProductionDataReleaseMetadataInvalid');};

// Reading the fixed protected record prevents an environment-only selector
// from asserting its own authorization. The caller still verifies current
// build/material/security evidence before using this snapshot for deployment.
export async function loadDeploymentDataRelease(clients,{stage,account,region,controlSourceTree,runtime,env={},now=Date.now()}){
  if(stage!=='prod'&&!/^pr-[1-9][0-9]*$/.test(stage??'')||!/^\d{12}$/.test(account??'')||
    !/^[a-z]{2}(?:-[a-z]+)+-[0-9]+$/.test(region??'')||!/^[a-f0-9]{40}$/.test(controlSourceTree??''))fail();
  const prefix=`/mem9-on-aws/${stage}/`,name=prefix+'consolidation-runtime/data-release';
  const selectionName=prefix+'ecs/image-selection',operatorName=prefix+'consolidation-runtime/operator-manifest';
  const names=[name,selectionName,...(stage==='prod'?[operatorName]:[])];
  const result=await clients.ssm.send(new GetParametersCommand({Names:names,WithDecryption:true}),{abortSignal:AbortSignal.timeout(30000)});
  const parameters=result.Parameters??[],missing=result.InvalidParameters??[],seen=[...parameters.map(p=>p.Name),...missing];
  if(new Set(seen).size!==seen.length||seen.sort().join()!==[...names].sort().join())fail();
  const record=new Map(parameters.map(p=>[p.Name,p]));
  for(const p of parameters)if(typeof p.Value!=='string'||!Number.isSafeInteger(p.Version)||p.Version<1||
    p.ARN!==`arn:aws:ssm:${region}:${account}:parameter${p.Name}`)fail();
  const parse=key=>{const p=record.get(key);if(!p)return;try{return JSON.parse(p.Value);}catch{fail();}};
  const current=parse(selectionName),operator=parse(operatorName),parameter=record.get(name);
  if(current!==undefined&&(!exact(current,['version','mode','controlTag','dataTag','images',...(current.mode==='retained'?['dataReleaseHash','arm64Digests']:[])])||
    current.version!==1||!['tag','retained'].includes(current.mode)))fail();
  if(operator!==undefined&&(![1,2,3].includes(operator?.version)||operator.stage!==stage||operator.account!==account||operator.region!==region))fail();
  const claimed=env.MEM9_RETAINED_DATA_RELEASE,claimedHash=env.MEM9_RETAINED_DATA_RELEASE_HASH;
  if(!parameter){
    if(current?.mode==='retained'||operator?.version>=2||claimed&&claimed!=='none'||claimedHash&&claimedHash!=='none')throw Error('ProductionDataReleaseMissing');
    return;
  }
  if(parameter.Type!=='SecureString'||runtime?.phase!=='complete'||runtime.status!=='running'||runtime.stage!==stage)fail();
  const selected=requireActiveDataRelease(parameter.Value,{stage,account,region,controlSourceTree,
    bindings:{runtimeNonce:runtime.nonce,schemaDigest:runtime.schemaDigest,operatorDigest:runtime.operatorDigest}},{now});
  if(claimed!==undefined&&claimed!==JSON.stringify(selected.data)||claimedHash!==undefined&&claimedHash!==selected.hash)throw Error('ProductionDataReleaseOverrideConflict');
  if(env.MEM9_RETAINED_DATA_RELEASE_VERSION!==undefined&&env.MEM9_RETAINED_DATA_RELEASE_VERSION!==String(parameter.Version))throw Error('ProductionDataReleaseVersionMismatch');
  // A descriptor for a new control release may legitimately supersede the old
  // selection hash. It must retain the exact already-selected data artifacts.
  if(current?.mode==='retained'){
    if(current.dataTag!==selected.data.dataSourceTag||JSON.stringify(Object.keys(current.images??{}).sort())!==JSON.stringify(Object.keys(selected.images).sort()))fail();
    for(const [component,image]of Object.entries(selected.images))if(current.images[component]!==image||
      current.arm64Digests?.[component]!==selected.data.images[component].arm64Digest)fail();
  }
  if(operator&&(operator.generation!==selected.data.generation||operator.sourceTag!==selected.data.dataSourceTag||operator.workerImage!==selected.images['llm-proxy']))fail();
  return {...selected,parameterVersion:parameter.Version,currentSelection:current};
}

export async function loadWorkerDataRelease(clients,meta,{controlRevision,controlSourceTree,mode='inspection',now=Date.now()}={}){
  if(!['inspection','admission'].includes(mode)||!/^[a-f0-9]{40}$/.test(controlRevision??'')||
    (meta.controlSourceTag??meta.sourceTag)!=='mem9-'+controlRevision.slice(0,7))throw Error('ProductionControlRevisionMismatch');
  if(meta.version===1){
    if(meta.dataReleaseHash!==undefined||meta.dataReleaseParameter!==undefined||meta.controlSourceTag&&meta.controlSourceTag!==meta.sourceTag)throw Error('ProductionDataReleaseInvalid');
    return;
  }
  const name='/mem9-on-aws/prod/consolidation-runtime/data-release';
  if(![2,3].includes(meta.version)||meta.stage!=='prod'||meta.dataReleaseParameter!==name||!/^[a-f0-9]{64}$/.test(meta.dataReleaseHash??'')||
    !/^[a-f0-9]{40}$/.test(controlSourceTree??''))throw Error('ProductionDataReleaseInvalid');
  if(meta.version===3&&(!Number.isSafeInteger(meta.dataReleaseParameterVersion)||meta.dataReleaseParameterVersion<1))throw Error('ProductionDataReleaseVersionRequired');
  if(meta.version===2&&meta.dataReleaseParameterVersion!==undefined)throw Error('ProductionDataReleaseInvalid');
  const result=await clients.ssm.send(new GetParametersCommand({Names:[name],WithDecryption:true}),{abortSignal:AbortSignal.timeout(30000)});
  const p=result.Parameters?.[0];
  if(result.InvalidParameters?.length||result.Parameters?.length!==1||p.Name!==name||p.Type!=='SecureString'||!Number.isSafeInteger(p.Version)||p.Version<1)throw Error('ProductionDataReleaseMissing');
  if(meta.version===3&&p.Version!==meta.dataReleaseParameterVersion||meta.version===2&&mode==='admission'&&p.Version!==1)throw Error('ProductionDataReleaseVersionMismatch');
  const expected={stage:'prod',account:meta.account,region:meta.region,controlSourceTree,bindings:{generation:meta.generation}};
  const selected=mode==='admission'?requireActiveDataRelease(p.Value,expected,{now}):inspectDataRelease(p.Value,expected);
  if(selected.hash!==meta.dataReleaseHash||selected.data.dataSourceTag!==meta.sourceTag||selected.images['llm-proxy']!==meta.workerImage)throw Error('ProductionDataReleaseMismatch');
  return {...selected,parameterVersion:p.Version};
}
