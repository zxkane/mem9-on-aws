import {createHash} from 'node:crypto';

const hash=value=>createHash('sha256').update(value).digest('hex');
export const isConsolidationPreview=stage=>/^pr-[1-9][0-9]*$/.test(stage||'');
export function validatePreviewContext(context){
  if(!context||typeof context!=='object'||Array.isArray(context)||
    Object.keys(context).sort().join()!=='kind,runtimeNonce'||context.kind!=='post-runtime'||
    !/^[a-f0-9]{32}$/.test(context.runtimeNonce||''))throw Error('InvalidPreviewContext');
  return {kind:'post-runtime',runtimeNonce:context.runtimeNonce};
}
export function previewAcceptanceContext(stage,env=process.env){
  if(env.MEM9_PREVIEW_ACCEPTANCE_CONTEXT===undefined&&env.MEM9_PREVIEW_RUNTIME_NONCE===undefined)return;
  if(!isConsolidationPreview(stage)||env.MEM9_PRODUCTION_RUNTIME_MODE!=='active')throw Error('InvalidPreviewContext');
  return validatePreviewContext({kind:env.MEM9_PREVIEW_ACCEPTANCE_CONTEXT,runtimeNonce:env.MEM9_PREVIEW_RUNTIME_NONCE});
}
export function previewGeneration(stage,env=process.env){
  if(!isConsolidationPreview(stage)||!/^[a-f0-9]{40}$/.test(env.MEM9_DEPLOY_COMMIT||'')||
    !/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ID||'')||!/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ATTEMPT||''))throw Error('InvalidPreviewGeneration');
  const base=hash([stage,env.MEM9_DEPLOY_COMMIT,env.GITHUB_RUN_ID,env.GITHUB_RUN_ATTEMPT].join('\n'));
  const context=previewAcceptanceContext(stage,env);
  return context?hash([base,context.kind,context.runtimeNonce].join('\n')):base;
}
export function previewUuid(generation,label){
  const s=hash(generation+'\n'+label);
  return `${s.slice(0,8)}-${s.slice(8,12)}-4${s.slice(13,16)}-a${s.slice(17,20)}-${s.slice(20,32)}`;
}
export function previewConfiguration(stage,generation,tenantSecret,postRuntimeContext){
  if(!isConsolidationPreview(stage)||!/^[0-9a-f]{64}$/.test(generation)||!tenantSecret)throw Error('InvalidPreviewConfiguration');
  const context=postRuntimeContext===undefined?undefined:validatePreviewContext(postRuntimeContext);
  const identity=context?[stage,context.kind,context.runtimeNonce,generation].join('\n'):stage;
  const prefix='mem9_preview_'+hash(identity).slice(0,12);
  return {version:context?2:1,stage,generation,database:prefix,
    tenantId:hash(context?tenantSecret+'\n'+identity:tenantSecret).slice(0,32),
    ...(context?{context,tenantName:'synthetic-consolidation-'+stage+'-'+hash(identity).slice(0,16)}:{}),
    usernames:Object.fromEntries(['planner','executor','backend','seed'].map(kind=>[kind,prefix+'_'+kind])),
    namespaces:['a','b','c'].map(label=>previewUuid(generation,'namespace-'+label))};
}
