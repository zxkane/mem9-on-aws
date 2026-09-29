import {createHash} from 'node:crypto';

const hash=value=>createHash('sha256').update(value).digest('hex');
export const isConsolidationPreview=stage=>/^pr-[1-9][0-9]*$/.test(stage||'');
export function previewGeneration(stage,env=process.env){
  if(!isConsolidationPreview(stage)||!/^[a-f0-9]{40}$/.test(env.MEM9_DEPLOY_COMMIT||'')||
    !/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ID||'')||!/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ATTEMPT||''))throw Error('InvalidPreviewGeneration');
  return hash([stage,env.MEM9_DEPLOY_COMMIT,env.GITHUB_RUN_ID,env.GITHUB_RUN_ATTEMPT].join('\n'));
}
export function previewUuid(generation,label){
  const s=hash(generation+'\n'+label);
  return `${s.slice(0,8)}-${s.slice(8,12)}-4${s.slice(13,16)}-a${s.slice(17,20)}-${s.slice(20,32)}`;
}
export function previewConfiguration(stage,generation,tenantSecret){
  if(!isConsolidationPreview(stage)||!/^[0-9a-f]{64}$/.test(generation)||!tenantSecret)throw Error('InvalidPreviewConfiguration');
  const prefix='mem9_preview_'+hash(stage).slice(0,12);
  return {version:1,stage,generation,database:prefix,tenantId:hash(tenantSecret).slice(0,32),
    usernames:Object.fromEntries(['planner','executor','backend','seed'].map(kind=>[kind,prefix+'_'+kind])),
    namespaces:['a','b','c'].map(label=>previewUuid(generation,'namespace-'+label))};
}
