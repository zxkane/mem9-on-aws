import {createHash} from 'node:crypto';

export const rolloutPhases=['prepared','maintenance','runtime_prepared','password_fenced','transferred','runtime_ready','retired','complete'];
export const rolloutStage=stage=>stage==='prod'||/^pr-[1-9][0-9]*$/.test(stage??'');
export function schemaAdministratorRole(stage){
  if(!rolloutStage(stage))throw Error('InvalidRolloutStage');
  return 'mem9_schema_'+createHash('sha256').update(stage).digest('hex').slice(0,12);
}

export function validateRolloutIdentity(value){
  const keys=['stage','database','databaseOid','writerEndpoint','clusterArn','legacyRoleOid','administratorRoleOid','runtimeRoleOid',
    'schemaDigest','operatorDigest','fallbackTaskDefinition','fallbackImageDigest','runtimeCredentialArn'];
  if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join()!==keys.sort().join()||
    !rolloutStage(value.stage)||!/^[a-zA-Z_][a-zA-Z0-9_]{0,62}$/.test(value.database??''))throw Error('InvalidRolloutIdentity');
  for(const key of keys.filter(key=>!key.endsWith('Oid')))if(typeof value[key]!=='string')throw Error('InvalidRolloutIdentity');
  const cluster=value.clusterArn?.match(/^arn:aws:ecs:([a-z0-9-]+):([0-9]{12}):cluster\/(mem9-on-aws-[A-Za-z0-9-]+)$/);
  if(!cluster||!cluster[3].startsWith('mem9-on-aws-'+value.stage+'-')||
    !/^[a-z0-9.-]{1,253}$/.test(value.writerEndpoint)||!value.writerEndpoint.startsWith('mem9-on-aws-'+value.stage+'-')||
    !value.writerEndpoint.endsWith('.'+cluster[1]+'.rds.amazonaws.com')||
    value.runtimeCredentialArn!==`arn:aws:ssm:${cluster[1]}:${cluster[2]}:parameter/mem9-on-aws/${value.stage}/runtime/database-credential`||
    !value.fallbackTaskDefinition?.startsWith(`arn:aws:ecs:${cluster[1]}:${cluster[2]}:task-definition/${cluster[3]}-Mem9RuntimeServer:`)||
    !/^[1-9][0-9]*$/.test(value.fallbackTaskDefinition.split('-Mem9RuntimeServer:')[1]??''))throw Error('InvalidRolloutIdentity');
  for(const key of ['databaseOid','legacyRoleOid','administratorRoleOid','runtimeRoleOid'])
    if(!Number.isInteger(value[key])||value[key]<1||value[key]>4294967295)throw Error('InvalidRolloutIdentity');
  if(new Set(['legacyRoleOid','administratorRoleOid','runtimeRoleOid'].map(key=>value[key])).size!==3)throw Error('InvalidRolloutIdentity');
  if(!/^[a-f0-9]{64}$/.test(value.schemaDigest??'')||!/^[a-f0-9]{64}$/.test(value.operatorDigest??'')||
    !/^sha256:[a-f0-9]{64}$/.test(value.fallbackImageDigest??''))throw Error('InvalidRolloutIdentity');
  return structuredClone(value);
}

export function assertRolloutClaim(state,claim,{recovery=false,now=Date.now()}={}){
  if(!state||!claim||state.operation_nonce!==claim.nonce||state.epoch!==claim.epoch||
    !/^[a-f0-9]{32}$/.test(claim.nonce??'')||!Number.isSafeInteger(claim.epoch)||claim.epoch<1||
    !rolloutPhases.includes(state.phase)||!['running','recovering','restored'].includes(state.status))throw Error('StaleRolloutClaim');
  if(!recovery&&(state.status!=='running'||state.phase==='complete'||
    (state.deadline_ms!==null&&now>=state.deadline_ms)||
    (state.started_ms!==null&&state.started_ms!==undefined&&rolloutPhases.indexOf(state.phase)<rolloutPhases.indexOf('runtime_ready')&&
      now>=state.started_ms+3600000)))throw Error('RolloutAdmissionClosed');
}
