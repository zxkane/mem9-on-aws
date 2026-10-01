import {GetParametersCommand,PutParameterCommand,DeleteParameterCommand} from '@aws-sdk/client-ssm';
import {schemaAdministratorRole,rolloutStage} from './production-runtime-config.mjs';
import {setTimeout as delay} from 'node:timers/promises';

const send=(client,command)=>client.send(command,{abortSignal:AbortSignal.timeout(30000)});
const fail=code=>{throw Error(code);};

function administratorTarget(meta){
  if(!rolloutStage(meta.stage)||!/^\d{12}$/.test(meta.account??'')||!/^[-a-z0-9]+$/.test(meta.region??''))fail('InvalidAdministratorRecoveryTarget');
  const prefix=`arn:aws:ssm:${meta.region}:${meta.account}:parameter/mem9-on-aws/${meta.stage}/runtime/`;
  if(meta.administratorCredential!==prefix+'schema-administrator-credential'||
    meta.administratorBackup!==prefix+'schema-administrator-backup')fail('InvalidAdministratorRecoveryTarget');
  return `/mem9-on-aws/${meta.stage}/runtime/schema-administrator-credential`;
}

function validateCredential(raw,stage){
  let value;try{value=JSON.parse(raw);}catch{fail('AdministratorBackupInvalid');}
  if(!value||Object.keys(value).sort().join()!=='password,salt,username'||value.username!==schemaAdministratorRole(stage)||
    !/^[A-Za-z0-9]{32,128}$/.test(value.password??'')||!/^[A-Za-z0-9]{16,128}$/.test(value.salt??''))fail('AdministratorBackupInvalid');
}

export function validateAdministratorLossIntent(meta,plan,intent){
  administratorTarget(meta);
  if(!/^pr-[1-9][0-9]*$/.test(meta.stage??'')||intent?.version!==1||intent.purpose!=='administrator-recovery-rehearsal'||
    intent.stage!==meta.stage||intent.nonce!==plan.nonce||!/^[a-f0-9]{32}$/.test(intent.nonce??'')||
    !/^[1-9][0-9]*$/.test(intent.sourceRunId??'')||intent.primary!==meta.administratorCredential||intent.backup!==meta.administratorBackup||
    !Number.isSafeInteger(intent.createdAt)||intent.createdAt<=0||intent.createdAt>Date.now()+30000||
    Object.keys(intent).sort().join()!=='backup,createdAt,nonce,primary,purpose,sourceRunId,stage,version')fail('AdministratorLossIntentMismatch');
  return intent;
}

export async function armAdministratorLoss(clients,meta,plan){
  if(!/^pr-[1-9][0-9]*$/.test(meta.stage??''))fail('PreviewAdministratorLossOnly');
  const intent=validateAdministratorLossIntent(meta,plan,{version:1,purpose:'administrator-recovery-rehearsal',stage:meta.stage,
    nonce:plan.nonce,sourceRunId:plan.sourceRunId,primary:meta.administratorCredential,backup:meta.administratorBackup,createdAt:Date.now()});
  const response=await send(clients.ssm,new GetParametersCommand({Names:[intent.primary,intent.backup],WithDecryption:true}));
  const values=new Map((response.Parameters??[]).map(p=>[p.ARN,p]));
  if(response.InvalidParameters?.length||response.Parameters?.length!==2||values.size!==2||
    values.get(intent.primary)?.Type!=='SecureString'||values.get(intent.backup)?.Type!=='SecureString'||
    values.get(intent.primary).Value!==values.get(intent.backup).Value)fail('AdministratorBackupDoesNotMatch');
  validateCredential(values.get(intent.backup).Value,meta.stage);
  // Durable intent precedes loss. A killed runner leaves enough information for
  // the independent receiver to restore before attempting any database task.
  const name=`/mem9-on-aws/${meta.stage}/runtime/administrator-recovery-intent`;
  try{await send(clients.ssm,new PutParameterCommand({Name:name,Type:'SecureString',Value:JSON.stringify(intent),Overwrite:false}));}
  catch(error){
    if(error.name!=='ParameterAlreadyExists')throw error;
    const prior=await send(clients.ssm,new GetParametersCommand({Names:[name],WithDecryption:true}));
    if(prior.InvalidParameters?.length||prior.Parameters?.length!==1)fail('AdministratorLossIntentMismatch');
    let value;try{value=JSON.parse(prior.Parameters[0].Value);}catch{fail('AdministratorLossIntentMismatch');}
    validateAdministratorLossIntent(meta,plan,value);
  }
  return intent;
}

export async function deletePreviewAdministrator(clients,meta,plan,intent){
  validateAdministratorLossIntent(meta,plan,intent);
  await send(clients.ssm,new DeleteParameterCommand({Name:`/mem9-on-aws/${meta.stage}/runtime/schema-administrator-credential`}));
}

export function administratorLossDeadlines(deadlineMs,now=Date.now()){
  const lossDeadline=deadlineMs-20*60000,restoreDeadline=deadlineMs-15*60000;
  if(!Number.isSafeInteger(deadlineMs)||now+60000>=lossDeadline)fail('AdministratorLossDeadline');
  return {lossDeadline,restoreDeadline};
}

// Only the trusted coordinator reads the backup. Workload tasks continue to
// receive their existing primary references and never gain a backup reader.
export async function restoreMissingAdministrator(clients,meta,{sleep=delay,now=Date.now,deadlineMs=Infinity}={}){
  const name=administratorTarget(meta);
  const primary=await send(clients.ssm,new GetParametersCommand({Names:[meta.administratorCredential],WithDecryption:false}));
  if(primary.Parameters?.length===1&&!primary.InvalidParameters?.length){
    if(primary.Parameters[0].ARN!==meta.administratorCredential||primary.Parameters[0].Type!=='SecureString')fail('AdministratorPrimaryMismatch');
    return {restored:false};
  }
  if(primary.Parameters?.length||primary.InvalidParameters?.length!==1||![name,meta.administratorCredential].includes(primary.InvalidParameters[0]))fail('AdministratorPrimaryObservationFailed');
  const backup=await send(clients.ssm,new GetParametersCommand({Names:[meta.administratorBackup],WithDecryption:true}));
  const parameter=backup.Parameters?.[0];
  if(backup.InvalidParameters?.length||backup.Parameters?.length!==1||parameter.ARN!==meta.administratorBackup||parameter.Type!=='SecureString')fail('AdministratorBackupUnavailable');
  validateCredential(parameter.Value,meta.stage);
  // SSM requires at least 30 seconds between deletion and recreation. Starting
  // from observed absence also covers recovery with no trustworthy delete time.
  if(now()+30000>=deadlineMs)fail('AdministratorRecoveryDeadline');
  await sleep(30000);
  try{
    await send(clients.ssm,new PutParameterCommand({Name:name,Type:'SecureString',Value:parameter.Value,Overwrite:false,
      Tags:[{Key:'Project',Value:'mem9-on-aws'},{Key:'Stage',Value:meta.stage},{Key:'ManagedBy',Value:'sst'}]}));
  }catch(error){if(error.name!=='ParameterAlreadyExists')throw error;}
  const restored=await send(clients.ssm,new GetParametersCommand({Names:[meta.administratorCredential],WithDecryption:true}));
  const actual=restored.Parameters?.[0];
  if(restored.InvalidParameters?.length||restored.Parameters?.length!==1||actual.ARN!==meta.administratorCredential||
    actual.Type!=='SecureString'||actual.Value!==parameter.Value)fail('AdministratorRecoveryReadbackMismatch');
  return {restored:true};
}
