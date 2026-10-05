import {createHash} from 'node:crypto';

const fail=()=>{throw Error('ArchiveChangeSetInvalid');};
const object=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const canonical=v=>Array.isArray(v)?v.map(canonical):object(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;
export const archiveChangeSetHash=value=>createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
export function archiveStackSettings(value){
 const tags=value.Tags??[],notifications=value.NotificationARNs??[],rollback=value.RollbackConfiguration??{};
 if(!Array.isArray(tags)||tags.some(t=>!t||typeof t.Key!=='string'||typeof t.Value!=='string')||new Set(tags.map(t=>t.Key)).size!==tags.length||
  !Array.isArray(notifications)||notifications.some(v=>typeof v!=='string')||new Set(notifications).size!==notifications.length||!object(rollback))fail();
 const triggers=rollback.RollbackTriggers??[],minutes=rollback.MonitoringTimeInMinutes??0;
 if(Object.keys(rollback).some(k=>!['RollbackTriggers','MonitoringTimeInMinutes'].includes(k))||!Array.isArray(triggers)||
  triggers.some(v=>!v||typeof v.Arn!=='string'||typeof v.Type!=='string')||new Set(triggers.map(v=>v.Arn)).size!==triggers.length||!Number.isSafeInteger(minutes)||minutes<0)fail();
 return {Tags:tags.map(({Key,Value})=>({Key,Value})).sort((a,b)=>a.Key.localeCompare(b.Key)),NotificationARNs:[...notifications].sort(),
  RollbackConfiguration:{RollbackTriggers:triggers.map(({Arn,Type})=>({Arn,Type})).sort((a,b)=>a.Arn.localeCompare(b.Arn)),MonitoringTimeInMinutes:minutes}};
}

export function archiveStackIdentity(stack,{account,region,bucket}){
 if(!stack||!['CREATE_COMPLETE','UPDATE_COMPLETE','UPDATE_ROLLBACK_COMPLETE'].includes(stack.StackStatus)||
    !/^[A-Za-z][A-Za-z0-9-]{0,127}$/.test(stack.StackName??'')||
    !stack.StackId?.startsWith(`arn:aws:cloudformation:${region}:${account}:stack/${stack.StackName}/`)||
    stack.ParentId||stack.RootId||stack.DeletionTime)fail();
 const parameters=archiveParameters(stack.Parameters);
 if(parameters.find(p=>p.ParameterKey==='DecisionArtifactBucketName')?.ParameterValue!==bucket||
    parameters.find(p=>p.ParameterKey==='ProjectName')?.ParameterValue!=='mem9-on-aws')fail();
 if(stack.RoleARN!==undefined&&!stack.RoleARN.startsWith(`arn:aws:iam::${account}:role/`))fail();
 return {StackId:stack.StackId,StackName:stack.StackName,Parameters:parameters,RoleARN:stack.RoleARN??null,...archiveStackSettings(stack),
  CreationTime:stack.CreationTime,LastUpdatedTime:stack.LastUpdatedTime??null};
}
export function archiveParameters(values){
 if(!Array.isArray(values)||values.length!==2||new Set(values.map(p=>p?.ParameterKey)).size!==2||
    values.some(p=>!['DecisionArtifactBucketName','ProjectName'].includes(p?.ParameterKey)||typeof p.ParameterValue!=='string'))fail();
 return values.map(({ParameterKey,ParameterValue})=>({ParameterKey,ParameterValue})).sort((a,b)=>a.ParameterKey.localeCompare(b.ParameterKey));
}

/** Every proposed resource change must be the existing bucket policy's
 * document. The caller independently verifies the uploaded template bytes
 * and pre-deployment validation events before this is executable evidence. */
export function verifyArchiveChangeSet(value,{account,region,stackId,stackName,bucket,changeSetName,parameters}){
 if(!value||value.Status!=='CREATE_COMPLETE'||value.ExecutionStatus!=='AVAILABLE'||value.NextToken||
    value.StackId!==stackId||value.StackName!==stackName||value.ChangeSetName!==changeSetName||
    !value.ChangeSetId?.startsWith(`arn:aws:cloudformation:${region}:${account}:changeSet/${changeSetName}/`)||
    value.ParentChangeSetId||value.RootChangeSetId||value.IncludeNestedStacks===true||value.ImportExistingResources===true||
    value.Capabilities?.length||!Array.isArray(value.Changes)||value.Changes.length!==1)fail();
 const actualParameters=archiveParameters(value.Parameters);
 if(archiveChangeSetHash(actualParameters)!==archiveChangeSetHash(archiveParameters(parameters)))fail();
 const change=value.Changes[0],resource=change?.ResourceChange;
 if(change.Type!=='Resource'||!resource||resource.Action!=='Modify'||resource.LogicalResourceId!=='DecisionArtifactBucketPolicy'||
    resource.PhysicalResourceId!==bucket||resource.ResourceType!=='AWS::S3::BucketPolicy'||resource.Replacement!=='False'||
    !Array.isArray(resource.Scope)||resource.Scope.length!==1||resource.Scope[0]!=='Properties'||
    !Array.isArray(resource.Details)||!resource.Details.length)fail();
 for(const detail of resource.Details){
  if(!['Static','Dynamic'].includes(detail.Evaluation)||detail.Target?.Attribute!=='Properties'||
    detail.Target.Name!=='PolicyDocument'||detail.Target.RequiresRecreation!=='Never')fail();
 }
 return {changeSetId:value.ChangeSetId,stackId,parameters:actualParameters,changes:value.Changes};
}
export function verifyArchiveValidationEvents(value){
 if(!value||!Array.isArray(value.OperationEvents)||value.NextToken)fail();
 for(const event of value.OperationEvents){
  if(!object(event)||typeof event.EventType!=='string'||event.EventType.endsWith('_ERROR'))fail();
  for(const field of ['ValidationStatus','HookStatus','OperationStatus','ResourceStatus']){
   if(event[field]!==undefined&&(typeof event[field]!=='string'||/FAILED|ERROR|ROLLBACK|CANCEL|TIMED_OUT/.test(event[field])))fail();
  }
 }
 return archiveChangeSetHash(value.OperationEvents);
}
