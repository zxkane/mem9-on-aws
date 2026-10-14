import {it,expect} from 'vitest';
import {archiveStackIdentity,archiveStackSettings,verifyArchiveChangeSet,verifyArchiveValidationEvents} from './lib/authorization-archive-change-set.mjs';
const account='123456789012',region='ap-northeast-1',bucket='example-audit',stackName='decision-artifact-bucket-mem9-on-aws',changeSetName='archive-policy-test';
// Derive a distinct, valid-format account from the documentation-only fixture.
const foreignAccount=String(BigInt(account)+1n);
const stackId=`arn:aws:cloudformation:${region}:${account}:stack/${stackName}/test`,parameters=[{ParameterKey:'DecisionArtifactBucketName',ParameterValue:bucket},{ParameterKey:'ProjectName',ParameterValue:'mem9-on-aws'}];
const context={account,region,bucket,stackName,stackId,changeSetName,parameters};
const fixture=()=>({Status:'CREATE_COMPLETE',ExecutionStatus:'AVAILABLE',StackName:stackName,StackId:stackId,ChangeSetName:changeSetName,ChangeSetId:`arn:aws:cloudformation:${region}:${account}:changeSet/${changeSetName}/test`,Parameters:parameters,Capabilities:[],Changes:[{Type:'Resource',ResourceChange:{Action:'Modify',LogicalResourceId:'DecisionArtifactBucketPolicy',PhysicalResourceId:bucket,ResourceType:'AWS::S3::BucketPolicy',Replacement:'False',Scope:['Properties'],Details:[{Evaluation:'Static',Target:{Attribute:'Properties',Name:'PolicyDocument',RequiresRecreation:'Never'}}]}}]});
it('accepts only the bound existing-policy document update',()=>{expect(verifyArchiveChangeSet(fixture(),context).changeSetId).toContain(changeSetName);});
for(const mutate of [v=>v.StackId+='other',v=>v.ChangeSetName+='other',v=>v.ChangeSetId=v.ChangeSetId.replace(account,foreignAccount),v=>v.NextToken='more',v=>v.ExecutionStatus='EXECUTE_COMPLETE',v=>v.Changes.push(v.Changes[0]),v=>v.Changes[0].ResourceChange.Action='Add',v=>v.Changes[0].ResourceChange.Replacement='True',v=>v.Changes[0].ResourceChange.PhysicalResourceId='other',v=>v.Changes[0].ResourceChange.LogicalResourceId='DecisionArtifactBucket',v=>v.Changes[0].ResourceChange.Scope.push('DeletionPolicy'),v=>v.Changes[0].ResourceChange.Details[0].Target.Name='Bucket',v=>v.Capabilities.push('CAPABILITY_IAM')])it('rejects unreviewed change '+mutate.toString(),()=>{const v=structuredClone(fixture());mutate(v);expect(()=>verifyArchiveChangeSet(v,context)).toThrow();});
it('rejects changed or duplicate parameter bindings',()=>{for(const list of [[parameters[0],parameters[0]],[...parameters,{ParameterKey:'extra',ParameterValue:'value'}],[{...parameters[0],ParameterValue:'other'},parameters[1]]])expect(()=>verifyArchiveChangeSet({...fixture(),Parameters:list},context)).toThrow();});
it('binds a complete same-account owner stack and preserves its execution role',()=>{
 const stack={StackName:stackName,StackId:stackId,StackStatus:'UPDATE_COMPLETE',Parameters:parameters,CreationTime:'2026-01-01T00:00:00Z'};
 expect(archiveStackIdentity(stack,context).StackId).toBe(stackId);
 expect(()=>archiveStackIdentity({...stack,StackStatus:'IMPORT_ROLLBACK_COMPLETE'},context)).toThrow();
 expect(()=>archiveStackIdentity({...stack,RoleARN:`arn:aws:iam::${foreignAccount}:role/foreign`},context)).toThrow();
});
it('requires complete validation-event coverage and rejects reported failures',()=>{
 expect(verifyArchiveValidationEvents({OperationEvents:[]})).toMatch(/^[a-f0-9]{64}$/);
 for(const events of [{NextToken:'more',OperationEvents:[]},{OperationEvents:[{EventType:'VALIDATION_ERROR'}]},{OperationEvents:[{ValidationStatus:'FAILED'}]},
  {OperationEvents:[{EventType:'HOOK_INVOCATION_ERROR'}]},
  {OperationEvents:[{EventType:'PROVISIONING_ERROR',ResourceStatus:'UPDATE_FAILED'}]},
  {OperationEvents:[{EventType:'STACK_EVENT',OperationType:'CREATE_CHANGESET',OperationStatus:'FAILED'}]},
  {OperationEvents:[{}]},{}])expect(()=>verifyArchiveValidationEvents(events)).toThrow();
});
it('preserves stack tags, notifications and rollback controls with unique keys',()=>{
 const values={Tags:[{Key:'Project',Value:'mem9-on-aws'}],NotificationARNs:['arn:aws:sns:ap-northeast-1:123456789012:fixture'],RollbackConfiguration:{MonitoringTimeInMinutes:5,RollbackTriggers:[]}};
 expect(archiveStackSettings(values)).toEqual(values);
 expect(()=>archiveStackSettings({...values,Tags:[values.Tags[0],values.Tags[0]]})).toThrow();
});
