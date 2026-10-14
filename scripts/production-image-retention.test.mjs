import {describe,it,expect} from 'vitest';
import {readFileSync} from 'node:fs';
import {parseRetentionTemplate,verifyRetentionTemplateChange,prepareRetentionTemplate,verifyRetentionChangeSet,lifecyclePolicyAbsent,RETENTION_REPOSITORIES} from './lib/production-image-retention.mjs';

const after=parseRetentionTemplate(readFileSync(new URL('../infra/cloudformation/ecr-repositories.yaml',import.meta.url),'utf8'));
const before=()=>{const value=structuredClone(after);for(const key of Object.keys(RETENTION_REPOSITORIES))value.Resources[key].Properties.LifecyclePolicy={LifecyclePolicyText:'{"rules":[]}'};return value;};
const names=Object.fromEntries(Object.entries(RETENTION_REPOSITORIES).map(([key,name])=>[key,'mem9-on-aws/'+name]));
const stackId='arn:aws:cloudformation:ap-northeast-1:123456789012:stack/example/fixture',changeSetId='arn:aws:cloudformation:ap-northeast-1:123456789012:changeSet/example/fixture';
const changes=()=>({StackId:stackId,ChangeSetId:changeSetId,Status:'CREATE_COMPLETE',ExecutionStatus:'AVAILABLE',Changes:Object.keys(names).map(key=>({Type:'Resource',ResourceChange:{LogicalResourceId:key,ResourceType:'AWS::ECR::Repository',Action:'Modify',PhysicalResourceId:names[key],Replacement:'False',Scope:['Properties'],Details:[{Target:{Attribute:'Properties',Name:'LifecyclePolicy',RequiresRecreation:'Never'},Evaluation:'Static',ChangeSource:'DirectModification'}]}}))});
describe('bounded DATA repository retention update',()=>{
 it('permits only three lifecycle removals and preserves all five other repositories',()=>{
  expect(verifyRetentionTemplateChange(before(),after).logicalIds).toHaveLength(3);
  for(const key of ['BootstrapRepo','PreviewMnemoServerRepo','PreviewQwen3EmbedRepo','PreviewLlmProxyRepo','PreviewBootstrapRepo'])expect(after.Resources[key].Properties.LifecyclePolicy).toBeDefined();
 });
 it('preserves the narrow observed description encoding without rewriting source identity',()=>{
  const prior=before();prior.Description=prior.Description.replaceAll('\u00a7','?');
  const prepared=prepareRetentionTemplate(prior,after);expect(prepared.template.Description).toBe(prior.Description);
  expect(prepared.metadataPreserved).toHaveLength(1);expect(prepared.sourceTemplateHash).not.toBe(prepared.afterHash);
  expect(verifyRetentionTemplateChange(prior,prepared.template).logicalIds).toHaveLength(3);
  expect(()=>prepareRetentionTemplate({...prior,Description:'unrelated'},after)).toThrow('ImageRetentionUnexpectedMetadata');
 });
 it.each([
  value=>{value.Resources.MnemoServerRepo.Properties.ImageTagMutability='IMMUTABLE';},
  value=>{delete value.Resources.BootstrapRepo.Properties.LifecyclePolicy;},
  value=>{value.Resources.MnemoServerRepo.DeletionPolicy='Delete';},
  value=>{value.Resources.MnemoServerRepo.Properties.RepositoryName='foreign';},
  value=>{value.Resources.Qwen3EmbedRepo.Properties.LifecyclePolicy={LifecyclePolicyText:'{}'};},
  value=>{value.Description='unreviewed metadata change';},
 ])('rejects every wider or incomplete template change',change=>{const value=structuredClone(after);change(value);expect(()=>verifyRetentionTemplateChange(before(),value)).toThrow();});
 it('verifies an exact UPDATE change set and rejects replacements, missing targets and extra properties',()=>{
  expect(verifyRetentionChangeSet(changes(),{stackId,changeSetId,repositoryNames:names}).logicalIds).toHaveLength(3);
  for(const mutate of [v=>{v.Changes[0].ResourceChange.Replacement='Conditional';},v=>{v.Changes.pop();},v=>{v.Changes[0].ResourceChange.Action='Add';},
   v=>{v.Changes[0].ResourceChange.Details[0].Target.Name='ImageTagMutability';},v=>{v.StackId+='-foreign';}]){
   const value=changes();mutate(value);expect(()=>verifyRetentionChangeSet(value,{stackId,changeSetId,repositoryNames:names})).toThrow();
  }
  const missing=changes();delete missing.StackId;expect(()=>verifyRetentionChangeSet(missing,{changeSetId,repositoryNames:names})).toThrow();
  const foreign=changes(),wrong={...names,MnemoServerRepo:'foreign/mnemo-server'};foreign.Changes[0].ResourceChange.PhysicalResourceId=wrong.MnemoServerRepo;
  expect(()=>verifyRetentionChangeSet(foreign,{stackId,changeSetId,repositoryNames:wrong})).toThrow();
 });
 it('distinguishes authenticated policy absence from denied access and a missing repository',()=>{
  const expected={account:'123456789012',region:'ap-northeast-1',name:'mem9-on-aws/mnemo-server'},repository={registryId:expected.account,repositoryName:expected.name,repositoryArn:'arn:aws:ecr:ap-northeast-1:123456789012:repository/'+expected.name};
  const error={name:'LifecyclePolicyNotFoundException',$metadata:{httpStatusCode:400,requestId:'synthetic-request'}};
  expect(lifecyclePolicyAbsent(error,repository,expected).status).toBe('absent');
  for(const name of ['RepositoryNotFoundException','AccessDeniedException','ServerException'])expect(()=>lifecyclePolicyAbsent({...error,name},repository,expected)).toThrow();
  expect(()=>lifecyclePolicyAbsent(error,{...repository,registryId:'0'.repeat(12)},expected)).toThrow();
 });
});
