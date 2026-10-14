import {parseDocument} from 'yaml';
import {copyNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';

export const RETENTION_REPOSITORIES=Object.freeze({MnemoServerRepo:'mnemo-server',Qwen3EmbedRepo:'qwen3-embed',LlmProxyRepo:'llm-proxy'});
const allRepositories=Object.freeze({...RETENTION_REPOSITORIES,BootstrapRepo:'bootstrap',PreviewMnemoServerRepo:'mnemo-server',PreviewQwen3EmbedRepo:'qwen3-embed',PreviewLlmProxyRepo:'llm-proxy',PreviewBootstrapRepo:'bootstrap'});
const need=(value,code='ImageRetentionInvalid')=>{if(!value)throw Error(code);};
const same=(a,b,code)=>need(hash(a)===hash(b),code);

/** Parse only the owning repository template's supported intrinsic syntax.
 * Comments never supply instructions or operation approval. */
export function parseRetentionTemplate(raw){
 need(typeof raw==='string'&&Buffer.byteLength(raw)<=51200,'ImageRetentionTemplateSize');
 const tags=[{tag:'!Ref',resolve:value=>({Ref:value})},{tag:'!Sub',resolve:value=>({'Fn::Sub':value})},
  {tag:'!GetAtt',resolve:value=>({'Fn::GetAtt':value.split('.')})}];
 const doc=parseDocument(raw,{customTags:tags,uniqueKeys:true});need(!doc.errors.length&&!doc.warnings.length,'ImageRetentionTemplateSyntax');
 return copyNonrootJson(doc.toJS({maxAliasCount:0}));
}

function structure(value){
 const template=copyNonrootJson(value),resources=template.Resources;
 need(resources&&Object.keys(resources).sort().join()===Object.keys(allRepositories).sort().join(),'ImageRetentionResourceSet');
 for(const [name,component]of Object.entries(allRepositories)){
  const resource=resources[name],preview=name.startsWith('Preview');
  need(resource?.Type==='AWS::ECR::Repository'&&resource.UpdateReplacePolicy==='Retain'&&resource.DeletionPolicy===(preview?'RetainExceptOnCreate':'Retain'),'ImageRetentionOwnership');
  same(resource.Properties?.RepositoryName,{'Fn::Sub':'${'+(preview?'PreviewProjectName':'ProjectName')+'}/'+component},'ImageRetentionRepositoryName');
  need(resource.Properties?.EncryptionConfiguration?.EncryptionType==='AES256','ImageRetentionEncryption');
 }
 return template;
}

/** A data-only comparison, not permission to submit or execute a change set. */
export function verifyRetentionTemplateChange(beforeValue,afterValue){
 const before=structure(beforeValue),after=structure(afterValue),wanted=structuredClone(before);
 for(const key of Object.keys(RETENTION_REPOSITORIES)){
  need(Object.hasOwn(before.Resources[key].Properties,'LifecyclePolicy'),'ImageRetentionPriorPolicyRequired');
  delete wanted.Resources[key].Properties.LifecyclePolicy;
 }
 same(wanted,after,'ImageRetentionUnexpectedTemplateChange');
 return Object.freeze({beforeHash:hash(before),afterHash:hash(after),logicalIds:Object.freeze(Object.keys(RETENTION_REPOSITORIES).sort())});
}

/** Preserve observed non-executable stack metadata. Some historical uploads
 * contain ASCII question marks at the section-sign positions; this is the
 * only accepted source/execution representation difference, recorded honestly. */
export function prepareRetentionTemplate(beforeValue,candidateValue){
 const before=structure(beforeValue),candidate=structure(candidateValue),template=structuredClone(candidate),metadataPreserved=[];
 if(before.Description!==candidate.Description){
  need(typeof before.Description==='string'&&typeof candidate.Description==='string'&&candidate.Description.includes('\u00a7')&&
   candidate.Description.replaceAll('\u00a7','?')===before.Description,'ImageRetentionUnexpectedMetadata');
  template.Description=before.Description;
  metadataPreserved.push({path:'Description',sourceHash:hash(candidate.Description),executionHash:hash(before.Description)});
 }
 const verified=verifyRetentionTemplateChange(before,template);
 return Object.freeze({template:copyNonrootJson(template),sourceTemplateHash:hash(candidate),...verified,metadataPreserved:copyNonrootJson(metadataPreserved)});
}

export function verifyRetentionChangeSet(value,{stackId,changeSetId,repositoryNames}){
 const change=copyNonrootJson(value);
 const stack=/^arn:aws:cloudformation:([a-z0-9-]+):([0-9]{12}):stack\/[A-Za-z][A-Za-z0-9-]{0,127}\/[A-Za-z0-9-]{1,128}$/.exec(stackId??'');
 const selected=/^arn:aws:cloudformation:([a-z0-9-]+):([0-9]{12}):changeSet\/[A-Za-z][A-Za-z0-9-]{0,127}\/[A-Za-z0-9-]{1,128}$/.exec(changeSetId??'');
 need(stack&&selected&&stack[1]===selected[1]&&stack[2]===selected[2],'ImageRetentionChangeSetIdentity');
 need(change.StackId===stackId&&change.ChangeSetId===changeSetId&&change.Status==='CREATE_COMPLETE'&&change.ExecutionStatus==='AVAILABLE'&&
  !change.ParentChangeSetId&&change.IncludeNestedStacks!==true,'ImageRetentionChangeSetIdentity');
 need(repositoryNames&&Object.keys(repositoryNames).sort().join()===Object.keys(RETENTION_REPOSITORIES).sort().join(),'ImageRetentionRepositorySet');
 for(const [key,name]of Object.entries(RETENTION_REPOSITORIES))need(repositoryNames[key]==='mem9-on-aws/'+name,'ImageRetentionRepositorySet');
 need(Array.isArray(change.Changes)&&change.Changes.length===3,'ImageRetentionChangeSetScope');
 const seen=new Set();
 for(const row of change.Changes){
  const resource=row?.ResourceChange,key=resource?.LogicalResourceId;
  need(row.Type==='Resource'&&Object.hasOwn(RETENTION_REPOSITORIES,key)&&!seen.has(key)&&resource.Action==='Modify'&&resource.ResourceType==='AWS::ECR::Repository'&&
   resource.PhysicalResourceId===repositoryNames[key]&&resource.Replacement==='False','ImageRetentionReplacementForbidden');seen.add(key);
  same(resource.Scope,['Properties'],'ImageRetentionChangeSetScope');
  need(Array.isArray(resource.Details)&&resource.Details.length>0&&resource.Details.every(detail=>detail.Target?.Attribute==='Properties'&&
   detail.Target.Name==='LifecyclePolicy'&&detail.Target.RequiresRecreation==='Never'&&detail.Evaluation==='Static'&&detail.ChangeSource==='DirectModification'),'ImageRetentionPropertyScope');
 }
 return Object.freeze({stackId,changeSetId,changeSetHash:hash(change),logicalIds:Object.freeze([...seen].sort())});
}

/** Call with the actual SDK exception for the exact signed repository request.
 * Existence/identity must already have been established by DescribeRepositories. */
export function lifecyclePolicyAbsent(error,repository,{account,region,name}){
 need(/^[0-9]{12}$/.test(account??'')&&/^[a-z]{2}(?:-[a-z]+)+-[0-9]+$/.test(region??'')&&Object.values(RETENTION_REPOSITORIES).some(component=>name==='mem9-on-aws/'+component),'ImageRetentionRepositoryIdentity');
 need(repository?.registryId===account&&repository.repositoryName===name&&repository.repositoryArn===`arn:aws:ecr:${region}:${account}:repository/${name}`,'ImageRetentionRepositoryIdentity');
 need(error?.name==='LifecyclePolicyNotFoundException'&&error.$metadata?.httpStatusCode===400&&
  typeof error.$metadata.requestId==='string'&&/^[A-Za-z0-9-]{1,160}$/.test(error.$metadata.requestId),'ImageRetentionPolicyAbsenceUnproven');
 return Object.freeze({registryId:account,repositoryName:name,requestId:error.$metadata.requestId,status:'absent'});
}
