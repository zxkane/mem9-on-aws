import {parseDocument} from 'yaml';
import {readControlSourceFile} from './production-control-source.mjs';
import {inspectCarrierBeforeCopyTemplate,CARRIER_CI_JOB,carrierHash as hash} from './ci-carrier-before-copy.mjs';
const contexts=new WeakMap(),need=(v,c)=>{if(!v)throw Error(c);};
/** Source membership and exact reviewed job/role definitions. No scope or
 * permission is obtained merely from a name or an ARN-shaped string. */
export async function verifyCarrierCiSource(template,sourceContext){
 const t=inspectCarrierBeforeCopyTemplate(template);need(sourceContext?.tree===t.source.candidateTree,'CarrierSourceTree');
 const workflow=await readControlSourceFile(sourceContext,CARRIER_CI_JOB.workflowPath),role=await readControlSourceFile(sourceContext,CARRIER_CI_JOB.roleSourcePath);
 const decode=bytes=>{const doc=parseDocument(new TextDecoder('utf-8',{fatal:true}).decode(bytes),{uniqueKeys:true,customTags:[{tag:'!Sub',resolve:v=>({'Fn::Sub':v})},{tag:'!Ref',resolve:v=>({Ref:v})},{tag:'!GetAtt',resolve:v=>({'Fn::GetAtt':v})}]});need(!doc.errors.length,'CarrierSourceYaml');return doc.toJS({maxAliasCount:0});};
 const w=decode(workflow.bytes),r=decode(role.bytes),job=w.jobs?.[CARRIER_CI_JOB.jobKey],resource=r.Resources?.[CARRIER_CI_JOB.roleResource];
 need(w.on&&Object.hasOwn(w.on,'workflow_dispatch')&&job?.name===CARRIER_CI_JOB.jobName&&job.environment==='preview-ci'&&hash(job)===t.source.jobDefinitionHash,'CarrierSourceJob');
 need(resource?.Type==='AWS::IAM::Role'&&resource.Properties?.RoleName?.['Fn::Sub']==='github-actions-${GitHubRepo}-preview'&&hash(resource)===t.source.roleDefinitionHash,'CarrierSourceRole');
 const handle=Object.freeze({kind:'carrier-ci-source'});contexts.set(handle,{templateHash:hash(t),tree:sourceContext.tree,workflowHash:workflow.file.sha256,roleHash:role.file.sha256});return handle;
}
export function inspectCarrierCiSource(handle,template){const v=contexts.get(handle);need(v&&v.templateHash===hash(inspectCarrierBeforeCopyTemplate(template)),'CarrierSourceContext');return Object.freeze({...v});}
