import {describe,it,expect} from 'vitest';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {previewBootstrapRegistration,previewRegistrationFromProviderArgs,buildNonrootPreviewPurposeMap,
 selectNonrootPreviewPurpose,verifyNonrootPreviewPurposeReadback,verifyPreviewRegistrationReadback,
 previewBootstrapPurposeForOperation,validateNonrootPreviewOverrides,buildNonrootPreviewLaunchInventory} from './lib/nonroot-preview-source.mjs';
const scope={stage:'pr-7',account:'123456789012',region:'ap-northeast-1',sourceTree:'a'.repeat(40)};
const family='mem9-on-aws-pr-7-Cluster-example-Mem9Bootstrap';
const role='arn:aws:iam::'+scope.account+':role/mem9-on-aws-pr-7-';
const arn=revision=>'arn:aws:ecs:'+scope.region+':'+scope.account+':task-definition/'+family+':'+revision;
function fixture(){
 const base={family,networkMode:'awsvpc',requiresCompatibilities:['FARGATE'],runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'},
  cpu:'256',memory:'512',taskRoleArn:role+'Task',executionRoleArn:role+'Execution',volumes:[],placementConstraints:[],
  containerDefinitions:[{name:'Mem9Bootstrap',image:'example.com/bootstrap@sha256:'+'a'.repeat(64),
   environment:[{name:'MEM9_STAGE',value:scope.stage},{name:'MEM9_RUNTIME_BOOTSTRAP_VERSION',value:'1'}],
   secrets:[{name:'MEM9_DB_SECRET',valueFrom:'arn:aws:ssm:'+scope.region+':'+scope.account+':parameter/mem9-on-aws/pr-7/db'}],
   linuxParameters:{initProcessEnabled:true},futureContainerSetting:{retained:true}}],tags:[{key:'Stage',value:scope.stage}]};
 const purposes=['bootstrap-runtime-bootstrap','bootstrap-runtime-verify','bootstrap-admin-probe'];
 const records=purposes.map((purpose,index)=>{
  const registration=previewBootstrapRegistration(base,purpose,scope),{tags,...material}=registration;
  return {purpose,registration,observation:{taskDefinition:{...material,taskDefinitionArn:arn(index+1),revision:index+1,status:'ACTIVE',
   registeredAt:'2026-10-08T00:00:00.000Z',registeredBy:'arn:aws:sts::'+scope.account+':assumed-role/preview/session',
   requiresAttributes:[{name:'ecs.capability.task-eni'}],compatibilities:['EC2','FARGATE']},tags}};
 });
 return {scope,defaultPurpose:purposes[0],records};
}
describe('source-bound fixed preview purpose revisions',()=>{
 it('produces separate exact revisions in one family while preserving roles/secrets and unrelated fields',()=>{
  const f=fixture(),map=buildNonrootPreviewPurposeMap(f);expect(map.bindings.map(b=>b.taskDefinitionArn)).toEqual([arn(1),arn(2),arn(3)]);
  for(const [index,r]of f.records.entries()){
   const c=r.registration.containerDefinitions[0];expect(c.entryPoint.at(-1)).toBe(r.purpose);expect(c.command).toEqual([]);
   expect(c.user).toBe('1000:1000');expect(c.linuxParameters).toEqual({initProcessEnabled:true,capabilities:{drop:['ALL']}});
   expect(c.futureContainerSetting).toEqual({retained:true});expect(r.registration.taskRoleArn).toBe(role+'Task');
   expect(c.secrets).toEqual(f.records[0].registration.containerDefinitions[0].secrets);
   expect(selectNonrootPreviewPurpose(map,r.purpose,scope).taskDefinitionArn).toBe(arn(index+1));
   expect(verifyNonrootPreviewPurposeReadback(map,r.purpose,r.observation,scope)).toEqual(r.observation);
  }
 });
 it.each([
  ['one revision reused for another purpose',m=>m.bindings[1].taskDefinitionArn=m.bindings[0].taskDefinitionArn],
  ['missing requested purpose',m=>m.bindings.pop()],
  ['production scope',m=>m.stage='prod'],
  ['another family',m=>m.bindings[0].taskDefinitionArn=arn(1).replace('Mem9Bootstrap','Other')],
  ['unversioned legacy ARN',m=>m.version=undefined],
  ['future unknown field',m=>m.allowLegacy=true],
  ['substituted source tree',m=>m.sourceTree='b'.repeat(40)],
 ])('rejects %s',(_label,change)=>{const map=structuredClone(buildNonrootPreviewPurposeMap(fixture()));change(map);expect(()=>selectNonrootPreviewPurpose(map,'bootstrap-admin-probe',scope)).toThrow();});
 it.each([
  ['purpose on fixed entrypoint',d=>d.taskDefinition.containerDefinitions[0].entryPoint[5]='bootstrap-runtime-verify'],
  ['operation environment',d=>d.taskDefinition.containerDefinitions[0].environment.find(e=>e.name==='MEM9_BOOTSTRAP_OPERATION').value='runtime-verify'],
  ['UID',d=>d.taskDefinition.containerDefinitions[0].user='root'],
  ['capabilities',d=>d.taskDefinition.containerDefinitions[0].linuxParameters.capabilities.add=['SYS_ADMIN']],
  ['secret binding',d=>d.taskDefinition.containerDefinitions[0].secrets[0].valueFrom+='-other'],
  ['task role',d=>d.taskDefinition.taskRoleArn+='-other'],
  ['unknown container field',d=>d.taskDefinition.containerDefinitions[0].futureContainerSetting.retained=false],
  ['requiresAttributes',d=>d.taskDefinition.requiresAttributes.push({name:'unreviewed'})],
  ['compatibilities',d=>d.taskDefinition.compatibilities.pop()],
  ['tags',d=>d.tags[0].value='prod'],
  ['unknown response field',d=>d.taskDefinition.futureField=true],
 ])('rejects changed full readback: %s',(_label,change)=>{const f=fixture(),map=buildNonrootPreviewPurposeMap(f),d=structuredClone(f.records[0].observation);change(d);expect(()=>verifyNonrootPreviewPurposeReadback(map,f.defaultPurpose,d,scope)).toThrow();});
 it('rejects provider-readback differences before publishing a map',()=>{
  const f=fixture(),r=f.records[0];r.observation.taskDefinition.cpu='512';expect(()=>buildNonrootPreviewPurposeMap(f)).toThrow();
  expect(()=>verifyPreviewRegistrationReadback({},r.observation)).toThrow();
 });
 it('requires exact provider options and retains complete registration material',()=>{
  const r=fixture().records[0].registration,args={...r,trackLatest:false,skipDestroy:true,containerDefinitions:JSON.stringify(r.containerDefinitions),tags:{Stage:scope.stage}};
  expect(previewRegistrationFromProviderArgs(args)).toEqual(r);
  for(const change of [a=>a.trackLatest=true,a=>a.futureProviderField=true,a=>a.skipDestroy=false]){const a=structuredClone(args);change(a);expect(()=>previewRegistrationFromProviderArgs(a)).toThrow();}
 });
 it('archives actual source-bound entries with a separately supplied test reference',()=>{
  const f=fixture(),tests={bytesHash:'a'.repeat(64),canonicalHash:'b'.repeat(64),bytesLength:2},a=buildNonrootPreviewLaunchInventory(f,tests);
  expect(a.inventory.sourceTree).toBe(scope.sourceTree);expect(a.inventory.entries.canonicalHash).toBe(hash(JSON.parse(a.entriesBytes)));
  expect(a.inventory.tests).toEqual(tests);expect(a.inventory).not.toHaveProperty('authorized');
 });
 it('supports only reviewed finite operation names',()=>{
  expect(previewBootstrapPurposeForOperation('runtime-verify')).toBe('bootstrap-runtime-verify');
  expect(previewBootstrapPurposeForOperation(null)).toBe('bootstrap-schema-seed');
  for(const op of ['production-runtime','namespace-reset','arbitrary'])expect(()=>previewBootstrapPurposeForOperation(op)).toThrow();
 });
 it('forbids command and purpose changes even when an override is empty',()=>{
  const now=1800000000000,overrides={containerOverrides:[{name:'Mem9Bootstrap',environment:[
   {name:'MEM9_BOOTSTRAP_OPERATION',value:'runtime-verify'},
   {name:'MEM9_RUNTIME_INVOCATION',value:'a'.repeat(32)},{name:'MEM9_RUNTIME_BOOTSTRAP_DEADLINE',value:String(now+60000)}]}]};
  expect(validateNonrootPreviewOverrides('bootstrap-runtime-verify',overrides,{now})).toEqual(overrides);
  for(const change of [o=>o.containerOverrides[0].command=[],o=>o.containerOverrides[0].environment[0].value='runtime-bootstrap',
   o=>o.taskRoleArn=role+'Other',o=>o.containerOverrides[0].environment.push({name:'NODE_OPTIONS',value:''}),
   o=>o.containerOverrides[0].environment[2].value=String(now-1)]){
   const o=structuredClone(overrides);change(o);expect(()=>validateNonrootPreviewOverrides('bootstrap-runtime-verify',o,{now})).toThrow();
  }
 });
});
