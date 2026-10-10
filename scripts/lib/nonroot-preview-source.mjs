/** Numeric-preview source construction and readback checks. Map inputs must be
 * obtained from the protected stage parameter and compared with independently
 * trusted checkout scope. A caller-supplied map/hash never grants authority. */
import {createHash} from 'node:crypto';
import {copyNonrootJson as copy,parseNonrootJson,nonrootHash as hash,inspectNonrootRecord} from './production-nonroot-contracts.mjs';
import {controlLaunchPolicy,NONROOT_FORBIDDEN_ENVIRONMENT} from './production-nonroot-launch.mjs';

const need=(ok,code='NonrootPreviewInvalid')=>{if(!ok)throw Error(code);};
const object=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const exact=(v,keys)=>need(object(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k)));
const same=(a,b)=>need(hash(a)===hash(b),'NonrootPreviewMismatch');
const h64=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const operationByPurpose=Object.freeze({
 'bootstrap-schema-seed':null,
 'bootstrap-runtime-bootstrap':'runtime-bootstrap',
 'bootstrap-runtime-verify':'runtime-verify',
 'bootstrap-admin-probe':'runtime-admin-probe',
 'bootstrap-admin-probe-cleanup':'runtime-admin-probe-cleanup',
 'preview-fixture-setup':'consolidation-preview-setup',
 'preview-fixture-pause':'consolidation-preview-pause',
 'preview-fixture-verify-planned':'consolidation-preview-verify-planned',
 'preview-fixture-verify-executed':'consolidation-preview-verify-executed',
 'preview-fixture-verify-repeated':'consolidation-preview-verify-repeated',
});
export const NONROOT_PREVIEW_BOOTSTRAP_PURPOSES=Object.freeze(Object.keys(operationByPurpose));
const purpose=v=>need(typeof v==='string'&&Object.hasOwn(operationByPurpose,v),'NonrootPreviewPurpose');
const scopeKeys=['stage','account','region','sourceTree'];
function checkedScope(value){
 const v=copy(value);exact(v,scopeKeys);
 need(/^pr-[1-9][0-9]*$/.test(v.stage)&&/^\d{12}$/.test(v.account)&&/^[a-z]{2}(?:-[a-z]+)+-\d$/.test(v.region)&&/^[a-f0-9]{40}$/.test(v.sourceTree));
 return v;
}
function familyScope(family,scope){
 need(typeof family==='string'&&family.startsWith('mem9-on-aws-'+scope.stage+'-')&&family.endsWith('-Mem9Bootstrap')&&/^[A-Za-z0-9_-]{1,255}$/.test(family));
}
export function previewBootstrapPurposeForOperation(operation){
 const found=Object.entries(operationByPurpose).find(([,value])=>value===operation);
 need(found,'NonrootPreviewPurpose');return found[0];
}
function environmentRows(rows){
 need(Array.isArray(rows));const names=new Set();
 for(const e of rows){exact(e,['name','value']);need(typeof e.name==='string'&&/^[A-Za-z_][A-Za-z0-9_]*$/.test(e.name)&&!names.has(e.name)&&typeof e.value==='string');
  need(!e.name.startsWith('LD_')&&!NONROOT_FORBIDDEN_ENVIRONMENT.includes(e.name),'NonrootPreviewPreload');names.add(e.name);}
 return Object.fromEntries(rows.map(e=>[e.name,e.value]));
}
function fixedContainer(container,selected,scope){
 purpose(selected);need(object(container)&&container.name==='Mem9Bootstrap');
 const env=environmentRows(container.environment??[]);
 need(env.MEM9_STAGE===scope.stage);
 need(!Object.hasOwn(container,'environmentFiles')&&!Object.hasOwn(container,'healthCheck'));
 for(const s of container.secrets??[]){exact(s,['name','valueFrom']);need(typeof s.name==='string'&&typeof s.valueFrom==='string'&&!s.name.startsWith('LD_')&&!NONROOT_FORBIDDEN_ENVIRONMENT.includes(s.name));}
 need(new Set((container.secrets??[]).map(s=>s.name)).size===(container.secrets??[]).length);
 const operation=operationByPurpose[selected];
 if(operation===null){need(!Object.hasOwn(env,'MEM9_BOOTSTRAP_OPERATION')&&!Object.hasOwn(env,'MEM9_RUNTIME_BOOTSTRAP_VERSION'));}
 else {need(env.MEM9_BOOTSTRAP_OPERATION===operation);if(selected.startsWith('bootstrap-'))need(env.MEM9_RUNTIME_BOOTSTRAP_VERSION==='1');}
 const expected=controlLaunchPolicy(selected,container);same(comparableContainer(container),comparableContainer(expected));
 return container;
}

/** Exact finite metadata delta; all roles, secret references and unrelated
 * registration fields are copied. The returned body is not deployment authority. */
export function previewBootstrapRegistration(original,selected,scopeValue){
 const scope=checkedScope(scopeValue);purpose(selected);
 const body=structuredClone(copy(original));need(object(body));familyScope(body.family,scope);
 need(body.containerDefinitions?.length===1&&body.containerDefinitions[0].name==='Mem9Bootstrap');
 body.containerDefinitions=[previewBootstrapContainer(body.containerDefinitions[0],selected,scope.stage)];
 return copy(body);
}
export function previewBootstrapContainer(original,selected,stage){
 need(typeof stage==='string'&&/^pr-[1-9][0-9]*$/.test(stage));purpose(selected);
 const c=structuredClone(copy(original));need(object(c)&&c.name==='Mem9Bootstrap');environmentRows(c.environment??[]);
 if(Object.hasOwn(c,'entrypoint')){need(!Object.hasOwn(c,'entryPoint'));c.entryPoint=c.entrypoint;delete c.entrypoint;}
 if(c.entryPoint!==undefined){
  const fixed=['/bin/setpriv','--no-new-privs','--','/usr/local/bin/node','/bootstrap/nonroot-dispatch.mjs'];
  need(hash(c.entryPoint)===hash(['/bootstrap/entrypoint.sh'])||c.entryPoint.length===6&&hash(c.entryPoint.slice(0,5))===hash(fixed)&&NONROOT_PREVIEW_BOOTSTRAP_PURPOSES.includes(c.entryPoint[5]));
 }
 if(c.command!==undefined)same(c.command,[]);
 const rows=c.environment??[];
 for(const e of rows){
  if(e.name==='MEM9_RUNTIME_BOOTSTRAP_VERSION')need(e.value==='1');
  if(e.name==='MEM9_BOOTSTRAP_OPERATION')need(Object.values(operationByPurpose).includes(e.value));
 }
 const operation=operationByPurpose[selected];
 const names=['MEM9_BOOTSTRAP_OPERATION','MEM9_RUNTIME_BOOTSTRAP_VERSION'];
 c.environment=rows.filter(e=>!names.includes(e.name));
 if(operation!==null)c.environment.push({name:'MEM9_BOOTSTRAP_OPERATION',value:operation});
 // Runtime/admin paths require this existing version marker; fixture paths
 // preserve it when present, while schema seed explicitly excludes it.
 if(selected.startsWith('bootstrap-')&&operation!==null||operation!==null&&rows.some(e=>e.name==='MEM9_RUNTIME_BOOTSTRAP_VERSION'))
  c.environment.push({name:'MEM9_RUNTIME_BOOTSTRAP_VERSION',value:'1'});
 const target=controlLaunchPolicy(selected,c);
 fixedContainer(target,selected,{stage});return target;
}

/** Only these provider-side options are outside RegisterTaskDefinition. They
 * are checked explicitly, never discarded as an arbitrary unknown field. */
const requestFields=Object.freeze(['family','taskRoleArn','executionRoleArn','networkMode','containerDefinitions','volumes','placementConstraints',
 'requiresCompatibilities','cpu','memory','tags','pidMode','ipcMode','proxyConfiguration','inferenceAccelerators','ephemeralStorage','runtimePlatform','enableFaultInjection']);
export function previewRegistrationFromProviderArgs(input){
 const args=copy(input);need(object(args)&&args.trackLatest===false);
 const body={};
 for(const [key,value]of Object.entries(args)){
  if(key==='trackLatest')continue;
  if(key==='skipDestroy'){need(value===true);continue;}
  need(requestFields.includes(key),'NonrootPreviewProviderField');
  if(key==='containerDefinitions')body[key]=parseNonrootJson(value);
  else if(key==='tags'){
   need(object(value)&&Object.values(value).every(v=>typeof v==='string'));
   body[key]=Object.keys(value).sort().map(key=>({key,value:value[key]}));
  }else body[key]=value;
 }
 need(Array.isArray(body.containerDefinitions)&&typeof body.family==='string');return copy(body);
}

const responseFields=Object.freeze(['taskDefinitionArn','revision','status','requiresAttributes','compatibilities','registeredAt','registeredBy']);
function checkedObservation(value){
 const o=copy(value);exact(o,['taskDefinition','tags']);need(object(o.taskDefinition)&&Array.isArray(o.tags));
 const t=o.taskDefinition;
 for(const k of Object.keys(t))need(requestFields.includes(k)&&k!=='tags'||responseFields.includes(k),'NonrootPreviewResponseField');
 need(typeof t.taskDefinitionArn==='string'&&Number.isSafeInteger(t.revision)&&t.revision>0&&t.status==='ACTIVE');
 need(t.taskDefinitionArn.endsWith('/'+t.family+':'+t.revision));
 need(Array.isArray(t.requiresAttributes)&&Array.isArray(t.compatibilities));
 for(const a of t.requiresAttributes){need(object(a)&&typeof a.name==='string'&&Object.keys(a).every(k=>['name','value','targetId','targetType'].includes(k))&&Object.values(a).every(v=>typeof v==='string'));}
 need(new Set(t.requiresAttributes.map(hash)).size===t.requiresAttributes.length&&new Set(t.compatibilities).size===t.compatibilities.length&&t.compatibilities.every(v=>typeof v==='string'));
 need(typeof t.registeredAt==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(t.registeredAt)&&Number.isFinite(Date.parse(t.registeredAt)));
 need(typeof t.registeredBy==='string'&&/^arn:aws:(?:iam|sts)::\d{12}:[^\s*?]+$/.test(t.registeredBy));
 for(const tag of o.tags){exact(tag,['key','value']);need(typeof tag.key==='string'&&typeof tag.value==='string');}
 need(new Set(o.tags.map(t=>t.key)).size===o.tags.length);
 return o;
}
function keyedRows(rows,valueKey){
 need(Array.isArray(rows));const seen=new Set();
 for(const row of rows){exact(row,['name',valueKey]);need(typeof row.name==='string'&&row.name.length>0&&typeof row[valueKey]==='string');
  need(!seen.has(row.name),'NonrootPreviewDuplicateName');seen.add(row.name);}
 return rows.toSorted((a,b)=>a.name<b.name?-1:a.name>b.name?1:0);
}
function emptyDefault(value,key){if(!Object.hasOwn(value,key))value[key]=[];need(Array.isArray(value[key]));}
/** Comparison copies only: ECS defaults optional CPU/essential fields and
 * empty lists; environment and secret rows are keyed by unique names. Retain
 * every other field and every explicit non-default value for exact comparison. */
function comparableContainer(value){
 const c=structuredClone(copy(value));need(object(c));
 if(!Object.hasOwn(c,'cpu'))c.cpu=0;
 if(!Object.hasOwn(c,'essential'))c.essential=true;
 need(Number.isSafeInteger(c.cpu)&&c.cpu>=0&&typeof c.essential==='boolean');
 for(const key of ['mountPoints','volumesFrom','systemControls'])emptyDefault(c,key);
 if(Object.hasOwn(c,'environment'))c.environment=keyedRows(c.environment,'value');
 if(Object.hasOwn(c,'secrets'))c.secrets=keyedRows(c.secrets,'valueFrom');
 if(Object.hasOwn(c,'portMappings')){
  need(Array.isArray(c.portMappings));for(const p of c.portMappings){need(object(p));if(!Object.hasOwn(p,'protocol'))p.protocol='tcp';}
 }
 if(c.linuxParameters?.capabilities!==undefined){need(object(c.linuxParameters.capabilities));emptyDefault(c.linuxParameters.capabilities,'add');}
 return c;
}
function comparableRegistration(value){
 const v=structuredClone(copy(value));need(object(v)&&Array.isArray(v.containerDefinitions));
 for(const key of ['volumes','placementConstraints'])emptyDefault(v,key);
 v.containerDefinitions=v.containerDefinitions.map(comparableContainer);return v;
}
/** Before publishing any binding, compare the complete request material using
 * only the finite equivalences above. Return the untouched observation so its
 * full hash still binds defaults, row order and all service-derived metadata. */
export function verifyPreviewRegistrationReadback(registration,value){
 const body=copy(registration),o=checkedObservation(value),material={};
 need(object(body)&&Object.keys(body).every(k=>requestFields.includes(k)));
 for(const [key,v]of Object.entries(o.taskDefinition))if(!responseFields.includes(key))material[key]=v;
 material.tags=[...o.tags].sort((a,b)=>a.key.localeCompare(b.key));
 const expected={...body,tags:[...(body.tags??[])].sort((a,b)=>a.key.localeCompare(b.key))};
 same(comparableRegistration(material),comparableRegistration(expected));return o;
}

export function inspectNonrootPreviewPurposeMap(value,scopeValue){
 const scope=checkedScope(scopeValue),v=typeof value==='string'?parseNonrootJson(value,{maxBytes:4096}):copy(value);
 exact(v,['version','kind',...scopeKeys,'family','containerName','defaultPurpose','bindings']);
 need(v.version===1&&v.kind==='nonroot-preview-purpose-map'&&v.containerName==='Mem9Bootstrap'&&Buffer.byteLength(JSON.stringify(v))<=4096);
 for(const key of scopeKeys)need(v[key]===scope[key],'NonrootPreviewSourceScope');familyScope(v.family,scope);purpose(v.defaultPurpose);
 need(Array.isArray(v.bindings)&&v.bindings.length>0&&v.bindings.length<=NONROOT_PREVIEW_BOOTSTRAP_PURPOSES.length);
 const arn='arn:aws:ecs:'+v.region+':'+v.account+':task-definition/'+v.family+':';
 for(const row of v.bindings){exact(row,['purpose','taskDefinitionArn','definitionHash']);purpose(row.purpose);
  need(typeof row.taskDefinitionArn==='string'&&row.taskDefinitionArn.startsWith(arn)&&/^[1-9][0-9]*$/.test(row.taskDefinitionArn.slice(arn.length))&&h64(row.definitionHash));}
 need(new Set(v.bindings.map(b=>b.purpose)).size===v.bindings.length&&new Set(v.bindings.map(b=>b.taskDefinitionArn)).size===v.bindings.length,'NonrootPreviewDistinctRevisions');
 need(v.bindings.some(b=>b.purpose===v.defaultPurpose));return v;
}
export function buildNonrootPreviewPurposeMap(input){
 const value=copy(input);exact(value,['scope','defaultPurpose','records']);
 const {scope:scopeValue,defaultPurpose,records}=value;
 const scope=checkedScope(scopeValue);need(Array.isArray(records)&&records.length>0);let family;
 const bindings=records.map(record=>{
  exact(record,['purpose','registration','observation']);purpose(record.purpose);
  const o=verifyPreviewRegistrationReadback(record.registration,record.observation);
  family??=o.taskDefinition.family;need(family===o.taskDefinition.family);fixedContainer(o.taskDefinition.containerDefinitions[0],record.purpose,scope);
  need(o.taskDefinition.containerDefinitions.length===1);
  return {purpose:record.purpose,taskDefinitionArn:o.taskDefinition.taskDefinitionArn,definitionHash:hash(o)};
 });
 return inspectNonrootPreviewPurposeMap({version:1,kind:'nonroot-preview-purpose-map',...scope,family,containerName:'Mem9Bootstrap',defaultPurpose,bindings},scope);
}
export function selectNonrootPreviewPurpose(value,selected,scope){
 const map=inspectNonrootPreviewPurposeMap(value,scope);purpose(selected);
 const binding=map.bindings.find(b=>b.purpose===selected);need(binding,'NonrootPreviewPurposeUnavailable');return binding;
}
export function verifyNonrootPreviewPurposeReadback(value,selected,observation,scope){
 const binding=selectNonrootPreviewPurpose(value,selected,scope),o=checkedObservation(observation);
 need(o.taskDefinition.taskDefinitionArn===binding.taskDefinitionArn&&hash(o)===binding.definitionHash,'NonrootPreviewReadbackChanged');
 need(o.taskDefinition.containerDefinitions.length===1);fixedContainer(o.taskDefinition.containerDefinitions[0],selected,checkedScope(scope));return o;
}
/** Unknown overrides and even empty command overrides are denied. Purpose and
 * stage belong to the fixed revision; an operation echo may only agree. */
export function validateNonrootPreviewOverrides(selected,value,{now=Date.now(),containerName='Mem9Bootstrap'}={}){
 purpose(selected);const v=copy(value);exact(v,['containerOverrides']);need(v.containerOverrides.length===1);
 need(containerName==='Mem9Bootstrap'||containerName==='Mem9PostFixture'&&selected.startsWith('preview-fixture-'));
 const c=v.containerOverrides[0];exact(c,['name','environment']);need(c.name===containerName);const env=environmentRows(c.environment);
 const runtime=selected.startsWith('bootstrap-')&&selected!=='bootstrap-schema-seed';
 const allowed=runtime?['MEM9_RUNTIME_INVOCATION','MEM9_RUNTIME_BOOTSTRAP_DEADLINE']:selected==='bootstrap-schema-seed'?[]:
  ['MEM9_PREVIEW_EXPECTED_GENERATION','MEM9_PREVIEW_OPERATOR_NONCE','MEM9_PREVIEW_OPERATOR_DEADLINE','MEM9_PREVIEW_BATCH_BOUNDARY_CROSSINGS'];
 for(const [key,val]of Object.entries(env)){
  if(key==='MEM9_BOOTSTRAP_OPERATION'){need(val===operationByPurpose[selected]&&val!==null);continue;}
  need(allowed.includes(key),'NonrootPreviewOverride');
  if(key.endsWith('_NONCE')||key==='MEM9_RUNTIME_INVOCATION')need(/^[a-f0-9]{32}$/.test(val));
  else if(key.endsWith('_GENERATION'))need(h64(val));
  else if(key.endsWith('_DEADLINE'))need(/^[1-9][0-9]*$/.test(val)&&Number.isSafeInteger(Number(val))&&Number(val)>now&&Number(val)<=now+(runtime?900000:600000));
  // Preserve the existing preview operator-journal observation bound. This is
  // a reported crossing count, not the production memory mutation budget.
  else need(/^[0-9]+$/.test(val)&&Number(val)<=10000);
 }
 return v;
}
/** Produces archive contents, not a review or permission. Actual source/test
 * evidence remains separately authenticated by the review/archive owner. */
export function buildNonrootPreviewLaunchInventory(input,testsRef){
 const map=buildNonrootPreviewPurposeMap(input),entries=copy({version:1,kind:'nonroot-preview-purpose-entries',map,records:input.records});
 const entriesBytes=JSON.stringify(entries),ref={bytesHash:createHash('sha256').update(entriesBytes).digest('hex'),canonicalHash:hash(entries),bytesLength:Buffer.byteLength(entriesBytes)};
 const inventory=inspectNonrootRecord('PreviewLaunchInventoryV1',{version:1,kind:'preview-guard-launch-inventory',sourceTree:map.sourceTree,entries:ref,tests:inspectNonrootRecord('JsonRef',testsRef)});
 return Object.freeze({inventory,entries,entriesBytes});
}
