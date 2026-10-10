import {controlLaunchPolicy,NONROOT_FORBIDDEN_ENVIRONMENT} from './production-nonroot-launch.mjs';
import {parseNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {deflateRawSync,inflateRawSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {validatePublicationInspectionRequest} from './production-continuation-publication.mjs';

export const CONTINUATION_INSPECTION_OPERATIONS=Object.freeze(['parse-begin','root-audit','capacity-census','absence-audit','publication-audit','publication-probe']);
const fail=code=>{throw Error(code);},need=(value,code='ContinuationInspectionInvalid')=>{if(!value)fail(code);};
const hex=value=>typeof value==='string'&&/^[a-f0-9]{32}$/.test(value);
const exact=(value,keys)=>need(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===keys.toSorted().join());
const clone=value=>JSON.parse(JSON.stringify(value));
const sha=value=>createHash('sha256').update(value).digest('hex');
const parameters=Object.freeze({'parse-begin':'MEM9_PRODUCTION_CONSOLIDATION_REQUEST','root-audit':'MEM9_CONTINUATION_INSPECTION_REQUEST','capacity-census':'MEM9_CONTINUATION_INSPECTION_REQUEST','absence-audit':'MEM9_CONTINUATION_INSPECTION_REQUEST','publication-audit':'MEM9_PUBLICATION_REQUEST','publication-probe':'MEM9_PUBLICATION_REQUEST'});
const families=Object.freeze({'parse-begin':'BeginAcceptance','root-audit':'ContinuationRootAudit','capacity-census':'ContinuationCensus','absence-audit':'ContinuationAbsence','publication-audit':'PublicationAudit','publication-probe':'PublicationProbe'});

/** No script/module/SQL/URL selector. The image's fixed dispatcher validates
 * identity and its manifest before it imports the fixed inspection module. */
export function parseContinuationInspection(raw,{operation,invocation,now=Date.now(),admission=true}){
 need(['root-audit','capacity-census','absence-audit'].includes(operation)&&hex(invocation));
 need(typeof raw==='string'&&Buffer.byteLength(raw)<=32768);
 let value=parseNonrootJson(raw,{maxBytes:32768});
 if(value.encoding!==undefined){
  exact(value,['version','encoding','bytes','sha256','body']);need(value.version===1&&value.encoding==='deflate-raw-base64'&&Number.isSafeInteger(value.bytes)&&value.bytes>0&&value.bytes<=32768&&/^[a-f0-9]{64}$/.test(value.sha256));
  need(typeof value.body==='string'&&value.body.length<=6144);const compressed=Buffer.from(value.body,'base64');need(compressed.toString('base64')===value.body);
  const {buffer,engine}=inflateRawSync(compressed,{maxOutputLength:32768,info:true});need(engine.bytesWritten===compressed.length&&buffer.length===value.bytes&&sha(buffer)===value.sha256,'ContinuationInspectionEncoding');
  value=parseNonrootJson(new TextDecoder('utf-8',{fatal:true}).decode(buffer),{maxBytes:32768});
 }
 exact(value,['version','operation','invocation','owner','deadline','input']);
 need(value.version===1&&value.operation===operation&&value.invocation===invocation&&hex(value.owner));
 need(Number.isSafeInteger(value.deadline)&&value.deadline>0&&Number.isSafeInteger(now)&&now>0);
 if(admission)need(value.deadline>now&&value.deadline<=now+300000,'ContinuationInspectionDeadline');
 need(value.input&&typeof value.input==='object'&&!Array.isArray(value.input));return value;
}

export function encodeContinuationInspection(value){
 const raw=Buffer.from(JSON.stringify(value));need(raw.length>0&&raw.length<=32768);const compressed=deflateRawSync(raw);need(compressed.length<=4608,'ContinuationInspectionWireLimit');
 return JSON.stringify({version:1,encoding:'deflate-raw-base64',bytes:raw.length,sha256:sha(raw),body:compressed.toString('base64')});
}

/** Derive only an owner-scoped, finite inspection definition from the exact
 * deployed guarded CONTROL baseline. It does not authorize registration. */
export function continuationInspectionDefinition(base,{operation,invocation,request,owner=request?.owner??request?.attemptId??request?.nonce??invocation}){
 need(CONTINUATION_INSPECTION_OPERATIONS.includes(operation)&&hex(invocation)&&hex(owner));
 const definition=clone(base),c=definition.containerDefinitions?.[0];
 need(definition.containerDefinitions?.length===1&&c.name==='ControlMem9Bootstrap'&&definition.networkMode==='awsvpc');
 need(hash(definition.runtimePlatform)===hash({cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'})&&hash(definition.requiresCompatibilities)===hash(['FARGATE']));
 const guarded=controlLaunchPolicy('consolidation-control',c);
 for(const field of ['entryPoint','command','user','linuxParameters'])need(hash(c[field])===hash(guarded[field]),'ContinuationInspectionGuardedBaseline');
 need(c.privileged!==true&&!c.environmentFiles?.length&&!c.repositoryCredentials,'ContinuationInspectionExternalInput');
 const env=c.environment??[];need(new Set(env.map(row=>row.name)).size===env.length);
 for(const row of env){exact(row,['name','value']);need(typeof row.value==='string'&&!NONROOT_FORBIDDEN_ENVIRONMENT.includes(row.name)&&!row.name.startsWith('LD_'));
  need(!['MEM9_CONTINUATION_OPERATION',...Object.values(parameters)].includes(row.name),'ContinuationInspectionEnvironmentCollision');}
 const parameter=parameters[operation],raw=JSON.stringify(request);need(Buffer.byteLength(raw)<=32768);
 definition.family='mem9-on-aws-prod-'+families[operation]+'-'+invocation;
 for(const key of ['taskDefinitionArn','revision','status','requiresAttributes','compatibilities','registeredAt','registeredBy','deregisteredAt'])delete definition[key];
 const target=clone(controlLaunchPolicy('continuation-inspection',c));target.readonlyRootFilesystem=true;target.stopTimeout=30;
 if(operation==='parse-begin'){
  delete definition.taskRoleArn;target.secrets=[];
  target.environment=env.filter(row=>['MEM9_STAGE','MEM9_PRODUCTION_WORKER_OPERATOR','NODE_EXTRA_CA_CERTS'].includes(row.name));
 }
 target.environment.push({name:'MEM9_CONTINUATION_OPERATION',value:operation},{name:parameter,value:raw});
 if(operation.startsWith('publication-')){
  target.environment.push({name:'MEM9_PUBLICATION_REQUEST_HASH',value:sha(raw)},{name:'MEM9_PUBLICATION_DEADLINE_MS',value:String(request.deadlineMs)});
  validatePublicationInspectionRequest({...Object.fromEntries(target.environment.map(e=>[e.name,e.value])),MEM9_PUBLICATION_INVOCATION:invocation},{now:request.issuedMs});
 }
 definition.containerDefinitions=[target];definition.tags=[{key:'Project',value:'mem9-on-aws'},{key:'Stage',value:'prod'},{key:'Purpose',value:'continuation-inspection'},{key:'Operation',value:owner},{key:'Invocation',value:invocation}];
 return definition;
}
