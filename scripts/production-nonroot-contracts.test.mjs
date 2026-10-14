import {describe,it,expect} from 'vitest';
import {NONROOT_DEPLOYED_CONTROL_IMAGE_SLOT} from './lib/production-nonroot-provenance.mjs';
import {
  NONROOT_LIMITS, NONROOT_LIMITS_HASH, NONROOT_RECORD_TYPES, NONROOT_GUARD_BUILTINS,
  parseNonrootJson, inspectNonrootRecord, inspectNonrootDescriptor,
  inspectCarrierRunTaskRequest, inspectRuntimeIdentity, nonrootHash,
} from './lib/production-nonroot-contracts.mjs';

const h=c=>c.repeat(64),d=c=>'sha256:'+h(c),account='123456789012',region='ap-northeast-1';
const image={rootDigest:d('a'),arm64Digest:d('b'),configDigest:d('c')};
const reference={bytesHash:h('a'),canonicalHash:h('b'),bytesLength:2};
const taskArn='arn:aws:ecs:'+region+':'+account+':task/mem9-on-aws-prod-example/'+'a'.repeat(32);
const definition='arn:aws:ecs:'+region+':'+account+':task-definition/mem9-on-aws-prod-example-ControlMem9Bootstrap:7';
const artifactV2=()=>({version:2,kind:'readonly-cached-artifact-reverification',copyRecordHash:h('a'),contentHash:h('b'),startedMs:100,completedMs:200,
  ...Object.fromEntries('verifierClosure graph cacheCustody historicalDestinationReadback freshDestinationMetadata filesystem imageConfigs pathPermissions primitiveEvidence readAccounting'.split(' ').map(k=>[k,{...reference}]))});

describe('closed cached artifact reverification',()=>{
  it('accepts the V2 cache references without granting authority',()=>{
    const input=artifactV2(),checked=inspectNonrootRecord('ArtifactReverificationV2',input);
    expect(checked).toEqual(input);expect(Object.isFrozen(checked.cacheCustody)).toBe(true);
    expect(checked).not.toHaveProperty('authority');
  });
  it.each('verifierClosure graph cacheCustody historicalDestinationReadback freshDestinationMetadata filesystem imageConfigs pathPermissions primitiveEvidence readAccounting'.split(' '))('requires the exact %s JsonRef',key=>{
    for(const value of [undefined,{},true,{sha256:h('a'),bytesLength:2},{...reference,extra:true}]){
      const input=artifactV2();if(value===undefined)delete input[key];else input[key]=value;
      expect(()=>inspectNonrootRecord('ArtifactReverificationV2',input)).toThrow();
    }
  });
  it.each([
    ['legacy destination alias',p=>p.destinationReadback=reference],['caller authority',p=>p.authority=true],
    ['legacy kind',p=>p.kind='readonly-artifact-reverification'],['legacy version',p=>p.version=1],
    ['reversed clock',p=>p.completedMs=99],['unknown field',p=>p.passed=true],
  ])('rejects %s',(_name,change)=>{const p=artifactV2();change(p);expect(()=>inspectNonrootRecord('ArtifactReverificationV2',p)).toThrow();});
  it('preserves the closed legacy V1 schema',()=>{
    const {cacheCustody,historicalDestinationReadback,freshDestinationMetadata,...common}=artifactV2();
    const legacy={...common,version:1,kind:'readonly-artifact-reverification',destinationReadback:historicalDestinationReadback};
    expect(inspectNonrootRecord('ArtifactReverificationV1',legacy)).toEqual(legacy);
    expect(()=>inspectNonrootRecord('ArtifactReverificationV1',{...legacy,cacheCustody})).toThrow();
    expect(()=>inspectNonrootRecord('ArtifactReverificationV1',artifactV2())).toThrow();
  });
});
function request(){return {cluster:'arn:aws:ecs:'+region+':'+account+':cluster/mem9-on-aws-prod-example',taskDefinition:definition,count:1,launchType:'FARGATE',platformVersion:'1.4.0',networkConfiguration:{awsvpcConfiguration:{subnets:['subnet-0123456789abcdef0'],securityGroups:['sg-0123456789abcdef0'],assignPublicIp:'DISABLED'}},enableExecuteCommand:false,enableECSManagedTags:false,propagateTags:'NONE',tags:[{key:'mem9-supersession-owner',value:'a'.repeat(32)}],clientToken:'b'.repeat(32),startedBy:'root-'+'b'.repeat(29),overrides:{containerOverrides:[{name:'ControlMem9Bootstrap',environment:[{name:'MEM9_SUPERSESSION_ROOT_INPUT',value:'e30='},{name:'MEM9_SUPERSESSION_ROOT_HASH',value:h('a')},{name:'MEM9_SUPERSESSION_ROOT_CODE_HASH',value:h('b')}]}]}};}
function processIdentity(){return {pid:7,ppid:1,startTimeTicks:20,executablePath:'/usr/local/bin/node',executableDigest:d('a'),entrypointIdentityHash:h('b'),uid:[1000,1000,1000,1000],gid:[1000,1000,1000,1000],groups:[1000],capInh:'0000000000000000',capPrm:'0000000000000000',capEff:'0000000000000000',capBnd:'0000000000000000',capAmb:'0000000000000000',noNewPrivs:1};}
function runtime(){return {version:2,kind:'application-process-identity',phase:'target',taskKey:'backend',account,region,taskArn,taskDefinitionArn:definition,containerName:'mnemo-server',runtimeId:'runtime-1',image,registrationHash:h('a'),launchContractHash:h('b'),sourceBindingHash:h('c'),artifactBinding:{kind:'data',descriptorHash:h('d'),launchContractHash:h('b')},collectorCodeHash:h('d'),sessionBinding:reference,startedMs:100,completedMs:200,application:[processIdentity()],trustedLaunch:[],managed:[],samples:reference,coverage:reference,result:'pass'};}

describe('nonroot closed JSON foundation',()=>{
  it('keeps canonical hashing compatible and freezes independent validated copies',()=>{
    expect(nonrootHash({b:2,a:1})).toBe(nonrootHash({a:1,b:2}));
    expect(NONROOT_LIMITS_HASH).toBe(nonrootHash(NONROOT_LIMITS));
    const input={x:[1]},parsed=parseNonrootJson(JSON.stringify(input));
    expect(Object.isFrozen(parsed.x)).toBe(true);expect(parsed).toEqual(input);
    expect(NONROOT_RECORD_TYPES).toContain('CarrierRunTaskBindingV1');
  });
  it.each(['{"a":1,"a":2}','{"a":1,"\\u0061":2}','{"a":{"x":1,"x":2}}','[1,]','01','1e999','9007199254740992','-0','"\\ud800"'])('rejects malformed or ambiguous JSON %s',text=>{expect(()=>parseNonrootJson(text)).toThrow();});
  it('enforces byte and depth ceilings before accepting JSON',()=>{
    expect(()=>parseNonrootJson('"abcd"',{maxBytes:2})).toThrow();
    expect(()=>parseNonrootJson('['.repeat(65)+'0'+']'.repeat(65))).toThrow();
    expect(()=>parseNonrootJson('{}',{maxBytes:NONROOT_LIMITS.maxProofBytes+1})).toThrow();
  });
  it('does not execute getters, toJSON or proxy traps; rejects exotic and sparse values',()=>{
    let calls=0;const getter={...reference};Object.defineProperty(getter,'bytesHash',{enumerable:true,get(){calls++;return h('a');}});
    const proxy=new Proxy(reference,{ownKeys(){calls++;return Reflect.ownKeys(reference);}});
    for(const value of [getter,proxy,{...reference,toJSON(){calls++;return reference;}},Object.assign(Object.create({}),reference),Object.assign([1],{extra:2}),Array(2)])expect(()=>inspectNonrootRecord('JsonRef',value)).toThrow();
    expect(calls).toBe(0);
    const cycle={};cycle.self=cycle;expect(()=>nonrootHash(cycle)).toThrow();
  });
  it('rejects unknown record types, unknown fields, missing blobs and invalid reference lengths',()=>{
    expect(()=>inspectNonrootRecord('Unreviewed',{})).toThrow();
    for(const value of [{...reference,extra:1},{...reference,bytesLength:0},{...reference,bytesLength:-1},{...reference,bytesHash:'bad'}])expect(()=>inspectNonrootRecord('JsonRef',value)).toThrow();
    expect(inspectNonrootRecord('ByteRef',{sha256:h('a'),bytesLength:0})).toEqual({sha256:h('a'),bytesLength:0});
  });
});

describe('closed CONTROL image field-change slot',()=>{
 const targets={bootstrap:'Mem9Bootstrap',control:'ControlMem9Bootstrap',promotion:'PromoteMem9Bootstrap',provision:'ProdMem9Bootstrap',transition:'TransitionMem9Bootstrap'};
 const change=(taskKey='control')=>({taskKey,surface:'container',selector:targets[taskKey],field:'image',cause:'guarded-control',
  before:{present:true,value:'example.com/old@'+d('a')},after:{present:true,value:structuredClone(NONROOT_DEPLOYED_CONTROL_IMAGE_SLOT)},observationHash:h('b')});
 it.each(Object.keys(targets))('accepts the exact unresolved slot for %s only in its approved container',taskKey=>{
  const row=change(taskKey);expect(inspectNonrootRecord('FieldChangeV2',row)).toEqual(row);
 });
 it.each([
  ['DATA backend',r=>r.taskKey='backend'],['DATA planner',r=>r.taskKey='planner'],['DATA executor',r=>r.taskKey='executor'],
  ['retained fallback',r=>r.taskKey='fallback'],['preaudit carrier',r=>r.taskKey='preaudit'],
  ['wrong container',r=>r.selector='Mem9Bootstrap'],['wrong surface',r=>r.surface='response'],
  ['carrier cause',r=>r.cause='carrier-image'],['DATA cause',r=>r.cause='retained-data-image'],
  ['unknown slot kind',r=>r.after.value.kind='future-image'],['unknown build contract',r=>r.after.value.buildContractKey='other'],
  ['unknown slot version',r=>r.after.value.version=2],['unknown slot field',r=>r.after.value.image='any'],
  ['missing before image',r=>r.before={present:false}],['slot as before image',r=>r.before.value=structuredClone(r.after.value)],
  ['slot on another field',r=>r.field='command'],
 ])('rejects %s',(_name,mutate)=>{const r=change();mutate(r);expect(()=>inspectNonrootRecord('FieldChangeV2',r)).toThrow();});
 it('does not introduce a legacy field-change record or resolve a slot into a wildcard image',()=>{
  expect(()=>inspectNonrootRecord('FieldChangeV1',change())).toThrow();
  const r=change();r.after.value={...r.after.value,rootDigest:'*'};expect(()=>inspectNonrootRecord('FieldChangeV2',r)).toThrow();
 });
});

// Synthetic structural records only. Cross-record authenticity and the full
// registration-body comparison are responsibilities of the archive adapter.
function resolvedPlan(){
  const guardImports={version:1,kind:'minimal-guard-imports',entryModule:{sha256:h('a'),bytesLength:1},
    localGuardFiles:{version:1,kind:'git-file-closure',tree:'a'.repeat(40),files:[],closureHash:nonrootHash([])},
    allowedBuiltins:[...NONROOT_GUARD_BUILTINS],policyHash:h('b'),importAudit:reference,
    nodeRuntime:{version:1,kind:'pinned-node-runtime',versionString:'v24.0.0',executablePath:'/usr/local/bin/node',
      executableSha256:h('c'),loaderAndNativeLibraries:reference,image,inventory:reference}};
  const environment={version:1,kind:'prelaunch-environment-gate',image,registrationBodyHash:h('a'),overrideHash:h('b'),
    forbiddenNamesHash:h('c'),imageEnvironment:reference,taskEnvironment:reference,secretNamesAndReferences:reference,
    overrideEnvironment:reference,loaderFileEvidence:reference,caBindings:[],checkedMs:100,result:'pass'};
  const launch={version:1,kind:'resolved-control-launch',taskKey:'control',containerName:'ControlMem9Bootstrap',
    templateHash:h('a'),contractHash:h('b'),image:{account,region,repositoryName:'mem9-on-aws/bootstrap',...image},
    entryPoint:['/bin/setpriv','--no-new-privs','--','/usr/local/bin/node','/bootstrap/nonroot-dispatch.mjs','consolidation-control'],
    command:[],dispatcherSha256:h('c'),guardClosureHash:h('d'),originalModule:{present:false},originalModuleSha256:{present:false},
    originalArgv:[],primitiveEvidence:reference,guardImports,environment,registrationBody:reference,registrationBodyHash:h('b')};
  return structuredClone({version:1,kind:'resolved-nonroot-task-plan',taskPlanHash:h('a'),deployedControlBuildHash:h('b'),
    tasks:['backend','bootstrap','control','executor','planner','promotion','provision','transition'].map(taskKey=>({taskKey,registrationBody:reference})),
    controlLaunches:[launch]});
}
describe('resolved deployed task plan schema',()=>{
  it('accepts only the eight update tasks with typed launches and immutable references',()=>{
    const p=resolvedPlan(),got=inspectNonrootRecord('ResolvedTaskPlanV1',p);
    expect(got).toEqual(p);expect(got).not.toHaveProperty('authorized');
    expect(Object.isFrozen(got.tasks[0].registrationBody)).toBe(true);
    p.tasks.reverse();expect(inspectNonrootRecord('ResolvedTaskPlanV1',p)).toEqual(p);
  });
  it.each([
    ['missing update task',p=>p.tasks.pop()],
    ['duplicate update task',p=>p.tasks[0]=p.tasks[1]],
    ['retained fallback',p=>p.tasks[0].taskKey='fallback'],
    ['separate preaudit carrier',p=>p.tasks[0].taskKey='preaudit'],
    ['additional update task',p=>p.tasks.push(p.tasks[0])],
    ['unknown task field',p=>p.tasks[0].disposition='update'],
    ['unbound registration content',p=>p.tasks[0].registrationBody={}],
    ['reference field injection',p=>p.tasks[0].registrationBody.authorized=true],
    ['missing plan pin',p=>delete p.taskPlanHash],
    ['malformed build pin',p=>p.deployedControlBuildHash='bad'],
    ['unknown plan field',p=>p.fallback={}],
    ['empty CONTROL coverage',p=>p.controlLaunches=[]],
    ['duplicate CONTROL key',p=>p.controlLaunches.push(p.controlLaunches[0])],
    ['shadow Node launch',p=>p.controlLaunches[0].entryPoint[3]='node'],
    ['unknown nested launch field',p=>p.controlLaunches[0].approved=true],
  ])('rejects %s',(_name,change)=>{const p=resolvedPlan();change(p);expect(()=>inspectNonrootRecord('ResolvedTaskPlanV1',p)).toThrow();});
});
describe('carrier whole-request and identity schemas',()=>{
  it.each(['1234','0123456','012345678','0123456789abcdef','0123456789abcdef01','0123456789abcdeg0','0123456789ABCDEf0'])('rejects invalid EC2 resource suffix %s',suffix=>{
    for(const field of ['subnets','securityGroups']){const r=request();r.networkConfiguration.awsvpcConfiguration[field]=[(field==='subnets'?'subnet-':'sg-')+suffix];expect(()=>inspectCarrierRunTaskRequest(r)).toThrow();}
  });
  it('accepts the exact historical eight-hex and current seventeen-hex ID forms',()=>{
    const r=request();r.networkConfiguration.awsvpcConfiguration.subnets=['subnet-01234567'];r.networkConfiguration.awsvpcConfiguration.securityGroups=['sg-01234567'];expect(()=>inspectCarrierRunTaskRequest(r)).not.toThrow();
  });
  it('accepts only the explicit Fargate request and returns no authority object',()=>{
    const input=request(),checked=inspectCarrierRunTaskRequest(input);expect(checked).toEqual(input);expect(checked).not.toHaveProperty('authorized');expect(Object.isFrozen(checked.networkConfiguration.awsvpcConfiguration.subnets)).toBe(true);
  });
  it.each([
    r=>r.count=2,r=>r.enableExecuteCommand=true,r=>r.enableECSManagedTags=true,r=>r.propagateTags='TASK_DEFINITION',r=>r.capacityProviderStrategy=[],r=>delete r.launchType,r=>r.launchType='EC2',r=>r.platformVersion='LATEST',r=>r.group='unreviewed',r=>r.volumeConfigurations=[],r=>r.cluster='default',r=>r.taskDefinition=r.taskDefinition.replace(/:7$/,''),r=>r.networkConfiguration.awsvpcConfiguration.assignPublicIp='ENABLED',r=>r.networkConfiguration.awsvpcConfiguration.subnets.push('subnet-0123456789abcdef0'),r=>r.networkConfiguration.awsvpcConfiguration.securityGroups=[],r=>r.tags.push(r.tags[0]),r=>r.overrides.containerOverrides[0].command=['sh'],r=>r.overrides.containerOverrides[0].environment.push({name:'NODE_OPTIONS',value:''}),r=>r.overrides.taskRoleArn='foreign',
  ])('rejects a changed request structure',mutate=>{const r=request();mutate(r);expect(()=>inspectCarrierRunTaskRequest(r)).toThrow();});
  it('requires nonroot zero-capability NNP application identities and unique PID/start tuples',()=>{
    expect(inspectRuntimeIdentity(runtime())).toEqual(runtime());
    for(const mutate of [r=>r.application[0].uid[1]=0,r=>r.application[0].gid[2]=0,r=>r.application[0].groups=[0],r=>r.application[0].capBnd='0000000000000001',r=>r.application[0].noNewPrivs=0,r=>r.application.push(r.application[0]),r=>r.completedMs=99]){const r=runtime();mutate(r);expect(()=>inspectRuntimeIdentity(r)).toThrow();}
  });
  it('requires descriptor v3/transition v2 without widening legacy or unknown shapes',()=>{
    const value={version:3,stage:'prod',account,region,controlSourceTree:'a'.repeat(40),dataRevision:'b'.repeat(40),dataSourceTree:'c'.repeat(40),dataSourceTag:'mem9-bbbbbbb',images:Object.fromEntries(['llm-proxy','mnemo-server','qwen3-embed'].map(n=>[n,{rootDigest:d('a'),arm64Digest:d('b')}])),...Object.fromEntries(['parentProofHash','backendBindingHash','generation','targetsHash','schemaDigest','operatorDigest','buildInputsHash','securityEvidenceHash','policyHash'].map(n=>[n,h('a')])),runtimeNonce:'a'.repeat(32),authorizationId:'b'.repeat(32),issuedMs:100,expiresMs:200,transition:{version:2,kind:'image-security-nonroot-upgrade',proofHash:h('a'),predecessorHash:h('b'),limitsHash:NONROOT_LIMITS_HASH}};
    expect(inspectNonrootDescriptor(value)).toEqual(value);
    for(const mutate of [v=>v.version=2,v=>v.transition.version=1,v=>v.transition.limitsHash=h('f'),v=>v.expiresMs=v.issuedMs,v=>v.images.worker=v.images['llm-proxy'],v=>v.authorized=true]){const v=structuredClone(value);mutate(v);expect(()=>inspectNonrootDescriptor(v)).toThrow();}
  });
});
