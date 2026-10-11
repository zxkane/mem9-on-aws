import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {POST_RUNTIME_OPERATOR,POST_RUNTIME_PURPOSES,postRuntimeOperatorEnvironment,selectGuardedPostRuntimeRoute,validatePostRuntimeDefinition,validatePostRuntimeRoute} from '../scripts/lib/post-runtime-preview-route.mjs';
import {previewRegistrationFromProviderArgs} from '../scripts/lib/nonroot-preview-source.mjs';
const state=vi.hoisted(()=>({stage:'pr-7',phase:'complete',status:'running',nonce:'b'.repeat(32)}));
const data=vi.hoisted(()=>({stage:'pr-7',account:'123456789012',region:'ap-northeast-1',runtimeNonce:'b'.repeat(32),generation:'a'.repeat(64),controlSourceTree:'c'.repeat(40)}));
const out=<T>(value:T):any=>({value,apply(fn:any){const run=(v:any)=>{const next=fn(v);return next&&typeof next==='object'&&'apply'in next?next.value:next;};return out(value instanceof Promise?value.then(run):run(value));}});
const unwrap=(v:any):any=>v instanceof Promise?v:v&&typeof v==='object'&&'apply'in v?unwrap(v.value):Array.isArray(v)?v.map(unwrap):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).map(([k,x])=>[k,unwrap(x)])):v;
async function resolved(v:any):Promise<any>{if(v instanceof Promise)return resolved(await v);if(v&&typeof v==='object'&&'apply'in v)return resolved(v.value);if(Array.isArray(v))return Promise.all(v.map(resolved));if(v&&typeof v==='object')return Object.fromEntries(await Promise.all(Object.entries(v).map(async([k,x])=>[k,await resolved(x)])));return v;}
const asynchronous=(v:any):boolean=>v instanceof Promise||!!(v&&typeof v==='object'&&Object.values(v).some(asynchronous));
const observed=vi.hoisted(()=>({value:undefined as any,definitions:new Map<string,any>(),revision:7,
  registrations:[] as Array<{name:string;dependencies:string[]}>,pending:[] as Promise<unknown>[],started:[] as string[],
  calls:[] as Array<{taskDefinition:string;include:string[]}>,active:0,maximumActive:0,rejectConcurrent:false,failName:null as string|null,drift:false,
  mutateTags:null as ((tags:Array<{key:string;value:string}>)=>void)|null}));
vi.mock('@aws-sdk/client-ecs',()=>({DescribeTaskDefinitionCommand:class{input;constructor(input:any){this.input=input;}},ECSClient:class{async send(c:any){
  observed.calls.push(structuredClone(c.input));
  if(c.input.include.join()!=='TAGS'||!observed.definitions.has(c.input.taskDefinition))throw Error('UnexpectedMockEcsReadback');
  const result=structuredClone(observed.definitions.get(c.input.taskDefinition));if(observed.drift)result.taskDefinition.cpu='4096';observed.mutateTags?.(result.tags);return result;
}destroy(){}}}));
vi.mock('./ecr',()=>({accountId:()=>out(data.account),applicationRegion:()=>out(data.region),selectedDataRelease:()=>out({data})}));
vi.mock('./vpc',()=>({resolveVpc:()=>({privateSubnetIds:out(['subnet-aaaabbbb'])})}));
const manifest=()=>({version:1,stage:'pr-7',mode:'active',account:data.account,region:data.region,clusterArn:`arn:aws:ecs:${data.region}:${data.account}:cluster/mem9-on-aws-pr-7-Cluster-example`,
  subnets:['subnet-aaaabbbb'],securityGroup:'sg-aaaabbbb',host:'writer.example.com',port:5432,database:'mem9',administratorCredential:`arn:aws:ssm:${data.region}:${data.account}:parameter/mem9-on-aws/pr-7/runtime/schema-administrator-credential`});
let resources:any[];
type RegisteredDefinition={name:string;completion:Promise<string>;arn:any};
function registerDefinition(name:string,args:any,options:{dependsOn?:RegisteredDefinition[]}={},base=false):RegisteredDefinition{
  const revision=base?7:++observed.revision,dependencies=options.dependsOn??[];
  observed.registrations.push({name,dependencies:dependencies.map(resource=>resource.name)});
  const completion=Promise.all(dependencies.map(resource=>resource.completion)).then(()=>resolved(args)).then(async values=>{
    observed.started.push(name);observed.active++;observed.maximumActive=Math.max(observed.maximumActive,observed.active);
    try{
      if(observed.rejectConcurrent&&observed.active>1)throw Error('ConcurrentFamilyRegistration');
      await Promise.resolve();
      if(observed.failName===name)throw Error('SyntheticRegistrationFailed');
      // Apply framework tags after the component transform, without mutating its captured tag object.
      const request=previewRegistrationFromProviderArgs({...values,tags:{...values.tags,'sst:app':$app.name,'sst:stage':$app.stage}});
      const {tags,...body}=request;
      const arn=`arn:aws:ecs:${data.region}:${data.account}:task-definition/${body.family}:${revision}`;
      const value={taskDefinition:{...body,taskDefinitionArn:arn,revision,status:'ACTIVE',registeredAt:'2026-10-08T00:00:00.000Z',
        registeredBy:`arn:aws:sts::${data.account}:assumed-role/preview/session`,requiresAttributes:[],compatibilities:['FARGATE']},tags};
      observed.definitions.set(arn,value);if(base)observed.value=value;else resources.push({kind:'definition',name,args:values,request});return arn;
    }finally{observed.active--;}
  });
  observed.pending.push(completion);return {name,completion,arn:out(completion)};
}
function setup(stage='pr-7'){
  vi.stubGlobal('$app',{name:'mem9-on-aws',stage});vi.stubGlobal('$jsonStringify',(x:any)=>{const value=unwrap(x);return out(asynchronous(value)?resolved(value).then(JSON.stringify):JSON.stringify(value));});
  vi.stubGlobal('$interpolate',(parts:any,...values:any[])=>out(parts.reduce((s:string,p:string,i:number)=>s+p+(i<values.length?String(unwrap(values[i])):''),'')));
  vi.stubGlobal('aws',{ssm:{getParameterOutput:({name}:any)=>out({value:JSON.stringify(name.endsWith('/production-state')?state:manifest())}),
    Parameter:class{constructor(name:string,args:any){resources.push({kind:'parameter',name,args});}}},
    ecr:{getImageOutput:()=>({imageDigest:out('sha256:'+'d'.repeat(64))})},
    ecs:{TaskDefinition:class{
      name;completion;arn;
      constructor(name:string,args:any,options:any){const definition=registerDefinition(name,args,options);this.name=definition.name;this.completion=definition.completion;this.arn=definition.arn;}
    }},
    kms:{getKeyOutput:()=>({arn:out(`arn:aws:kms:${data.region}:${data.account}:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee`)})}});
  vi.stubGlobal('sst',{aws:{Task:class{
    taskDefinition;nodes;
    constructor(name:string,args:any){resources.push({kind:'task',name,args});
      this.nodes={taskRole:{arn:out(`arn:aws:iam::${data.account}:role/mem9-on-aws-pr-7-${name}TaskRole-role-test`)},executionRole:{arn:out(`arn:aws:iam::${data.account}:role/mem9-on-aws-pr-7-${name}ExecutionRole-role-test`)}};
      const c={name,image:unwrap(args.image),entrypoint:args.entrypoint,command:args.command,
        environment:Object.entries(unwrap(args.environment)).map(([name,value])=>({name,value})),
        secrets:Object.entries(unwrap(args.ssm)).map(([name,valueFrom])=>({name,valueFrom})),
        logConfiguration:{logDriver:'awslogs',options:{'awslogs-group':'/sst/mem9-on-aws/pr-7/operator','awslogs-region':data.region,'awslogs-stream-prefix':'ecs'}}};
      const generated:any={family:'mem9-on-aws-pr-7-Cluster-example-'+name,containerDefinitions:out(JSON.stringify([c])),trackLatest:true,
        taskRoleArn:this.nodes.taskRole.arn,executionRoleArn:this.nodes.executionRole.arn,networkMode:'awsvpc',requiresCompatibilities:['FARGATE'],
        runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'},cpu:'256',memory:'512'};
      args.transform.taskDefinition(generated);
      const definition=registerDefinition(name,generated,{},true);this.taskDefinition=definition.arn;
      Object.assign(this.nodes,{taskDefinition:out(definition)});
    }
  }}});
}
const context={kind:'post-runtime' as const,runtimeNonce:'b'.repeat(32)};
const db=()=>({host:out('writer.example.com'),port:out(5432),database:out('mem9'),taskSecurityGroupId:out('sg-aaaabbbb')});
const ecs=()=>({cluster:{},clusterName:out('mem9-on-aws-pr-7-Cluster-example')});
async function createOperator(){
  const {verifiedPostRuntimePreview,postRuntimePreviewOperator}=await import('./post-runtime-preview');
  const prefix=`arn:aws:ssm:${data.region}:${data.account}:parameter/mem9-on-aws/pr-7/consolidation-preview/`;
  const config={generation:'a'.repeat(64),context,verification:verifiedPostRuntimePreview('pr-7',context,'a'.repeat(64)),
    arns:Object.fromEntries(['config','planner','executor','backend','seed'].map(k=>[k,out(prefix+k+(k==='config'?'':'-credential'))]))};
  postRuntimePreviewOperator(ecs() as any,db() as any,config as any,{mode:'active',administratorArn:out(manifest().administratorCredential)} as any);
  return JSON.parse(await resolved(resources.find(r=>r.kind==='parameter').args.value));
}
describe('post-runtime preview resources',()=>{
  beforeEach(()=>{vi.doUnmock('../scripts/lib/post-runtime-preview-route.mjs');vi.resetModules();resources=[];observed.definitions.clear();Object.assign(observed,{value:undefined,revision:7,registrations:[],pending:[],started:[],calls:[],active:0,maximumActive:0,rejectConcurrent:false,failName:null,drift:false,mutateTags:null});Object.assign(state,{stage:'pr-7',phase:'complete',status:'running',nonce:'b'.repeat(32)});vi.stubEnv('MEM9_IMAGE_TAG','pr-abcdef0');setup();});
  afterEach(async()=>{await Promise.allSettled(observed.pending);vi.doUnmock('../scripts/lib/post-runtime-preview-route.mjs');vi.unstubAllGlobals();vi.unstubAllEnvs();});
  it('serializes registrations from the base pause definition through every additional purpose',async()=>{
    observed.rejectConcurrent=true;const map=await createOperator();
    expect(map.bindings.map((b:any)=>b.purpose)).toEqual(POST_RUNTIME_PURPOSES);expect(observed.maximumActive).toBe(1);
    expect(observed.registrations).toHaveLength(5);expect(observed.registrations[0]).toEqual({name:POST_RUNTIME_OPERATOR,dependencies:[]});
    for(let i=1;i<observed.registrations.length;i++)expect(observed.registrations[i].dependencies).toEqual([observed.registrations[i-1].name]);
    expect(observed.calls).toHaveLength(5);
  });
  it('blocks later AWS registrations and the usable map when a dependency fails',async()=>{
    observed.failName='Mem9PostFixturePurposePreviewFixtureSetup';
    await expect(createOperator()).rejects.toThrow('SyntheticRegistrationFailed');await Promise.allSettled(observed.pending);
    expect(observed.started).toEqual([POST_RUNTIME_OPERATOR,observed.failName]);
    expect(observed.definitions.size).toBe(1);expect(resources.filter(r=>r.kind==='definition')).toEqual([]);expect(observed.calls).toHaveLength(1);
    await expect(resolved(resources.find(r=>r.kind==='parameter').args.value)).rejects.toThrow('SyntheticRegistrationFailed');
  });
  it('keeps map order and the dependency chain when base pause is not first',async()=>{
    const order=[POST_RUNTIME_PURPOSES[1],POST_RUNTIME_PURPOSES[0],...POST_RUNTIME_PURPOSES.slice(2)];
    vi.doMock('../scripts/lib/post-runtime-preview-route.mjs',async()=>({...await vi.importActual<typeof import('../scripts/lib/post-runtime-preview-route.mjs')>('../scripts/lib/post-runtime-preview-route.mjs'),POST_RUNTIME_PURPOSES:order}));
    observed.rejectConcurrent=true;const map=await createOperator();
    expect(map.bindings.map((b:any)=>b.purpose)).toEqual(order);expect(observed.maximumActive).toBe(1);
    expect(map.route.taskDefinitionArn).toBe(map.bindings.find((b:any)=>b.purpose==='preview-fixture-pause').taskDefinitionArn);
    for(let i=1;i<observed.registrations.length;i++)expect(observed.registrations[i].dependencies).toEqual([observed.registrations[i-1].name]);
    expect(observed.calls.map(c=>c.taskDefinition).sort()).toEqual(map.bindings.map((b:any)=>b.taskDefinitionArn).sort());
  });
  it('retains full readback rejection after sequential registration',async()=>{
    observed.drift=true;await expect(createOperator()).rejects.toThrow('NonrootPreviewMismatch');
  });
  it.each(['sst:app','sst:stage'])('rejects a missing framework tag %s',async key=>{
    observed.mutateTags=tags=>{tags.splice(tags.findIndex(tag=>tag.key===key),1);};
    await expect(createOperator()).rejects.toThrow('NonrootPreviewMismatch');
  });
  it.each(['sst:app','sst:stage'])('rejects a wrong framework tag %s',async key=>{
    observed.mutateTags=tags=>{tags.find(tag=>tag.key===key)!.value='different';};
    await expect(createOperator()).rejects.toThrow('NonrootPreviewMismatch');
  });
  it('rejects an extra tag rather than dropping it from comparison',async()=>{
    observed.mutateTags=tags=>{tags.push({key:'unexpected',value:'value'});};
    await expect(createOperator()).rejects.toThrow('NonrootPreviewMismatch');
  });
  it('creates no task for ordinary active finalization or production',async()=>{
    const {postRuntimePreviewOperator}=await import('./post-runtime-preview');
    expect(postRuntimePreviewOperator(ecs() as any,db() as any,undefined,{mode:'active'} as any)).toBeUndefined();
    setup('prod');expect(postRuntimePreviewOperator(ecs() as any,db() as any,undefined,{mode:'active'} as any)).toBeUndefined();expect(resources).toEqual([]);
  });
  it.each(['prepare','paused','ready'])('rejects a post-runtime operator in %s mode',async mode=>{
    const {postRuntimePreviewOperator}=await import('./post-runtime-preview');
    expect(()=>postRuntimePreviewOperator(ecs() as any,db() as any,{context} as any,{mode} as any)).toThrow();expect(resources).toEqual([]);
  });
  it('rejects stale or unfinished runtime proof before creating task resources',async()=>{
    const {verifiedPostRuntimePreview}=await import('./post-runtime-preview');
    state.phase='retired';expect(()=>verifiedPostRuntimePreview('pr-7',context,'a'.repeat(64))).toThrow();
    state.phase='complete';state.nonce='e'.repeat(32);expect(()=>verifiedPostRuntimePreview('pr-7',context,'a'.repeat(64))).toThrow();expect(resources).toEqual([]);
  });
  it('creates five fixed-purpose revisions with one existing family and unchanged roles and secrets',async()=>{
    const {verifiedPostRuntimePreview,postRuntimePreviewOperator}=await import('./post-runtime-preview');
    const prefix=`arn:aws:ssm:${data.region}:${data.account}:parameter/mem9-on-aws/pr-7/consolidation-preview/`;
    const config={generation:'a'.repeat(64),context,verification:verifiedPostRuntimePreview('pr-7',context,'a'.repeat(64)),
      arns:Object.fromEntries(['config','planner','executor','backend','seed'].map(k=>[k,out(prefix+k+(k==='config'?'':'-credential'))]))};
    postRuntimePreviewOperator(ecs() as any,db() as any,config as any,{mode:'active',administratorArn:out(manifest().administratorCredential)} as any);
    const task=resources.find(r=>r.kind==='task'),route=await resolved(resources.find(r=>r.kind==='parameter').args.value);
    const map=JSON.parse(route),parsed=map.route;expect(task.args.permissions).toEqual([]);expect(Object.keys(unwrap(task.args.ssm))).toHaveLength(6);
    const taskRole:any={inlinePolicies:['wrong'],managedPolicyArns:['wrong']},execution:any={};task.args.transform.taskRole(taskRole);task.args.transform.executionRole(execution);
    expect(taskRole.inlinePolicies).toEqual([]);expect(taskRole.managedPolicyArns).toEqual([]);
    const policy=JSON.parse(unwrap(execution.inlinePolicies[0].policy));expect(policy.Statement[0].Resource).toHaveLength(6);expect(policy.Statement[1].Resource).toBe(parsed.kmsKeyArn);
    expect(JSON.stringify(policy)).not.toMatch(/administrator-backup|transition-credential|database-credential/);
    const container={name:task.name,image:parsed.image,entryPoint:['node'],command:unwrap(task.args.command),environment:Object.entries(unwrap(task.args.environment)).map(([name,value])=>({name,value})),
      secrets:Object.entries(unwrap(task.args.ssm)).map(([name,valueFrom])=>({name,valueFrom})),logConfiguration:{logDriver:'awslogs',options:{'awslogs-group':'/sst/mem9-on-aws/pr-7/operator','awslogs-region':data.region,'awslogs-stream-prefix':'ecs'}}};
    const def:any={containerDefinitions:out(JSON.stringify([container]))};task.args.transform.taskDefinition(def);
    const full={...def,containerDefinitions:JSON.parse(unwrap(def.containerDefinitions)),taskDefinitionArn:parsed.taskDefinitionArn,networkMode:'awsvpc',requiresCompatibilities:['FARGATE'],runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'},cpu:'256',memory:'512',taskRoleArn:parsed.taskRoleArn,executionRoleArn:parsed.executionRoleArn};
    const expected={stage:'pr-7',account:data.account,region:data.region,generation:config.generation,context,controlSourceTree:data.controlSourceTree,runtime:state,manifest:manifest()};
    expect(map.bindings).toHaveLength(5);expect(new Set(map.bindings.map((r:any)=>r.taskDefinitionArn)).size).toBe(5);
    expect(observed.calls).toHaveLength(5);expect(observed.calls.every(c=>c.include.join()==='TAGS')).toBe(true);
    expect(resources.filter(r=>r.kind==='definition')).toHaveLength(4);
    const expectedTags={Project:'mem9-on-aws',Stage:'pr-7',ManagedBy:'sst','sst:app':'mem9-on-aws','sst:stage':'pr-7'};
    for(const row of resources.filter(r=>r.kind==='definition')){
      expect(row.args.tags).toEqual(expectedTags);expect(Object.fromEntries(row.request.tags.map((t:any)=>[t.key,t.value]))).toEqual(expectedTags);
    }
    for(const value of observed.definitions.values())expect(Object.fromEntries(value.tags.map((t:any)=>[t.key,t.value]))).toEqual(expectedTags);
    expect(validatePostRuntimeRoute(parsed,expected)).toEqual(parsed);
    for(const purpose of POST_RUNTIME_PURPOSES){
      const selected=selectGuardedPostRuntimeRoute(map,expected,purpose),o=observed.definitions.get(selected.taskDefinitionArn);
      expect(()=>validatePostRuntimeDefinition(o.taskDefinition,selected,o)).not.toThrow();
      expect(o.taskDefinition.family).toBe(observed.value.taskDefinition.family);
      expect(o.taskDefinition.taskRoleArn).toBe(parsed.taskRoleArn);expect(o.taskDefinition.executionRoleArn).toBe(parsed.executionRoleArn);
      expect(o.taskDefinition.containerDefinitions[0].secrets).toEqual(observed.value.taskDefinition.containerDefinitions[0].secrets);
      expect(o.taskDefinition.containerDefinitions[0].command).toEqual([]);
    }
    expect(full.containerDefinitions[0].entryPoint).toEqual(['/bin/setpriv','--no-new-privs','--','/usr/local/bin/node','/bootstrap/nonroot-dispatch.mjs','post-runtime-fixture']);
    expect(full.containerDefinitions[0].user).toBe('1000:1000');
    expect(unwrap(task.args.environment)).toEqual(postRuntimeOperatorEnvironment(parsed));
  });
});
