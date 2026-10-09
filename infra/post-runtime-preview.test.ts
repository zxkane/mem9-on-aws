import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {POST_RUNTIME_PURPOSES,postRuntimeOperatorEnvironment,selectGuardedPostRuntimeRoute,validatePostRuntimeDefinition,validatePostRuntimeRoute} from '../scripts/lib/post-runtime-preview-route.mjs';
import {previewRegistrationFromProviderArgs} from '../scripts/lib/nonroot-preview-source.mjs';
const state=vi.hoisted(()=>({stage:'pr-7',phase:'complete',status:'running',nonce:'b'.repeat(32)}));
const data=vi.hoisted(()=>({stage:'pr-7',account:'123456789012',region:'ap-northeast-1',runtimeNonce:'b'.repeat(32),generation:'a'.repeat(64),controlSourceTree:'c'.repeat(40)}));
const out=<T>(value:T):any=>({value,apply(fn:any){const run=(v:any)=>{const next=fn(v);return next&&typeof next==='object'&&'apply'in next?next.value:next;};return out(value instanceof Promise?value.then(run):run(value));}});
const unwrap=(v:any):any=>v instanceof Promise?v:v&&typeof v==='object'&&'apply'in v?unwrap(v.value):Array.isArray(v)?v.map(unwrap):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).map(([k,x])=>[k,unwrap(x)])):v;
async function resolved(v:any):Promise<any>{if(v instanceof Promise)return resolved(await v);if(v&&typeof v==='object'&&'apply'in v)return resolved(v.value);if(Array.isArray(v))return Promise.all(v.map(resolved));if(v&&typeof v==='object')return Object.fromEntries(await Promise.all(Object.entries(v).map(async([k,x])=>[k,await resolved(x)])));return v;}
const asynchronous=(v:any):boolean=>v instanceof Promise||!!(v&&typeof v==='object'&&Object.values(v).some(asynchronous));
const observed=vi.hoisted(()=>({value:undefined as any,definitions:new Map<string,any>(),revision:7}));
vi.mock('@aws-sdk/client-ecs',()=>({DescribeTaskDefinitionCommand:class{input;constructor(input:any){this.input=input;}},ECSClient:class{async send(c:any){return observed.definitions.get(c.input.taskDefinition);}destroy(){}}}));
vi.mock('./ecr',()=>({accountId:()=>out(data.account),applicationRegion:()=>out(data.region),selectedDataRelease:()=>out({data})}));
vi.mock('./vpc',()=>({resolveVpc:()=>({privateSubnetIds:out(['subnet-aaaabbbb'])})}));
const manifest=()=>({version:1,stage:'pr-7',mode:'active',account:data.account,region:data.region,clusterArn:`arn:aws:ecs:${data.region}:${data.account}:cluster/mem9-on-aws-pr-7-Cluster-example`,
  subnets:['subnet-aaaabbbb'],securityGroup:'sg-aaaabbbb',host:'writer.example.com',port:5432,database:'mem9',administratorCredential:`arn:aws:ssm:${data.region}:${data.account}:parameter/mem9-on-aws/pr-7/runtime/schema-administrator-credential`});
let resources:any[];
function setup(stage='pr-7'){
  vi.stubGlobal('$app',{name:'mem9-on-aws',stage});vi.stubGlobal('$jsonStringify',(x:any)=>{const value=unwrap(x);return out(asynchronous(value)?resolved(value).then(JSON.stringify):JSON.stringify(value));});
  vi.stubGlobal('$interpolate',(parts:any,...values:any[])=>out(parts.reduce((s:string,p:string,i:number)=>s+p+(i<values.length?String(unwrap(values[i])):''),'')));
  vi.stubGlobal('aws',{ssm:{getParameterOutput:({name}:any)=>out({value:JSON.stringify(name.endsWith('/production-state')?state:manifest())}),
    Parameter:class{constructor(name:string,args:any){resources.push({kind:'parameter',name,args});}}},
    ecr:{getImageOutput:()=>({imageDigest:out('sha256:'+'d'.repeat(64))})},
    ecs:{TaskDefinition:class{
      arn;
      constructor(name:string,args:any){
        const {tags,...body}=previewRegistrationFromProviderArgs(args),revision=++observed.revision;
        const arn=`arn:aws:ecs:${data.region}:${data.account}:task-definition/${body.family}:${revision}`;
        const value={taskDefinition:{...body,taskDefinitionArn:arn,revision,status:'ACTIVE',registeredAt:'2026-10-08T00:00:00.000Z',
          registeredBy:`arn:aws:sts::${data.account}:assumed-role/preview/session`,requiresAttributes:[],compatibilities:['FARGATE']},tags};
        observed.definitions.set(arn,value);resources.push({kind:'definition',name,args});this.arn=out(arn);
      }
    }},
    kms:{getKeyOutput:()=>({arn:out(`arn:aws:kms:${data.region}:${data.account}:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee`)})}});
  vi.stubGlobal('sst',{aws:{Task:class{
    taskDefinition;nodes;
    constructor(name:string,args:any){resources.push({kind:'task',name,args});this.taskDefinition=out(`arn:aws:ecs:${data.region}:${data.account}:task-definition/mem9-on-aws-pr-7-Cluster-example-${name}:7`);
      this.nodes={taskRole:{arn:out(`arn:aws:iam::${data.account}:role/mem9-on-aws-pr-7-${name}TaskRole-role-test`)},executionRole:{arn:out(`arn:aws:iam::${data.account}:role/mem9-on-aws-pr-7-${name}ExecutionRole-role-test`)}};
      const c={name,image:unwrap(args.image),entrypoint:args.entrypoint,command:args.command,
        environment:Object.entries(unwrap(args.environment)).map(([name,value])=>({name,value})),
        secrets:Object.entries(unwrap(args.ssm)).map(([name,valueFrom])=>({name,valueFrom})),
        logConfiguration:{logDriver:'awslogs',options:{'awslogs-group':'/sst/mem9-on-aws/pr-7/operator','awslogs-region':data.region,'awslogs-stream-prefix':'ecs'}}};
      const generated:any={family:'mem9-on-aws-pr-7-Cluster-example-'+name,containerDefinitions:out(JSON.stringify([c])),trackLatest:true,
        taskRoleArn:this.nodes.taskRole.arn,executionRoleArn:this.nodes.executionRole.arn,networkMode:'awsvpc',requiresCompatibilities:['FARGATE'],
        runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'},cpu:'256',memory:'512'};
      args.transform.taskDefinition(generated);
      const {tags,...registration}=previewRegistrationFromProviderArgs(unwrap(generated));
      observed.value={taskDefinition:{...registration,taskDefinitionArn:unwrap(this.taskDefinition),revision:7,status:'ACTIVE',registeredAt:'2026-10-08T00:00:00.000Z',
        registeredBy:`arn:aws:sts::${data.account}:assumed-role/preview/session`,requiresAttributes:[],compatibilities:['FARGATE']},tags};
      observed.definitions.set(unwrap(this.taskDefinition),observed.value);
      Object.assign(this.nodes,{taskDefinition:out({arn:this.taskDefinition})});
    }
  }}});
}
const context={kind:'post-runtime' as const,runtimeNonce:'b'.repeat(32)};
const db=()=>({host:out('writer.example.com'),port:out(5432),database:out('mem9'),taskSecurityGroupId:out('sg-aaaabbbb')});
const ecs=()=>({cluster:{},clusterName:out('mem9-on-aws-pr-7-Cluster-example')});
describe('post-runtime preview resources',()=>{
  beforeEach(()=>{vi.resetModules();resources=[];observed.definitions.clear();observed.revision=7;Object.assign(state,{stage:'pr-7',phase:'complete',status:'running',nonce:'b'.repeat(32)});vi.stubEnv('MEM9_IMAGE_TAG','pr-abcdef0');setup();});
  afterEach(()=>{vi.unstubAllGlobals();vi.unstubAllEnvs();});
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
    expect(resources.filter(r=>r.kind==='definition')).toHaveLength(4);
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
