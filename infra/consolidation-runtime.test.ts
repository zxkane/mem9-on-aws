import {afterEach,beforeEach,describe,expect,it,vi} from "vitest";
type Box<T>={value:T;apply:(fn:(v:T)=>unknown)=>unknown};
const out=<T>(value:T):Box<T>=>({value,apply(fn){const r=fn(value);return r&&typeof r==="object"&&"apply" in r?r:out(r);}});
const value=(v:any):any=>v&&typeof v==="object"&&"apply" in v?value(v.value):Array.isArray(v)?v.map(value):v&&typeof v==="object"?Object.fromEntries(Object.entries(v).map(([k,x])=>[k,value(x)])):v;
let resources:{kind:string;name:string;args:any}[];
vi.mock("./ecr",()=>({accountId:()=>out("123456789012"),applicationRegion:()=>out("ap-northeast-1"),workloadImage:()=>out("preview-image")}));
function setup(stage:string){
  vi.stubGlobal("$app",{stage,name:"mem9-on-aws"});
  vi.stubGlobal("$jsonStringify",(x:unknown)=>out(JSON.stringify(value(x))));
  vi.stubGlobal("$interpolate",(parts:TemplateStringsArray,...values:unknown[])=>out(parts.reduce((s,p,i)=>s+p+(i<values.length?String(value(values[i])):""),"")));
  vi.stubGlobal("random",{RandomPassword:class{result;constructor(name:string,args:any){resources.push({kind:"password",name,args});this.result=out("synthetic-secret-"+name);}}});
  vi.stubGlobal("aws",{ssm:{Parameter:class{arn;name;constructor(name:string,args:any){resources.push({kind:"parameter",name,args});this.name=args.name;this.arn=out("arn:aws:ssm:ap-northeast-1:123456789012:parameter"+args.name);}}}});
  vi.stubGlobal("sst",{aws:{Task:class{taskDefinition;nodes;subnets;securityGroups;assignPublicIp;
    constructor(name:string,args:any){resources.push({kind:"task",name,args});this.taskDefinition=out("arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-on-aws-"+stage+"-"+name+":1");
      this.nodes={taskRole:{arn:out("task-role-"+name)},executionRole:{arn:out("execution-role-"+name)}};this.subnets=out(["subnet-private"]);this.securityGroups=out(["sg-task"]);this.assignPublicIp=false;}
  }}});
}
const db=()=>({host:out("db.example.com"),port:out(5432),database:out("mem9"),secretArn:out("owner-secret"),taskSecurityGroupId:out("sg-task"),ssmPrefix:"/mem9-on-aws/pr-7"});
const ecs=()=>({cluster:{nodes:{cluster:{arn:out("cluster-arn"),name:out("cluster-name")}}},serviceDnsName:out("server.internal")});
describe("continuous consolidation preview resources",()=>{
  beforeEach(()=>{vi.resetModules();resources=[];vi.stubEnv("MEM9_DEPLOY_COMMIT","a".repeat(40));vi.stubEnv("GITHUB_RUN_ID","7");vi.stubEnv("GITHUB_RUN_ATTEMPT","1");});
  afterEach(()=>{vi.unstubAllGlobals();vi.unstubAllEnvs();});
  it.each(["prod","dev","pr-invalid"])("creates no new credentials or workers in %s",async stage=>{
    setup(stage);const {consolidationPreviewConfig}=await import("./consolidation-runtime");
    expect(consolidationPreviewConfig()).toBeUndefined();expect(resources).toEqual([]);
  });
  it.each(["prod","dev","pr-invalid"])("creates no runtime administrator probe credential in %s",async stage=>{
    setup(stage);const {runtimeCredentials}=await import("./runtime-credentials");
    expect(runtimeCredentials()).toBeUndefined();expect(resources).toEqual([]);
  });
  it("keeps the preview authority-probe credential independent from application runtime",async()=>{
    setup("pr-7");const {runtimeCredentials}=await import("./runtime-credentials");
    const config=runtimeCredentials()!;
    expect(value(config.probeParameterArn)).not.toBe(value(config.parameterArn));
    const probe=resources.find(r=>r.kind==="parameter"&&r.name==="RuntimeAdminProbeCredential")!;
    expect(probe.args.name).toBe("/mem9-on-aws/pr-7/runtime/admin-probe-credential");
    expect(probe.args.type).toBe("SecureString");
    const parsed=JSON.parse(value(probe.args.value));
    expect(parsed.username).toMatch(/^mem9_probe_[a-f0-9]{12}$/);
    expect(parsed.password).not.toContain("RuntimeDatabasePassword");
  });
  it("pins preview generation and keeps credentials in SecureString outputs",async()=>{
    setup("pr-7");const {consolidationPreviewConfig}=await import("./consolidation-runtime");const config=consolidationPreviewConfig()!;
    expect(config.generation).toMatch(/^[a-f0-9]{64}$/);
    const parameters=resources.filter(r=>r.kind==="parameter");expect(parameters.length).toBeGreaterThan(5);
    expect(parameters.every(r=>r.args.type==="SecureString")).toBe(true);
    const ids=JSON.parse(value(config.values.config));expect(ids.tenantId).toMatch(/^[0-9a-f]{32}$/);
    expect(ids.namespaces).toHaveLength(3);expect(new Set(ids.namespaces).size).toBe(3);
  });
  it("separates worker credentials and replaces SST wildcard secret-read permissions",async()=>{
    setup("pr-7");const {consolidationPreviewConfig,continuousConsolidationTasks}=await import("./consolidation-runtime");
    const config=consolidationPreviewConfig()!;
    const workers=continuousConsolidationTasks(ecs() as any,db() as any,config,{serviceParameterArns:{consolidation:out("consolidation-signing")}} as any);
    expect(workers.map(w=>w.kind)).toEqual(["planner","executor"]);
    const planner=resources.find(r=>r.kind==="task"&&r.name.endsWith("Planner"))!;
    const executor=resources.find(r=>r.kind==="task"&&r.name.endsWith("Executor"))!;
    expect(Object.keys(planner.args.ssm).sort()).toEqual(["MEM9_PLANNER_DB_SECRET","MEM9_WORKER_TARGETS"]);
    expect(Object.keys(executor.args.ssm).sort()).toEqual(["MEM9_EXECUTOR_DB_SECRET","MEM9_SERVICE_TRANSPORT_SIGNING_KEYS","MEM9_TENANT_ID","MEM9_WORKER_TARGETS"]);
    expect(JSON.stringify(value(planner.args))).not.toContain("owner-secret");
    expect(executor.args.permissions).toEqual([]);
    const role:any={managedPolicyArns:["ecs-execution-baseline"],inlinePolicies:[{policy:"wildcard"}]};
    planner.args.transform.executionRole(role);
    expect(role.managedPolicyArns).toEqual(["ecs-execution-baseline"]);
    const policy=JSON.parse(value(role.inlinePolicies[0].policy));
    expect(policy.Statement[0].Action).toEqual(["ssm:GetParameters"]);
    expect(policy.Statement[0].Resource).not.toContain("*");
    expect(JSON.stringify(policy)).not.toContain("executor-credential");
    expect(JSON.stringify(policy)).not.toContain("secretsmanager:GetSecretValue");
    expect(value(planner.args.environment).MEM9_WORKER_GENERATION).toBe(config.generation);
  });
});
