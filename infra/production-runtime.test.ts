import {describe,it,expect,vi,afterEach} from "vitest";

type Box<T>={value:T;apply:(fn:(value:T)=>unknown)=>unknown};
const out=<T>(value:T):Box<T>=>({value,apply(fn){const next=fn(value);return next&&typeof next==="object"&&"apply" in next?next:out(next);}});
const unwrap=(value:any):any=>value&&typeof value==="object"&&"apply" in value?unwrap(value.value):
  Array.isArray(value)?value.map(unwrap):value&&typeof value==="object"?Object.fromEntries(Object.entries(value).map(([k,v])=>[k,unwrap(v)])):value;
vi.mock("./ecr",()=>({accountId:()=>out("123456789012"),applicationRegion:()=>out("ap-northeast-1"),workloadImage:()=>out("image")}));
const images=Object.fromEntries(["mnemo-server","qwen3-embed","llm-proxy"].map(name=>[name,`123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/${name}@sha256:${"a".repeat(64)}`]));
function setup(stage:string){
  const resources:Array<{type:string;name:string;args:any}>=[];
  vi.stubGlobal("$app",{stage,name:"mem9-on-aws"});
  vi.stubGlobal("$jsonStringify",(value:unknown)=>out(JSON.stringify(unwrap(value))));
  vi.stubGlobal("$interpolate",(parts:TemplateStringsArray,...values:unknown[])=>out(parts.reduce((s,p,i)=>s+p+(i<values.length?String(unwrap(values[i])):""),"")));
  vi.stubGlobal("random",{RandomPassword:class{result;constructor(name:string,args:any){resources.push({type:"password",name,args});this.result=out(name+"Synthetic");}}});
  vi.stubGlobal("aws",{ssm:{Parameter:class{arn;constructor(name:string,args:any){resources.push({type:"parameter",name,args});this.arn=out("arn:aws:ssm:ap-northeast-1:123456789012:parameter"+args.name);}}},
    iam:{Role:class{arn;constructor(name:string,args:any){resources.push({type:"role",name,args});this.arn=out("arn:role/"+name);}}}});
  const identity={tenantSecretArn:out("tenant-secret"),tenantId:out("synthetic-tenant")};
  const namespace={transportSigningParameterArn:out("namespace-signing")};
  const maintenance={bundleParameterArn:out("service-signing")};
  return {resources,identity,namespace,maintenance};
}
afterEach(()=>{vi.unstubAllGlobals();vi.unstubAllEnvs();vi.resetModules();});
describe("production runtime preparation",()=>{
  it("does not create production credentials by omission",async()=>{
    const f=setup("prod");vi.stubEnv("MEM9_PRODUCTION_RUNTIME_MODE","");
    const {productionRuntimeResources}=await import("./production-runtime");
    expect(()=>productionRuntimeResources(undefined,f.identity as any,f.namespace as any,f.maintenance as any)).toThrow("InvalidProductionRuntimeMode");
    vi.stubEnv("MEM9_PRODUCTION_RUNTIME_MODE","off");
    expect(productionRuntimeResources(undefined,f.identity as any,f.namespace as any,f.maintenance as any)).toBeUndefined();
    expect(f.resources).toEqual([]);
  });
  it("validates the pinned fallback before provisioning anything",async()=>{
    const f=setup("prod");vi.stubEnv("MEM9_PRODUCTION_RUNTIME_MODE","prepare");vi.stubEnv("MEM9_NAMESPACE_REQUIRED","1");
    const {productionRuntimeResources}=await import("./production-runtime");
    expect(()=>productionRuntimeResources(undefined,f.identity as any,f.namespace as any,f.maintenance as any)).toThrow("RuntimeFallbackDigestRequired");
    expect(f.resources).toEqual([]);
  });
  it("separates administrator, runtime and transition references and never injects the backup into a role",async()=>{
    const f=setup("prod");vi.stubEnv("MEM9_PRODUCTION_RUNTIME_MODE","prepare");vi.stubEnv("MEM9_NAMESPACE_REQUIRED","1");
    vi.stubEnv("MEM9_RUNTIME_FALLBACK_IMAGES",JSON.stringify(images));
    const {productionRuntimeResources}=await import("./production-runtime");
    const config=productionRuntimeResources(undefined,f.identity as any,f.namespace as any,f.maintenance as any)!;
    expect(config.active).toBe(false);expect(config.runtime.ready).toBe(false);
    expect(new Set([config.runtime.parameterArn,config.administratorArn,config.transitionArn].map(unwrap)).size).toBe(3);
    const parameters=f.resources.filter(r=>r.type==="parameter");expect(parameters.every(p=>p.args.type==="SecureString")).toBe(true);
    expect(unwrap(parameters.find(p=>p.name==="SchemaAdministratorCredential")!.args.value)).toBe(unwrap(parameters.find(p=>p.name==="SchemaAdministratorBackup")!.args.value));
    const roles=f.resources.filter(r=>r.type==="role");
    expect(JSON.stringify(unwrap(roles))).not.toContain("schema-administrator-backup");
    const runtime=JSON.parse(unwrap(roles.find(r=>r.name==="RuntimeMem9ServerExecutionRole")!.args.inlinePolicies[0].policy));
    expect(JSON.stringify(runtime)).not.toContain("schema-administrator-credential");
    expect(JSON.stringify(runtime)).not.toContain("transition-credential");
  });
  it("fences replacements before retirement and keeps the same policy identity at retirement",async()=>{
    setup("prod");vi.stubEnv("MEM9_PRODUCTION_RUNTIME_MODE","prepare");
    const {protectLegacyRuntimeCredentials}=await import("./production-runtime");
    const before:any={inlinePolicies:out([{name:"old",policy:"existing"}])};protectLegacyRuntimeCredentials(before);
    const policy=unwrap(before.inlinePolicies).at(-1);expect(policy.name).toBe("ProductionCredentialFence");
    expect(JSON.parse(policy.policy).Statement.some((s:any)=>s.Action.includes("ssm:GetParametersByPath")&&s.Resource==="*")).toBe(true);
    vi.stubEnv("MEM9_PRODUCTION_RUNTIME_MODE","active");
    const after:any={inlinePolicies:[]};protectLegacyRuntimeCredentials(after);
    expect(unwrap(after.inlinePolicies)[0].name).toBe(policy.name);
    expect(JSON.parse(unwrap(after.inlinePolicies)[0].policy).Statement[0]).toMatchObject({Effect:"Deny",Resource:"*"});
  });
  it("preserves existing ECS trust while fencing legacy credentials",async()=>{
    setup("prod");
    const {protectLegacyRuntimeCredentials}=await import("./production-runtime");
    const trust=out(JSON.stringify({Version:"2012-10-17",Statement:[{
      Effect:"Allow",Action:"sts:AssumeRole",Principal:{Service:"ecs-tasks.amazonaws.com"},
    }]}));
    for(const mode of ["prepare","paused","ready","active"]){
      vi.stubEnv("MEM9_PRODUCTION_RUNTIME_MODE",mode);
      const args:any={assumeRolePolicy:trust,inlinePolicies:[]};
      protectLegacyRuntimeCredentials(args);
      expect(args.assumeRolePolicy).toBe(trust);
      expect(unwrap(args.inlinePolicies)).toHaveLength(1);
    }
  });
});
