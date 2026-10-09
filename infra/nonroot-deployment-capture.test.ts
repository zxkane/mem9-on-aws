import {it,expect,vi,afterEach} from 'vitest';
import * as pulumi from '@pulumi/pulumi';
import {NONROOT_POSTAPPLY_FUNCTIONS as functions,NONROOT_POSTAPPLY_RESOURCES as resources} from '../scripts/lib/nonroot-postapply.mjs';
import {installNonrootDeploymentCapture} from './nonroot-deployment-capture';
const {capture}=vi.hoisted(()=>({capture:vi.fn(async()=> 'a'.repeat(64))}));
vi.mock('../scripts/lib/nonroot-postapply-capture.mjs',()=>({captureSstPostApplyOutputs:capture}));
afterEach(()=>{vi.unstubAllEnvs();vi.unstubAllGlobals();vi.clearAllMocks();});
it('real Pulumi transformations wait for asynchronously registered resources and nested Outputs',async()=>{
 vi.stubEnv('GITHUB_JOB','deploy-prod');vi.stubEnv('MEM9_CI_ACQUISITION_CONFIG',JSON.stringify({version:3,startup:{notAfter:Date.now()+10000}}));
 vi.stubGlobal('$app',{name:'mem9-on-aws',stage:'prod'});vi.stubGlobal('$cli',{command:'deploy',paths:{root:'/synthetic',work:'/synthetic/.sst'}});
 pulumi.runtime.setMocks({newResource:args=>({id:args.name+'-id',state:args.inputs}),call:args=>args.inputs},'mem9-on-aws','prod',false);
 class Fn extends pulumi.ComponentResource{
  nodes:{function:pulumi.OutputInstance<Record<string,unknown>>;role:pulumi.OutputInstance<Record<string,unknown>>};
  constructor(name:string){super('sst:aws:Function',name,{});this.nodes={function:pulumi.output(new Promise<Record<string,unknown>>(resolve=>setImmediate(()=>resolve({arn:name,environment:{variables:{STAGE:'prod'}}})))),role:pulumi.output({arn:name+'-role'})};}
 }
 class ObservedResource extends pulumi.CustomResource{constructor(type:string,name:string,props:Record<string,unknown>){super(type,name,props);}}
 const result=await pulumi.runtime.runInPulumiStack(async()=>{
  const observer=installNonrootDeploymentCapture()!;const out=observer.complete();
  await new Promise<void>(resolve=>setImmediate(resolve));expect(capture).not.toHaveBeenCalled();
  for(const name of functions)new Fn(name);
  // This is the actual scheduling pattern used by SST's late environment
  // resource. Creation happens only after complete() has returned its Output.
  const registered=pulumi.output(Promise.resolve(true)).apply(()=>{
   for(const [key,spec]of Object.entries(resources)){
    const name=key==='Mem9ProxyFnEnvironmentUpdate'?key+'.sst.aws.FunctionEnvironmentUpdate':key;
    const type=key==='Mem9ProxyFnEnvironmentUpdate'?'pulumi-nodejs:dynamic:Resource':spec.type;
    const fields:Record<string,unknown>=Object.fromEntries(spec.fields.map(f=>[f,null]));
    if(key==='Mem9ProxyFnEnvironmentUpdate')fields.environment={MEM9_SECRET_ENDPOINT_MODE:'private'};
    if(key==='Mem9GatewayTarget')fields.environment={MEM9_TGT_REGION:'us-east-1',MEM9_TGT_GATEWAY_ID:'fixture',MEM9_TGT_NAME:'target',MEM9_TGT_LAMBDA_ARN:'proxy',AWS_SECRET_ACCESS_KEY:'must-not-capture'};
    new ObservedResource(type,name,fields);
   }return true;
  });
  expect(()=>observer.complete()).toThrow('PostApplyDuplicateCompletion');return {hash:await out,registered};
 });
 expect(result).toMatchObject({hash:'a'.repeat(64),registered:true});expect(capture).toHaveBeenCalledTimes(1);
 const packet=capture.mock.calls[0] as unknown as [{functions:Record<string,{environment:Record<string,string>}>;resources:Record<string,{environment:Record<string,string>}>}];
 expect(packet[0].functions.Mem9ProxyFn.environment.MEM9_SECRET_ENDPOINT_MODE).toBe('private');expect(packet[0].resources.Mem9GatewayTarget.environment).not.toHaveProperty('AWS_SECRET_ACCESS_KEY');
});
it('does not install capture for a preview, dry run, or unrelated job',()=>{
 vi.stubGlobal('$app',{stage:'pr-1'});vi.stubGlobal('$cli',{command:'deploy'});expect(installNonrootDeploymentCapture()).toBeNull();
 vi.stubGlobal('$app',{stage:'prod'});vi.stubGlobal('$cli',{command:'diff'});expect(installNonrootDeploymentCapture()).toBeNull();
 vi.stubGlobal('$cli',{command:'deploy'});vi.stubEnv('GITHUB_JOB','other');expect(installNonrootDeploymentCapture()).toBeNull();
});

it('rejects an expired original funding window before installing any capture',()=>{vi.stubGlobal('$app',{stage:'prod'});vi.stubGlobal('$cli',{command:'deploy'});vi.stubEnv('GITHUB_JOB','deploy-prod');vi.stubEnv('MEM9_CI_ACQUISITION_CONFIG',JSON.stringify({version:3,startup:{notAfter:1}}));expect(()=>installNonrootDeploymentCapture()).toThrow('PostApplyExpired');expect(capture).not.toHaveBeenCalled();});

it('missing asynchronous resource fails under the inherited deadline without producing an artifact',async()=>{vi.stubGlobal('$app',{name:'mem9-on-aws',stage:'prod'});vi.stubGlobal('$cli',{command:'deploy',paths:{root:'/synthetic',work:'/synthetic/.sst'}});vi.stubEnv('GITHUB_JOB','deploy-prod');vi.stubEnv('MEM9_CI_ACQUISITION_CONFIG',JSON.stringify({version:3,startup:{notAfter:Date.now()+100}}));await pulumi.runtime.runInPulumiStack(async()=>{await expect(installNonrootDeploymentCapture()!.complete()).rejects.toThrow('PostApplyResourceDeadline');return {};});expect(capture).not.toHaveBeenCalled();});
