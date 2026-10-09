import {runtime,output, type Output} from '@pulumi/pulumi';
import {NONROOT_POSTAPPLY_FUNCTIONS as functions,NONROOT_POSTAPPLY_RESOURCES as selection} from '../scripts/lib/nonroot-postapply.mjs';
import {captureSstPostApplyOutputs} from '../scripts/lib/nonroot-postapply-capture.mjs';

type Node = Record<string, unknown>;
declare const $cli: {command:string;paths:{root:string;work:string}};
const pick=(value:Node,keys:readonly string[])=>Object.fromEntries(keys.map(key=>[key,value[key]??null]));
/** Observe fixed resources, including children registered inside Output.apply.
 * No constructor argument, permission, provider or dependency is changed. */
export function installNonrootDeploymentCapture(){
 if($app.stage!=='prod'||$cli.command!=='deploy'||runtime.isDryRun()||process.env.GITHUB_JOB!=='deploy-prod'||!process.env.MEM9_CI_ACQUISITION_CONFIG)return null;
 const config=JSON.parse(process.env.MEM9_CI_ACQUISITION_CONFIG);if(config.version!==3)return null;
 const deadline=config.startup?.notAfter;if(!Number.isSafeInteger(deadline)||deadline<=Date.now())throw Error('PostApplyExpired');
 const slots=new Map<string,{promise:Promise<Node>;resolve:(r:Node)=>void;seen:boolean}>();
 for(const key of [...functions,...Object.keys(selection)]){
  let resolve!:(r:Node)=>void;const promise=new Promise<Node>(r=>{resolve=r;});slots.set(key,{promise,resolve,seen:false});
 }
 runtime.registerStackTransformation(args=>{
  let key:string|undefined;
  if(args.type==='sst:aws:Function'&&functions.includes(args.name))key=args.name;
  for(const [name,spec]of Object.entries(selection)){
   const expectedName=name==='Mem9ProxyFnEnvironmentUpdate'?name+'.sst.aws.FunctionEnvironmentUpdate':name;
   const expectedType=name==='Mem9ProxyFnEnvironmentUpdate'?'pulumi-nodejs:dynamic:Resource':spec.type;
   if(args.name===expectedName&&args.type===expectedType)key=name;
  }
  if(key){const slot=slots.get(key)!;if(slot.seen)throw Error('PostApplyDuplicateResource');slot.seen=true;
   // Transformations run in the base constructor, before subclass output fields
   // exist. Observe the completed constructor on the next event-loop turn.
   setImmediate(()=>slot.resolve(args.resource as unknown as Node));
  }
  return undefined;
 });
 let completed=false;
 return {complete():Promise<string>{
  if(completed)throw Error('PostApplyDuplicateCompletion');completed=true;
  let timer:ReturnType<typeof setTimeout>,terminal=false;
  const expired=new Promise<never>((_,reject)=>{timer=setTimeout(()=>reject(Error('PostApplyResourceDeadline')),Math.min(deadline-Date.now(),2147483647));});
  const capture=new Promise<string>((resolve,reject)=>{Promise.all([...slots].map(async([key,slot])=>[key,await slot.promise] as const)).then(rows=>{
   const observed=new Map(rows),resources:Node={},captured:Node={};
   for(const [key,spec]of Object.entries(selection))resources[key]=pick(observed.get(key)!,spec.fields);
   for(const name of functions){const c=observed.get(name) as {nodes?:{function:Node|Output<Node>;role:Node|Output<Node>}};
    if(!c.nodes)throw Error('PostApplyFunctionMissing');
    captured[name]=output<Node>(c.nodes.function).apply(f=>output<Node>(c.nodes!.role).apply(role=>({
     ...pick(f,['arn','codeSha256','s3Key','runtime','architectures','handler','vpcConfig']),
     role:pick(role,['arn','name','uniqueId','assumeRolePolicy','inlinePolicies','managedPolicyArns','permissionsBoundary']),
     environment:output<Record<string,unknown>>(f.environment as Record<string,unknown>).apply(env=>env.variables),
    })));
   }
   return output({functions:captured,resources}).apply(async value=>{
    const data=JSON.parse(JSON.stringify(value));Object.assign(data.functions.Mem9ProxyFn.environment,data.resources.Mem9ProxyFnEnvironmentUpdate.environment);
    const e=data.resources.Mem9GatewayTarget.environment;
    data.resources.Mem9GatewayTarget.environment=Object.fromEntries(['MEM9_TGT_REGION','MEM9_TGT_GATEWAY_ID','MEM9_TGT_NAME','MEM9_TGT_LAMBDA_ARN'].map(k=>[k,e[k]]));
    try{if(terminal||Date.now()>=deadline)throw Error('PostApplyResourceDeadline');resolve(await captureSstPostApplyOutputs({env:process.env,root:$cli.paths.root,work:$cli.paths.work,...data}));}catch(error){reject(error);}
   });
  }).catch(reject);});
  // Flatten both the registered-resource promises and all nested provider
  // Outputs before ending the inherited deadline guard.
  return Promise.race([capture,expired]).finally(()=>{terminal=true;clearTimeout(timer);});
 }};
}
