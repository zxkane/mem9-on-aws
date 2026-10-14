import {test,expect,vi,afterEach} from 'vitest';
import {observerTopologyResources,observerWorkerTemplate,publishObserverTopology} from './observer-topology';
class Out<T>{constructor(public value:T){}apply<U>(f:(x:T)=>U){return new Out(f(this.value));}}
function setup(stage='pr-42'){
 const resources:any[]=[];const un=(v:any):any=>v instanceof Out?un(v.value):Array.isArray(v)?v.map(un):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).map(([k,x])=>[k,un(x)])):v;
 class Service{ id:Out<string>;arn:Out<string>;constructor(name:string,args:any){resources.push({type:'CloudMapService',name,args:un(args)});this.id=new Out('srv-synthetic'+resources.length);this.arn=new Out('arn:aws:servicediscovery:ap-northeast-1:123456789012:service/'+this.id.value);}}
 class Definition{arn:Out<string>;constructor(name:string,args:any){resources.push({type:'TaskDefinition',name,args:un(args)});this.arn=new Out('arn:aws:ecs:ap-northeast-1:123456789012:task-definition/'+args.family+':1');}}
 class Parameter{constructor(name:string,args:any){resources.push({type:'Parameter',name,args:un(args)});}}
 vi.stubGlobal('$app',{stage});vi.stubGlobal('aws',{servicediscovery:{Service},ecs:{TaskDefinition:Definition},ssm:{Parameter}});vi.stubGlobal('$util',{all:(xs:any[])=>new Out(xs.map(un))});vi.stubGlobal('$jsonStringify',(x:any)=>new Out(JSON.stringify(un(x))));return {resources};
}
afterEach(()=>vi.unstubAllGlobals());
test('default and production paths create no observer resources',()=>{const f=setup();expect(observerTopologyResources({id:'ns-test',arn:'namespace'},undefined)).toBeUndefined();expect(f.resources).toEqual([]);setup('prod');expect(()=>observerTopologyResources({id:'ns-test',arn:'namespace'},JSON.stringify({owner:'a'.repeat(32),operation:'b'.repeat(32)}))).toThrow();});
test('selected graph contains five empty registries, two exact mirrors, one separate metadata output and no role/service/task run',()=>{
 const f=setup(),t=observerTopologyResources({id:'ns-test',arn:'namespace'},JSON.stringify({owner:'a'.repeat(32),operation:'b'.repeat(32)}))!;
 const originals:any[]=[];const workers:Record<string,any>={};
 for(const kind of ['planner','executor'] as const){const args={family:'normal-'+kind,taskRoleArn:'original-task-role',executionRoleArn:'original-execution-role',networkMode:'awsvpc',requiresCompatibilities:['FARGATE'],cpu:'512',memory:'1024',runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'},tags:{Project:'mem9-on-aws',Stage:'pr-42'},containerDefinitions:new Out(JSON.stringify([{name:kind,user:'1000:1000',entryPoint:['/usr/bin/setpriv','--no-new-privs','--','/usr/local/bin/node'],command:['/app/scripts/consolidation-worker.mjs'],environment:[{name:'MEM9_BASE_URL',value:'http://main.example.com:8080'},{name:'MEM9_WORKER_GENERATION',value:'generation'}],secrets:[{name:'MEM9_WORKER_TARGETS',valueFrom:'original-parameter'}]}]))};originals.push(args);workers[kind]=observerWorkerTemplate(kind,args,t).arn;}
 publishObserverTopology(t,'generation',workers);
 expect(f.resources.map(r=>r.type)).toEqual([...Array(5).fill('CloudMapService'),'TaskDefinition','TaskDefinition','Parameter']);expect(new Set(t.cases.map(c=>c.privateOrigin)).size).toBe(5);
 for(const [i,r]of f.resources.filter(r=>r.type==='TaskDefinition').entries()){const {family,tags,containerDefinitions,...rest}=r.args;const {family:_f,tags:_t,containerDefinitions:_c,...before}=originals[i];expect(rest).toEqual(before);const app=JSON.parse(containerDefinitions)[0];expect(app.environment.find((e:any)=>e.name==='MEM9_BASE_URL').value).toBe(t.cases[0].privateOrigin);expect(app.secrets).toEqual(JSON.parse(originals[i].containerDefinitions.value)[0].secrets);}
 expect(f.resources.at(-1).args.name).toMatch(/\/observer-topology$/);console.log('OBSERVER_GRAPH_JSON='+JSON.stringify({synthetic:true,authority:false,resources:f.resources}));
});
