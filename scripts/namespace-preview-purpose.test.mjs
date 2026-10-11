import {it,expect} from 'vitest';
import {nonrootPreviewFixture} from './nonroot-preview.fixture.mjs';
import {previewBootstrapRegistration,buildNonrootPreviewPurposeMap,previewBootstrapPurposeForOperation,validateNonrootPreviewOverrides,assertPreviewPurposeMapFits,NONROOT_PREVIEW_BOOTSTRAP_PURPOSES} from './lib/nonroot-preview-source.mjs';
import {loadNonrootPreviewBootstrap,revalidateNonrootPreviewBootstrap} from './lib/post-runtime-preview-aws.mjs';
import {resolveGuardPurpose} from '../docker/bootstrap/nonroot-identity.mjs';

const cases=[['preview-namespace-benchmark','benchmark'],['preview-namespace-connection-snapshot','connection-snapshot']];
const environment=[{name:'AWS_REGION',value:'ap-northeast-1'},{name:'MEM9_DB_HOST',value:'writer.example.com'},
 {name:'MEM9_DB_PORT',value:'5432'},{name:'MEM9_DB_NAME',value:'mem9'},{name:'MEM9_COGNITO_ISSUER',value:'https://issuer.example.com'},
 {name:'MEM9_COGNITO_USER_POOL_ID',value:'synthetic-pool'},{name:'MEM9_AUTH_MODE',value:'managed'},
 {name:'MEM9_PREVIEW_GENERATION',value:'c'.repeat(64)}];
const secrets=[{name:'MEM9_DB_SECRET',valueFrom:'arn:aws:ssm:ap-northeast-1:123456789012:parameter/mem9-on-aws/pr-7/db'},
 {name:'MEM9_RUNTIME_DB_SECRET',valueFrom:'arn:aws:ssm:ap-northeast-1:123456789012:parameter/mem9-on-aws/pr-7/runtime'},
 {name:'MEM9_TENANT_ID',valueFrom:'arn:aws:ssm:ap-northeast-1:123456789012:parameter/mem9-on-aws/pr-7/tenant'}];

function fixture(purpose){
 const f=nonrootPreviewFixture({environment,secrets}),original=f.records[0].registration;
 const registration=previewBootstrapRegistration(original,purpose,f.scope),{tags,...body}=registration,revision=201;
 const observation={taskDefinition:{...body,taskDefinitionArn:`arn:aws:ecs:${f.scope.region}:${f.scope.account}:task-definition/${body.family}:${revision}`,revision,status:'ACTIVE',
  registeredAt:'2026-10-08T00:00:00.000Z',registeredBy:f.records[0].observation.taskDefinition.registeredBy,requiresAttributes:[],compatibilities:['FARGATE']},tags};
 const map=buildNonrootPreviewPurposeMap({scope:f.scope,defaultPurpose:f.map.defaultPurpose,records:[...f.records,{purpose,registration,observation}]});
 f.parameters.get(`/mem9-on-aws/${f.scope.stage}/bootstrap/purpose-bindings`).Value=JSON.stringify(map);
 f.definitions.set(observation.taskDefinition.taskDefinitionArn,observation);
 const calls=[],clients={
  sts:{send:async c=>{calls.push(c.constructor.name);return {Account:f.scope.account};}},
  ssm:{send:async c=>{calls.push(c.constructor.name);return {Parameters:c.input.Names.map(name=>f.parameters.get(name)),InvalidParameters:[]};}},
  ecs:{send:async c=>{calls.push(c.constructor.name);return f.definitions.get(c.input.taskDefinition);}},
 };
 return {...f,original,registration,observation,clients,calls};
}

it.each(cases)('registers and loads the exact guarded namespace purpose %s',async(purpose,operation)=>{
 const f=fixture(purpose),c=f.registration.containerDefinitions[0];
 expect(previewBootstrapPurposeForOperation(operation)).toBe(purpose);
 expect(c.entryPoint.at(-1)).toBe(purpose);expect(c.command).toEqual([]);expect(c.secrets).toEqual([secrets[0]]);
 expect(f.registration.taskRoleArn).toBe(f.original.taskRoleArn);expect(f.registration.executionRoleArn).toBe(f.original.executionRoleArn);
 expect(c.image).toBe(f.original.containerDefinitions[0].image);
 const env=Object.fromEntries(c.environment.map(e=>[e.name,e.value]));
 expect(env.MEM9_BOOTSTRAP_OPERATION).toBe(operation);expect(env.MEM9_PREVIEW_GENERATION).toBeUndefined();
 const binding=await loadNonrootPreviewBootstrap(f.clients,{...f.scope,purpose});
 await revalidateNonrootPreviewBootstrap(f.clients,binding);
 expect(f.calls).toEqual(['GetCallerIdentityCommand','GetParametersCommand','DescribeTaskDefinitionCommand','GetCallerIdentityCommand','GetParametersCommand','DescribeTaskDefinitionCommand']);
 expect(resolveGuardPurpose(purpose,env)).toEqual({kind:'module',module:'/bootstrap/operator/operator-entrypoint.mjs',operation});
 const overrides={containerOverrides:[{name:'Mem9Bootstrap',environment:purpose===cases[0][0]?[{name:'MEM9_NAMESPACE_BENCHMARK_SAMPLES',value:'100'},{name:'MEM9_NAMESPACE_BENCHMARK_WARMUPS',value:'20'}]:[]}]};
 expect(validateNonrootPreviewOverrides(purpose,overrides)).toEqual(overrides);
});

it.each(cases)('rejects operation, identity, command and role overrides for %s',purpose=>{
 const good={containerOverrides:[{name:'Mem9Bootstrap',environment:[]}]};
 for(const name of ['MEM9_BOOTSTRAP_OPERATION','MEM9_STAGE','MEM9_DB_SECRET','MEM9_DB_HOST','MEM9_COGNITO_ISSUER','MEM9_NAMESPACE_IDENTITY_PARAMETER','MEM9_NAMESPACE_CONFIG_PARAMETER','MEM9_TENANT_ID']){
  const value=structuredClone(good);value.containerOverrides[0].environment.push({name,value:'synthetic'});
  expect(()=>validateNonrootPreviewOverrides(purpose,value)).toThrow();
 }
 for(const change of [v=>{v.taskRoleArn='synthetic';},v=>{v.executionRoleArn='synthetic';},v=>{v.containerOverrides[0].command=[];}]){
  const value=structuredClone(good);change(value);expect(()=>validateNonrootPreviewOverrides(purpose,value)).toThrow();
 }
});
it.each([['20','0'],['500','100']])('admits only bounded benchmark counts %s/%s',(samples,warmups)=>{
 const env={MEM9_NAMESPACE_BENCHMARK_SAMPLES:samples,MEM9_NAMESPACE_BENCHMARK_WARMUPS:warmups};
 const overrides={containerOverrides:[{name:'Mem9Bootstrap',environment:Object.entries(env).map(([name,value])=>({name,value}))}]};
 expect(validateNonrootPreviewOverrides(cases[0][0],overrides)).toEqual(overrides);
 const f=fixture(cases[0][0]),base=Object.fromEntries(f.registration.containerDefinitions[0].environment.map(e=>[e.name,e.value]));
 expect(resolveGuardPurpose(cases[0][0],{...base,...env}).operation).toBe('benchmark');
 expect(()=>validateNonrootPreviewOverrides(cases[1][0],overrides)).toThrow();
});
it.each([['MEM9_NAMESPACE_BENCHMARK_SAMPLES','19'],['MEM9_NAMESPACE_BENCHMARK_SAMPLES','501'],['MEM9_NAMESPACE_BENCHMARK_SAMPLES','1e2'],
 ['MEM9_NAMESPACE_BENCHMARK_WARMUPS','-1'],['MEM9_NAMESPACE_BENCHMARK_WARMUPS','101'],['MEM9_NAMESPACE_BENCHMARK_WARMUPS','01']])('denies invalid %s=%s before credentials',(name,value)=>{
 const purpose=cases[0][0],f=fixture(purpose),base=Object.fromEntries(f.registration.containerDefinitions[0].environment.map(e=>[e.name,e.value]));let getters=0;
 const env={...base,[name]:value,get MEM9_DB_SECRET(){getters++;throw Error('must not read');}};
 expect(()=>resolveGuardPurpose(purpose,env)).toThrow('NonrootPurpose');expect(getters).toBe(0);
 expect(()=>validateNonrootPreviewOverrides(purpose,{containerOverrides:[{name:'Mem9Bootstrap',environment:[{name,value}]}]})).toThrow();
});
it.each(cases)('denies foreign stage, wrong operation, missing DB/issuer fields and extra credentials for %s',purpose=>{
 const f=fixture(purpose),base=Object.fromEntries(f.registration.containerDefinitions[0].environment.map(e=>[e.name,e.value]));
 for(const change of [e=>{e.MEM9_STAGE='prod';},e=>{e.MEM9_BOOTSTRAP_OPERATION='runtime-bootstrap';},e=>{delete e.MEM9_DB_HOST;},e=>{delete e.MEM9_COGNITO_ISSUER;},
  e=>{e.MEM9_RUNTIME_DB_SECRET='synthetic';},e=>{e.MEM9_NAMESPACE_CONFIG_PARAMETER='synthetic';},e=>{e.MEM9_NAMESPACE_IDENTITY_PARAMETER='synthetic';}]){
  let getters=0;const env={...base,get MEM9_DB_SECRET(){getters++;throw Error('must not read');}};change(env);
  expect(()=>resolveGuardPurpose(purpose,env)).toThrow('NonrootPurpose');expect(getters).toBe(0);
 }
 for(const change of [v=>{v.containerDefinitions[0].secrets=[];},v=>{v.containerDefinitions[0].environment=v.containerDefinitions[0].environment.filter(e=>e.name!=='MEM9_COGNITO_ISSUER');}]){
  const original=structuredClone(f.original);change(original);expect(()=>previewBootstrapRegistration(original,purpose,f.scope)).toThrow();
 }
});
it.each(['map-version','definition','missing-purpose','foreign-source'])('holds the real loader on %s drift',async defect=>{
 const purpose=cases[0][0],f=fixture(purpose),binding=await loadNonrootPreviewBootstrap(f.clients,{...f.scope,purpose});
 if(defect==='map-version')f.parameters.get(`/mem9-on-aws/${f.scope.stage}/bootstrap/purpose-bindings`).Version++;
 if(defect==='definition'){const next=structuredClone(f.observation);next.taskDefinition.containerDefinitions[0].secrets.push(secrets[1]);f.definitions.set(next.taskDefinition.taskDefinitionArn,next);}
 if(defect==='missing-purpose'){const p=f.parameters.get(`/mem9-on-aws/${f.scope.stage}/bootstrap/purpose-bindings`),map=JSON.parse(p.Value);map.bindings=map.bindings.filter(b=>b.purpose!==purpose);p.Value=JSON.stringify(map);}
 if(defect==='foreign-source'){const p=f.parameters.get(`/mem9-on-aws/${f.scope.stage}/bootstrap/purpose-bindings`),map=JSON.parse(p.Value);map.sourceTree='d'.repeat(40);p.Value=JSON.stringify(map);}
 await expect(revalidateNonrootPreviewBootstrap(f.clients,binding)).rejects.toThrow();
 expect(f.calls.every(name=>['GetCallerIdentityCommand','GetParametersCommand','DescribeTaskDefinitionCommand'].includes(name))).toBe(true);
});
it('accounts for both snapshot loader/rechecks plus the benchmark loader/recheck',async()=>{
 let reads=0;
 for(const purpose of [cases[1][0],cases[1][0],cases[0][0]]){
  const f=fixture(purpose),binding=await loadNonrootPreviewBootstrap(f.clients,{...f.scope,purpose});
  await revalidateNonrootPreviewBootstrap(f.clients,binding);reads+=f.calls.length;
 }
 expect(reads).toBe(18);
});
it('preflights the unchanged map cap using source-bound fields and maximum safe revisions',()=>{
 const scope={stage:'pr-123',account:'123456789012',region:'ap-northeast-1',sourceTree:'a'.repeat(40)},defaultPurpose='bootstrap-runtime-bootstrap',purposes=NONROOT_PREVIEW_BOOTSTRAP_PURPOSES;
 expect(purposes).toHaveLength(12);
 expect(assertPreviewPurposeMapFits({scope,family:'mem9-on-aws-pr-123-Mem9ClusterCluster-xxxxxxxx-Mem9Bootstrap',defaultPurpose,purposes})).toBe(3718);
 const boundary={scope:{...scope,stage:'pr-1234'},family:'mem9-on-aws-pr-1234-Mem9ClusterCluster-'+ 'x'.repeat(36)+'-Mem9Bootstrap',defaultPurpose,purposes};
 expect(assertPreviewPurposeMapFits(boundary)).toBe(4096);
 expect(()=>assertPreviewPurposeMapFits({...boundary,family:boundary.family.replace('x'.repeat(36),'x'.repeat(37))})).toThrow('NonrootPreviewMapSize');
 expect(()=>assertPreviewPurposeMapFits({...boundary,purposes:[...purposes,purposes[0]]})).toThrow();
});
