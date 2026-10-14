import {it,expect,beforeAll,afterAll} from 'vitest';
import {mkdtemp,mkdir,writeFile,readFile,symlink,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {previewProgramSourceFixture} from './production-nonroot-preview-provider.fixture.mjs';
import {ciSmokeSourceClosure} from './lib/ci-smoke-isolation.mjs';
import {readControlSourceFile} from './lib/production-control-source.mjs';
import {nonrootPreviewFixture} from './nonroot-preview.fixture.mjs';

const exec=promisify(execFile);let root,repository,fixture,sequence=0;
beforeAll(async()=>{
 root=await mkdtemp(join(tmpdir(),'namespace-runner-test-'));repository=join(root,'repository');await mkdir(repository);await mkdir(join(root,'bin'));
 const source=previewProgramSourceFixture(),files=await ciSmokeSourceClosure(source.context,['scripts/run-memory-namespace-benchmark.sh','scripts/lib/post-runtime-preview-aws.mjs']);
 for(const file of files){const path=join(repository,file.path);await mkdir(dirname(path),{recursive:true});await writeFile(path,(await readControlSourceFile(source.context,file.path)).bytes);}
 await symlink(new URL('../node_modules',import.meta.url).pathname,join(repository,'node_modules'),'dir');
 await writeFile(join(repository,'.gitignore'),'node_modules/\n');
 const git=async args=>(await exec('git',['-c','core.hooksPath=/dev/null',...args],{cwd:repository,maxBuffer:1048576})).stdout.trim();
 await git(['init','-q']);await git(['add','.']);await git(['-c','user.name=Synthetic fixture','-c','user.email=fixture@example.com','commit','--no-gpg-sign','-qm','test: synthetic source']);
 fixture=nonrootPreviewFixture({sourceTree:await git(['rev-parse','HEAD^{tree}']),purposes:['bootstrap-runtime-bootstrap','preview-namespace-benchmark','preview-namespace-connection-snapshot'],
  environment:[{name:'AWS_REGION',value:'ap-northeast-1'},{name:'MEM9_DB_HOST',value:'writer.example.com'},{name:'MEM9_DB_PORT',value:'5432'},
   {name:'MEM9_DB_NAME',value:'mem9'},{name:'MEM9_COGNITO_ISSUER',value:'https://issuer.example.com'}],
  secrets:[{name:'MEM9_DB_SECRET',valueFrom:'arn:aws:ssm:ap-northeast-1:123456789012:parameter/mem9-on-aws/pr-7/db'}],logGroup:'/sst/synthetic',logStreamPrefix:'bootstrap'});
 await writeFile(join(root,'data.json'),JSON.stringify({parameters:[...fixture.parameters.values()],definitions:[...fixture.definitions]}),{mode:0o600});
 // Only synthetic CLI responses. Unlisted commands fail; there is no network
 // server, credential provider, real AWS fallback or mocked source-tree check.
 await writeFile(join(root,'bin','aws'),`#!/usr/bin/env node
const fs=require('node:fs'),args=process.argv.slice(2),data=JSON.parse(fs.readFileSync(process.env.FIXTURE_DATA,'utf8'));
fs.appendFileSync(process.env.FIXTURE_LOG,JSON.stringify(args)+'\\n',{mode:0o600});
const history=fs.readFileSync(process.env.FIXTURE_LOG,'utf8').trim().split('\\n').map(JSON.parse);
const out=value=>process.stdout.write(JSON.stringify(value)+'\\n');
if(args[0]==='sts'&&args[1]==='get-caller-identity')out({Account:'123456789012'});
else if(args[0]==='ssm'&&args[1]==='get-parameters'){
 const names=args.slice(args.indexOf('--names')+1).filter((v,i,a)=>i<(a.findIndex(x=>x.startsWith('--'))<0?a.length:a.findIndex(x=>x.startsWith('--'))));
 const rows=data.parameters.filter(p=>names.includes(p.Name));
 if(process.env.FIXTURE_DEFECT==='map-drift'&&history.filter(a=>a[0]==='ssm').length===2)rows[0].Version++;
 out({Parameters:rows,InvalidParameters:[]});
}else if(args[0]==='ecs'&&args[1]==='describe-task-definition'){
 const value=data.definitions.find(([arn])=>arn===args[args.indexOf('--task-definition')+1])[1];
 if(process.env.FIXTURE_DEFECT==='definition')value.taskDefinition.containerDefinitions[0].user='0';out(value);
}else if(args[0]==='ecs'&&args[1]==='run-task')out({tasks:[{taskArn:'arn:aws:ecs:ap-northeast-1:123456789012:task/mem9-on-aws-pr-7-Cluster-example/'+ 'a'.repeat(32)}],failures:[]});
else if(args[0]==='ecs'&&args[1]==='describe-tasks')process.stdout.write(args.includes('tasks[0].lastStatus')?'STOPPED\\n':'0\\n');
else if(args[0]==='logs'&&args[1]==='filter-log-events')out({events:[{message:JSON.stringify(process.env.FIXTURE_OPERATION==='benchmark'?{event:'namespace_resolution_benchmark',version:1,samples:100,p95_ms:1,threshold_ms:20}:{event:'namespace_connection_snapshot',version:1,control_connections:1,tenant_connections:1,active_connections:0,unknown_connections:0})}]});
else{process.stderr.write('UnexpectedSyntheticCommand\\n');process.exitCode=70;}
`,{mode:0o755});
},20000);
afterAll(async()=>{if(root)await rm(root,{recursive:true,force:true});});

async function run(operation,{defect='',extra={}}={}){
 const log=join(root,'calls-'+(++sequence)+'.jsonl');await writeFile(log,'',{mode:0o600});
 let status=0,stdout='';
 try{({stdout}=await exec('bash',['scripts/run-memory-namespace-benchmark.sh'],{cwd:repository,timeout:20000,maxBuffer:16384,
  env:{PATH:join(root,'bin')+':'+process.env.PATH,STAGE:'pr-7',AWS_REGION:'ap-northeast-1',FIXTURE_DATA:join(root,'data.json'),FIXTURE_LOG:log,FIXTURE_DEFECT:defect,FIXTURE_OPERATION:operation,
   MEM9_PREVIEW_OBSERVATION_OPERATION:operation,MEM9_PREVIEW_OBSERVATION_EVENT:operation==='benchmark'?'namespace_resolution_benchmark':'namespace_connection_snapshot',...extra}}));}
 catch(error){status=error.code;}
 const calls=(await readFile(log,'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse);return {status,stdout,calls};
}
it('uses the real source/loader/recheck bridge for both snapshots and the benchmark',async()=>{
 let metadata=0;
 for(const operation of ['connection-snapshot','connection-snapshot','benchmark']){
  const result=await run(operation);expect(result.status).toBe(0);expect(JSON.parse(result.stdout).version).toBe(1);
  const readCalls=result.calls.filter(a=>a[0]==='sts'||a[0]==='ssm'||a[1]==='describe-task-definition');metadata+=readCalls.length;
  expect(readCalls.map(a=>a.slice(0,2).join(':'))).toEqual(['sts:get-caller-identity','ssm:get-parameters','ecs:describe-task-definition','sts:get-caller-identity','ssm:get-parameters','ecs:describe-task-definition']);
  const launches=result.calls.filter(a=>a[1]==='run-task');expect(launches).toHaveLength(1);const args=launches[0];
  const purpose=operation==='benchmark'?'preview-namespace-benchmark':'preview-namespace-connection-snapshot';
  expect(args[args.indexOf('--task-definition')+1]).toBe(fixture.map.bindings.find(b=>b.purpose===purpose).taskDefinitionArn);
  expect(args).toContain('--disable-execute-command');
  const overrides=JSON.parse(args[args.indexOf('--overrides')+1]);
  expect(Object.keys(overrides)).toEqual(['containerOverrides']);
  expect(overrides.containerOverrides[0].environment.map(e=>e.name)).toEqual(operation==='benchmark'?['MEM9_NAMESPACE_BENCHMARK_SAMPLES','MEM9_NAMESPACE_BENCHMARK_WARMUPS']:[]);
 }
 expect(metadata).toBe(18);
},20000);
it.each(['map-drift','definition'])('never launches after actual loader/recheck %s rejection',async defect=>{
 const result=await run('benchmark',{defect});expect(result.status).not.toBe(0);expect(result.calls.some(a=>a[1]==='run-task')).toBe(false);
});
it.each(['19','501','00020','999999999999999999999'])('rejects benchmark count %s before any provider read',async count=>{
 const result=await run('benchmark',{extra:{MEM9_NAMESPACE_BENCHMARK_SAMPLES:count}});expect(result.status).toBe(2);expect(result.calls).toEqual([]);
});
it('rejects benchmark overrides on the snapshot before any provider read',async()=>{
 const result=await run('connection-snapshot',{extra:{MEM9_NAMESPACE_BENCHMARK_WARMUPS:'0'}});expect(result.status).toBe(2);expect(result.calls).toEqual([]);
});
