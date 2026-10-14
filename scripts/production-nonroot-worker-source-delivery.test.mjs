import {test,expect} from 'vitest';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {brotliCompressSync,brotliDecompressSync,constants} from 'node:zlib';

const sha=b=>createHash('sha256').update(b).digest('hex');
const compiler=new URL('./lib/production-nonroot-observed-node-launch.mjs',import.meta.url).href;
const goldens=JSON.parse(readFileSync(new URL('./fixtures/nonroot-worker-v1-compiler.json',import.meta.url))).results;
function input(role='planner',count=24){
 const v=structuredClone(goldens.find(g=>g.role===role).input);
 v.plan={...v.plan,version:2,clock:'observed-worker-exec',owner:sha('synthetic owner').slice(0,32),operation:sha('synthetic operation').slice(0,32),launchNonce:sha('synthetic nonce').slice(0,32),sourceTree:sha('synthetic tree').slice(0,40)};
 for(const k of ['rootDigest','arm64Digest','configDigest'])v.plan.image[k]='sha256:'+sha('synthetic '+k);
 v.original.image='example.com/worker@'+v.plan.image.rootDigest;
 const paths=['/usr/local/bin/node','/app/scripts/consolidation-worker.mjs',...Array.from({length:count-2},(_,i)=>'/app/lib/synthetic-module-'+i+'-'+sha('path '+i).slice(0,24)+'.mjs')];
 v.files=paths.map((path,i)=>({path,resolvedPath:path,sha256:sha('synthetic file '+i),size:4096+i*97,mode:493,uid:0,gid:0}));
 return v;
}
function run(code,{args=[],input:stdin}={}){
 return spawnSync(process.execPath,['--input-type=module','-e',code,...args],{env:{},input:stdin,encoding:'utf8',timeout:10000,maxBuffer:2097152});
}
function compile(v){
 const r=run(`import {compileObservedNodeDataLaunch as compile} from ${JSON.stringify(compiler)};import {readFileSync} from 'node:fs';process.stdout.write(JSON.stringify(compile(JSON.parse(readFileSync(0,'utf8')))));`,{input:JSON.stringify(v)});
 expect(r.error).toBeUndefined();expect(r.status,r.stderr).toBe(0);return JSON.parse(r.stdout);
}
const descriptor=program=>JSON.parse(/const descriptor=(\{.*?\}),body=/.exec(program)[1]);
function internals(){
 const s=readFileSync(new URL('./lib/production-nonroot-observed-node-launch.mjs',import.meta.url),'utf8');
 const start=s.indexOf('function fixedBrotliBootstrap('),end=s.indexOf('function sharedSource(',start);
 expect(start).toBeGreaterThan(0);expect(end).toBeGreaterThan(start);
 return Function('brotliCompressSync','constants','sha',s.slice(start,end)+'\nreturn {pack:packedWorkerNodeSource,bootstrap:fixedBrotliBootstrap};')(brotliCompressSync,constants,sha);
}
test.each(['planner','executor'])('complete diverse %s file closure fits the original argv cap with margin',role=>{
 const v=input(role),c=compile(v),d=descriptor(c.target.entryPoint.at(-1));
 expect(c.delivery.kind).toBe('fixed-brotli-source-v1');
 expect(c.delivery.cmdlineBytes).toBeLessThanOrEqual(15360);
 const raw=brotliDecompressSync(Buffer.from(d.base64,'base64'),{maxOutputLength:d.bytes});
 expect(raw.length).toBe(d.bytes);expect(sha(raw)).toBe(d.sha256);expect(c.delivery.sourceHash).toBe(d.sha256);
 expect(c.delivery.compressedBytes).toBe(Buffer.from(d.base64,'base64').length);
 expect(c.delivery.compressedHash).toBe(sha(Buffer.from(d.base64,'base64')));
 expect(c.delivery.bootstrapHash).toBe(sha(c.target.entryPoint.at(-1)));
 const body=raw.toString(),spec=JSON.parse(/\nconst spec=(\{.*\});\nexport async function runPackedObservation/.exec(body)[1]);
 expect(spec.files).toEqual(v.files);expect(spec.plan).toEqual(v.plan);
 expect(c.snapshotCount).toBe(8);expect(c.delivery.maximumInvocations).toBe(3);
 for(const name of ['fixedNodeObservationCommonGate','collectWorkerObservationEpisode','writeNodeObservationFrames','workerObserverEntry','relayEntry','coordinatorEntry'])expect(body).toContain(name);
 expect(body).toContain("process.execArgv[2]!==bootstrap");expect(body).toContain("process.execArgv.length!==3");
 const argv=['/usr/local/bin/node','--input-type=module','-e',c.target.entryPoint.at(-1),'observer',...Array(3).fill(String(Number.MAX_SAFE_INTEGER))];
 expect(Buffer.byteLength(argv.join('\0')+'\0')).toBeLessThanOrEqual(c.delivery.cmdlineBytes);
});
test('fixed worker packing is deterministic and preserves every plan and input field',()=>{
 const v=input();expect(compile(v)).toEqual(compile(v));
});
test('actual Brotli bootstrap expands the complete module and preserves dynamic argv',()=>{
 const {pack}=internals();
 const body='/*'+'synthetic source\n'.repeat(2500)+"*/\nexport async function runPackedObservation(){process.stdout.write(JSON.stringify(process.argv.slice(1)));}";
 const p=pack(body,4),r=run(p.bootstrap,{args:['observer','42','100','1500']});
 expect(r.error).toBeUndefined();expect(r.status,r.stderr).toBe(0);expect(JSON.parse(r.stdout)).toEqual(['observer','42','100','1500']);
 expect(p.binding.sourceBytes).toBe(Buffer.byteLength(body));expect(p.binding.cmdlineBytes).toBeLessThanOrEqual(16384);
});
test.each(['hash','short-length','long-length','corrupt','truncated'])('Brotli %s corruption rejects before module execution',kind=>{
 const {pack,bootstrap}=internals(),p=pack("export async function runPackedObservation(){process.stdout.write('executed');}",0),d=descriptor(p.bootstrap);
 if(kind==='hash')d.sha256='0'.repeat(64);
 if(kind==='short-length')d.bytes--;
 if(kind==='long-length')d.bytes++;
 if(kind==='corrupt')d.base64=Buffer.from('not a brotli stream').toString('base64');
 if(kind==='truncated')d.base64=Buffer.from(d.base64,'base64').subarray(0,-1).toString('base64');
 const r=run(bootstrap(d));expect(r.error).toBeUndefined();expect(r.status).toBe(1);expect(r.stdout).toBe('');expect(r.stderr).toBe('');
});
test('declared expansion bound stops a much larger compressed body before execution',()=>{
 const {pack,bootstrap}=internals();
 const p=pack('/*'+'synthetic large module\n'.repeat(12000)+"*/export async function runPackedObservation(){process.stdout.write('executed');}",0),d=descriptor(p.bootstrap);d.bytes=64;
 const r=run(bootstrap(d));expect(r.error).toBeUndefined();expect(r.status).toBe(1);expect(r.stdout).toBe('');
});
test('incompressible complete source still rejects oversized command lines',()=>{
 const {pack}=internals(),source='/*'+Array.from({length:1800},(_,i)=>sha('incompressible '+i)).join('')+'*/';
 expect(()=>pack(source,4)).toThrow('DataObservationSourceArgvBound');
});
test('a larger valid file closure is rejected instead of dropping rows to fit argv',()=>{
 const r=run(`import {compileObservedNodeDataLaunch as compile} from ${JSON.stringify(compiler)};import {readFileSync} from 'node:fs';try{compile(JSON.parse(readFileSync(0,'utf8')))}catch(e){process.stdout.write(e.message);process.exitCode=1}`,{input:JSON.stringify(input('planner',192))});
 expect(r.error).toBeUndefined();expect(r.status).toBe(1);expect(r.stdout).toBe('DataObservationSourceArgvBound');
});
test('expanded genuine program rejects a direct invocation with different execArgv',()=>{
 const c=compile(input()),d=descriptor(c.target.entryPoint.at(-1)),raw=brotliDecompressSync(Buffer.from(d.base64,'base64'),{maxOutputLength:d.bytes});
 const code=`const m=await import('data:text/javascript;base64,'+${JSON.stringify(raw.toString('base64'))});try{await m.runPackedObservation(${JSON.stringify(d)})}catch(e){process.stdout.write(e.message);process.exitCode=1}`;
 const r=run(code);expect(r.error).toBeUndefined();expect(r.status).toBe(1);expect(r.stdout).toBe('DataObservationSourceInvocation');
});
test.each(['foreign','coordinator'])('genuine worker bundle rejects unsupported mode %s',mode=>{
 const c=compile(input()),r=run(c.target.entryPoint.at(-1),{args:[mode]});
 expect(r.error).toBeUndefined();expect(r.status).toBe(1);expect(r.stdout).toBe('');expect(r.stderr).toBe('');
});
test.each(['codec','source','compressed','bootstrap'])('caller cannot inject %s into the compiler',field=>{
 const v=input();v[field]='synthetic override';
 const r=run(`import {compileObservedNodeDataLaunch as compile} from ${JSON.stringify(compiler)};import {readFileSync} from 'node:fs';try{compile(JSON.parse(readFileSync(0,'utf8')))}catch(e){process.stdout.write(e.message);process.exitCode=1}`,{input:JSON.stringify(v)});
 expect(r.status).toBe(1);expect(r.stdout).toBe('DataObservationLaunchInput');
});
