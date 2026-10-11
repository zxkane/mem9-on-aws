import {test,expect} from 'vitest';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {gzipSync,gunzipSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {compileObservedNodeDataLaunch} from './lib/production-nonroot-observed-node-launch.mjs';
const input=()=>({"plan":{"version":1,"kind":"bounded-data-observation","owner":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","operation":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","launchNonce":"cccccccccccccccccccccccccccccccc","sourceTree":"dddddddddddddddddddddddddddddddddddddddd","role":"planner","image":{"rootDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","arm64Digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","configDigest":"sha256:3333333333333333333333333333333333333333333333333333333333333333"},"startedMs":1000,"latestArmMs":1100,"observationEndMs":1400,"deadlineMs":1500,"armingLimitMs":25,"cleanupReserveMs":100,"episodes":[{"index":0,"offsetMs":200,"durationMs":100,"sampleEveryMs":50}],"limits":{"readBytes":268435456,"rawBytes":1048576,"initialProcesses":128,"finalProcesses":128,"combinedIdentities":256}},"files":[{"path":"/usr/local/bin/node","resolvedPath":"/usr/local/bin/node","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1,"mode":493,"uid":0,"gid":0},{"path":"/app/scripts/consolidation-worker.mjs","resolvedPath":"/app/scripts/consolidation-worker.mjs","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1,"mode":493,"uid":0,"gid":0}],"original":{"name":"Mem9ConsolidationPlanner","image":"example.com/worker@sha256:1111111111111111111111111111111111111111111111111111111111111111","linuxParameters":{"initProcessEnabled":true},"readonlyRootFilesystem":true}});
const sha=b=>createHash('sha256').update(b).digest('hex');
const source=readFileSync(new URL('./lib/production-nonroot-observed-node-launch.mjs',import.meta.url),'utf8');
const start=source.indexOf('function fixedPackedBootstrap('),end=source.indexOf('function sharedSource()',start);
const {pack,bootstrap}=Function('gzipSync','sha',source.slice(start,end)+'\nreturn {pack:packedNodeSource,bootstrap:fixedPackedBootstrap};')(gzipSync,sha);
const descriptor=s=>JSON.parse(/const descriptor=(\{.*?\}),body=/.exec(s)[1]);
function run(program,args=[]){return spawnSync(process.execPath,['--input-type=module','-e',program,...args],{env:{},encoding:'utf8',timeout:5000,maxBuffer:65536});}
test('complete generated shared source remains below original cmdline bound without dropping file rows',()=>{
 const v=compileObservedNodeDataLaunch(input()),d=descriptor(v.target.entryPoint.at(-1)),raw=gunzipSync(Buffer.from(d.base64,'base64'));
 expect(raw.length).toBe(v.delivery.sourceBytes);expect(sha(raw)).toBe(d.sha256);expect(v.delivery.cmdlineBytes).toBeLessThanOrEqual(16384);
 for(const name of ['fixedNodeObservationCommonGate','collectNodeObservationEpisode','writeNodeObservationFrames','observerEntry','relayEntry','coordinatorEntry'])expect(raw.toString()).toContain(name);
 for(const f of input().files)expect(raw.toString()).toContain(f.path);
 expect(v.delivery.maximumInvocations).toBe(3);expect(v.snapshotCount).toBe(4);
});
test('actual bootstrap verifies a larger complete module and preserves original dynamic argv',()=>{
 const body="/*"+'fixed source fixture\n'.repeat(1800)+"*/\nexport async function runPackedObservation(){const fs=await import('node:fs');process.stdout.write(JSON.stringify({argv:process.argv.slice(1),bytes:fs.readFileSync('/proc/self/cmdline').length}));}";
 const p=pack(body,4),r=run(p.bootstrap,['observer','42','100','1500']);expect(r.error).toBeUndefined();expect(r.status).toBe(0);expect(r.stderr).toBe('');
 const data=JSON.parse(r.stdout);expect(data.argv).toEqual(['observer','42','100','1500']);expect(data.bytes).toBeLessThanOrEqual(16384);
});
test.each(['hash','length','compressed'])('corrupted %s is rejected before module body runs',which=>{
 const p=pack("export async function runPackedObservation(){process.stdout.write('executed');}",0),d=descriptor(p.bootstrap);
 if(which==='hash')d.sha256='0'.repeat(64);if(which==='length')d.bytes--;if(which==='compressed')d.base64=Buffer.from('corrupt').toString('base64');
 const r=run(bootstrap(d));expect(r.status).toBe(1);expect(r.stdout).toBe('');expect(r.stderr).toBe('');
});
test('incompressible complete source rejects before producing an oversized argv',()=>{
 const body='/*'+Array.from({length:1500},(_,i)=>sha(Buffer.from(String(i)))).join('')+'*/';expect(()=>pack(body,4)).toThrow('DataObservationSourceArgvBound');
});
test('unsupported role mode in genuine compiled bundle rejects without app execution',()=>{
 const p=compileObservedNodeDataLaunch(input()),r=run(p.target.entryPoint.at(-1),['foreign']);expect(r.status).toBe(1);expect(r.stdout).toBe('');expect(r.stderr).toBe('');
});
test('expanded source argv parameters remain fixed known modes and counted in the original bound',()=>{
 const p=compileObservedNodeDataLaunch(input()),body=gunzipSync(Buffer.from(descriptor(p.target.entryPoint.at(-1)).base64,'base64')).toString();
 expect(body).toContain("observerSource,'observer',...args");expect(body).toContain("relaySource,'relay',String(parent.pid)");expect(body).toContain("process.execArgv[2]!==bootstrap");
});
