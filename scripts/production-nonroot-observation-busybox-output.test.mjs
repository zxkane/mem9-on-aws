import {test,expect} from 'vitest';
import fs from 'node:fs';
import {spawn,execFileSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {busyboxObservationOutputSource,describeBusyboxObservationOutputWork} from './lib/production-nonroot-observation-busybox-output.mjs';
import {encodeObservationFrames,createObservationFrameDecoder} from './lib/production-nonroot-observation-frames.mjs';
import {busyboxObservationCollectorSource,decodeBusyboxObservationRows} from './lib/production-nonroot-observation-busybox-collector.mjs';

const binding='a'.repeat(64),capture='b'.repeat(32);
test('fixed BusyBox source has no executable-source or tool callback parameter',()=>{
 expect(()=>busyboxObservationOutputSource('replacement')).toThrow('DataObservationBusyboxSourceArguments');
 const s=busyboxObservationOutputSource();expect(s).toContain('exec /bin/busybox dd');expect(s).toContain('wait "$obs_writer_pid"');expect(s).not.toContain('/environ');
});
test('full-cap geometry keeps all514 writer invocations and both pipe creators per frame',()=>{
 expect(describeBusyboxObservationOutputWork({rawBytes:1048576})).toMatchObject({rawBytes:1048576,frameCount:514,writerInvocations:514,anonymousPipeCreators:1028,maximumGuardTicks:51400});
 expect(()=>describeBusyboxObservationOutputWork({rawBytes:1048577})).toThrow();
 expect(()=>describeBusyboxObservationOutputWork({rawBytes:1,credit:true})).toThrow();
});

// Local opt-in uses the retained executable+loader bytes by reference. Only
// fixed tool path spellings are mapped; no returned tool output is substituted.
const tool=process.env.MEM9_TEST_BUSYBOX,loader=process.env.MEM9_TEST_BUSYBOX_LOADER;
const native=process.platform==='linux'&&!!tool&&!!loader;
const q=s=>"'"+s.replaceAll("'","'\\''")+"'";
async function actual({size=2049,drain=true,alias=false,expired=false,badBinding=false,collectFirst=false}={}){
 const directory=fs.mkdtempSync(join(tmpdir(),'busybox-observer-'));fs.chmodSync(directory,0o700);
 const outPath=join(directory,'out'),appPath=join(directory,'app');let out,app,reader,child,timer,watchdog;
 const chunks=[];let length=0,summary='',failure;
 try{
  execFileSync('mkfifo',['-m','600',outPath,appPath]);out=fs.openSync(outPath,fs.constants.O_RDWR);app=fs.openSync(alias?outPath:appPath,fs.constants.O_RDWR);
  reader=fs.openSync(outPath,fs.constants.O_RDONLY|fs.constants.O_NONBLOCK);
  const before=fs.readFileSync('/proc/self/fdinfo/'+out,'utf8');
  const mapped='obs_test_busybox(){ '+q(loader)+' '+q(tool)+' "$@"; }\n'+busyboxObservationOutputSource()
   .replace('obs_bb=/bin/busybox','obs_bb=obs_test_busybox').replace('exec /bin/busybox dd','exec '+q(loader)+' '+q(tool)+' dd');
  const deadline=Date.now()+(expired?-1:55000);
  const collection=collectFirst?busyboxObservationCollectorSource().replace('obs_collect_bb=/bin/busybox','obs_collect_bb=obs_test_busybox')+
   '\nOBS_COLLECT_DEADLINE_MS='+deadline+'\nobs_collect_proc $$ || exit 71\nobs_collect_close || exit 72\nraw=$OBS_COLLECT_ROW; ':'raw=$(obs_test_busybox cat); ';
  const source='set -o pipefail\n'+mapped+'\n'+collection+'obs_emit_busybox "$raw" '+q(badBinding?'invalid':binding)+' '+q(capture)+' '+deadline+
   '; result=$?; children=""; IFS= read -r children < /proc/$$/task/$$/children || :; printf "{\\"status\\":%s,\\"frames\\":%s,\\"bytes\\":%s,\\"children\\":\\"%s\\"}" "$result" "${OBS_FRAMES:-0}" "${OBS_WIRE_BYTES:-0}" "$children" >&3; exit "$result"';
  child=spawn(loader,[tool,'sh',...(collectFirst?['-s']:['-c',source])],{env:{PATH:'/usr/bin:/bin',LC_ALL:'C'},stdio:['pipe',app,out,'pipe']});
  child.on('error',e=>{failure=e;});child.stdin.on('error',e=>{failure??=e;});child.stdio[3].on('data',b=>{summary+=b.toString();if(summary.length>4096)failure=Error('summary bound');});
  const read=()=>{
   for(;;){try{const b=Buffer.alloc(16384),n=fs.readSync(reader,b);if(!n)break;length+=n;if(length>2105344){failure=Error('wire bound');break;}chunks.push(b.subarray(0,n));}catch(e){if(e.code==='EAGAIN')break;failure=e;break;}}
  };
  if(drain)timer=setInterval(read,1);
  const terminal=new Promise(resolve=>child.once('close',(code,signal)=>resolve({code,signal})));
  watchdog=setTimeout(()=>{failure=Error('native writer timeout');child.kill('SIGKILL');},60000);
  child.stdin.end(collectFirst?source:Buffer.alloc(size,91));const end=await terminal;clearTimeout(watchdog);clearInterval(timer);read();
  if(failure)throw failure;
  return {...end,summary:JSON.parse(summary),wire:Buffer.concat(chunks),flagsUnchanged:before===fs.readFileSync('/proc/self/fdinfo/'+out,'utf8')};
 }finally{
  clearTimeout(watchdog);clearInterval(timer);
  for(const fd of [reader,app,out])if(fd!==undefined)fs.closeSync(fd);
  fs.rmSync(directory,{recursive:true,force:true});
 }
}
test.runIf(native).each([1,2049,1048576])('retained BusyBox emits exact reviewed wire for %s bytes and joins its helpers',async size=>{
 const r=await actual({size});expect(r.signal).toBeNull();expect(r.code).toBe(0);expect(r.summary.status).toBe(0);expect(r.summary.children).toBe('');expect(r.flagsUnchanged).toBe(true);
 const frames=encodeObservationFrames({binding,capture,bytes:Buffer.alloc(size,91)});expect(r.wire).toEqual(Buffer.concat(frames));expect(r.summary.frames).toBe(frames.length);expect(r.summary.bytes).toBe(r.wire.length);
},65000);
test.runIf(native)('blocked output remains failed after its owned writer is killed and joined',async()=>{
 const r=await actual({size:1048576,drain:false});expect(r.signal).toBeNull();expect(r.code).not.toBe(0);expect(r.summary.status).not.toBe(0);expect(r.summary.children).toBe('');expect(r.flagsUnchanged).toBe(true);expect(r.summary.frames).toBeLessThan(514);
},65000);
test.runIf(native).each([{alias:true},{expired:true},{badBinding:true}])('invalid or expired output selection writes no observation: %j',async options=>{
 const r=await actual(options);expect(r.code).not.toBe(0);expect(r.wire).toHaveLength(0);expect(r.summary.children).toBe('');expect(r.flagsUnchanged).toBe(true);
},65000);
test.runIf(native)('actual proc row flows through BusyBox writer, reviewed framing and active strict record decoder',async()=>{
 const r=await actual({collectFirst:true});expect(r.code).toBe(0);expect(r.summary.children).toBe('');expect(r.flagsUnchanged).toBe(true);
 const decoder=createObservationFrameDecoder({bindings:[binding],maxCaptures:1,maxInputBytes:2105344});decoder.push(r.wire);const decoded=decoder.finish();
 expect(decoded.nonFrameBytes).toBe(0);expect(decoded.captures).toHaveLength(1);
 const row=JSON.parse(decoded.captures[0].bytes.toString()),p=decodeBusyboxObservationRows([row])[0];
 expect(p.executablePath).toBe(loader);expect(p.pid).toBe(row.pid);expect(p.file.inode).toBe(fs.statSync(loader,{bigint:true}).ino.toString());
},65000);
