import {test,expect} from 'vitest';
import {spawnSync,execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {encodeObservationFrames,observationFrameEncoderSource} from './lib/production-nonroot-observation-frames.mjs';
import {observationNodeEncoderSource,observationNodeOutputSource} from './lib/production-nonroot-observation-node-output.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
const binding='a'.repeat(64),capture='b'.repeat(32);
test('inline encoder uses the exact reviewed export and produces identical complete wire',()=>{
 const source=observationNodeEncoderSource();expect(source).toBe(observationFrameEncoderSource());
 const cases=[1,2048,2049,1048576];
 const code=source+`\nimport {createHash as testHash} from 'node:crypto';\nconst out=${JSON.stringify(cases)}.map(n=>{const f=encodeObservationFrames({binding:'${binding}',capture:'${capture}',bytes:Buffer.alloc(n,91)});return {n,count:f.length,hash:testHash('sha256').update(Buffer.concat(f)).digest('hex')}});process.stdout.write(JSON.stringify(out));`;
 const run=spawnSync(process.execPath,['--input-type=module','-e',code],{env:{},encoding:'utf8',timeout:10000,maxBuffer:65536});
 expect(run.error).toBeUndefined();expect(run.status).toBe(0);expect(run.stderr).toBe('');
 expect(JSON.parse(run.stdout)).toEqual(cases.map(n=>{const f=encodeObservationFrames({binding,capture,bytes:Buffer.alloc(n,91)});return {n,count:f.length,hash:sha(Buffer.concat(f))};}));
});
test('generated encoder preserves original invalid binding/raw-bound rejection',()=>{
 const code=observationNodeEncoderSource()+`\nconst errors=[];for(const v of [{binding:'x',capture:'${capture}',bytes:Buffer.alloc(1)},{binding:'${binding}',capture:'${capture}',bytes:Buffer.alloc(1048577)}]){try{encodeObservationFrames(v);errors.push(null)}catch(e){errors.push(e.message)}}process.stdout.write(JSON.stringify(errors));`;
 const run=spawnSync(process.execPath,['--input-type=module','-e',code],{env:{},encoding:'utf8',timeout:10000,maxBuffer:65536});
 expect(run.status).toBe(0);expect(JSON.parse(run.stdout)).toEqual(['NonrootObservationBinding','NonrootObservationRawBound']);
});

// Named pipes are an isolated Linux TEST fixture only. The runtime writer
// creates no files and receives the actual task descriptors from its caller.
function realPipeCase({size=2049,alias=false,expired=false}={}){
 const directory=fs.mkdtempSync(join(tmpdir(),'observation-writer-'));fs.chmodSync(directory,0o700);
 const output=join(directory,'output'),application=join(directory,'application');let outFd,appFd,reader;
 try{
  execFileSync('mkfifo',['-m','600',output,application]);
  outFd=fs.openSync(output,fs.constants.O_RDWR);appFd=fs.openSync(alias?output:application,fs.constants.O_RDWR);
  reader=fs.openSync(output,fs.constants.O_RDONLY|fs.constants.O_NONBLOCK);
  const code=observationNodeOutputSource()+`\nconst fs=await import('node:fs');const before=fs.readFileSync('/proc/self/fdinfo/3','utf8');let result,code;try{result=await writeNodeObservationFrames({fd:3,stdoutFd:4,binding:'${binding}',capture:'${capture}',bytes:Buffer.alloc(${size},91),deadlineMs:Date.now()+${expired?-1:10000}})}catch(e){code=e.code??e.message;process.exitCode=1}const after=fs.readFileSync('/proc/self/fdinfo/3','utf8');process.stdout.write(JSON.stringify({result,code,flagsUnchanged:before===after,callerDescriptorsOpen:fs.fstatSync(3).isFIFO()&&fs.fstatSync(4).isFIFO()}));`;
  const run=spawnSync(process.execPath,['--input-type=module','-e',code],{env:{},encoding:'utf8',stdio:['ignore','pipe','pipe',outFd,appFd],timeout:5000,maxBuffer:65536});
  expect(run.error).toBeUndefined();expect(run.signal).toBeNull();expect(run.stderr).toBe('');
  const chunks=[];for(;;){try{const b=Buffer.alloc(8192),n=fs.readSync(reader,b);if(!n)break;chunks.push(b.subarray(0,n));}catch(e){if(e.code==='EAGAIN')break;throw e;}}
  return {status:run.status,...JSON.parse(run.stdout),wire:Buffer.concat(chunks)};
 }finally{
  for(const fd of [reader,appFd,outFd])if(fd!==undefined)fs.closeSync(fd);
  fs.rmSync(directory,{recursive:true,force:true});
 }
}
test.runIf(process.platform==='linux')('actual writer emits complete frames and preserves caller descriptors/flags',()=>{
 const r=realPipeCase();expect(r.status).toBe(0);expect(r.flagsUnchanged).toBe(true);expect(r.callerDescriptorsOpen).toBe(true);
 const expected=Buffer.concat(encodeObservationFrames({binding,capture,bytes:Buffer.alloc(2049,91)}));expect(r.wire).toEqual(expected);expect(r.result).toEqual({frames:4,bytes:expected.length});
});
test.runIf(process.platform==='linux')('full-cap output against a blocked sink rejects EAGAIN without retry or inherited flag mutation',()=>{
 const r=realPipeCase({size:1048576});expect(r.status).toBe(1);expect(r.code).toBe('EAGAIN');expect(r.flagsUnchanged).toBe(true);expect(r.callerDescriptorsOpen).toBe(true);
 expect(r.wire.length).toBeLessThan(Buffer.concat(encodeObservationFrames({binding,capture,bytes:Buffer.alloc(1048576,91)})).length);
});
test.runIf(process.platform==='linux')('different FD numbers aliasing the same app pipe reject before output',()=>{
 const r=realPipeCase({alias:true});expect(r.status).toBe(1);expect(r.code).toBe('DataObservationOutputSeparation');expect(r.wire.length).toBe(0);
});
test.runIf(process.platform==='linux')('expired original deadline rejects before output',()=>{
 const r=realPipeCase({expired:true});expect(r.status).toBe(1);expect(r.code).toBe('DataObservationOutputExpired');expect(r.wire.length).toBe(0);
});
