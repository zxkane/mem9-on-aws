import {test,expect} from 'vitest';
import {readFileSync} from 'node:fs';
import {spawn,spawnSync} from 'node:child_process';

test('real shared arm channel remains writable by observer after relay closes its own descriptor',()=>{
 // Execute the exact production primitive factory, not a parallel sender.
 // This probes descriptor lifetime only, not target/init/cloud acceptance.
 const source=readFileSync(new URL('./lib/production-nonroot-observed-node-launch.mjs',import.meta.url),'utf8');
 const factory=source.slice(source.indexOf('function nodeLifecyclePrimitives('),source.indexOf('\nfunction observerEntry('));
 expect(factory.startsWith('function nodeLifecyclePrimitives(')).toBe(true);
 const imports="import * as fs from 'node:fs';import * as net from 'node:net';import * as crypto from 'node:crypto';";
 const setup=imports+factory+'\nconst p=nodeLifecyclePrimitives(fs,net,crypto,2000);';
 const observer=setup+"\nawait new Promise(r=>setTimeout(r,20));await p.send('A|50|400|'+('c'.repeat(32))+'\\n',Number(process.argv[1]));";
 const relay=setup+"\nimport {spawn} from 'node:child_process';const deadline=Date.now()+2000;const child=spawn(process.execPath,['--input-type=module','-e',"+JSON.stringify(observer)+",String(deadline)],{env:{},stdio:['ignore','ignore','pipe',3]});let exited=false;const joined=new Promise((resolve,reject)=>{child.on('error',reject);child.on('exit',(code,signal)=>{exited=true;resolve({code,signal})})});try{await p.send('B|50|400|'+('c'.repeat(32))+'\\n',deadline);const status=await joined;if(status.code!==0||status.signal)process.exitCode=1;}catch{if(!exited)child.kill('SIGKILL');await joined;process.exitCode=1;}";
 const r=spawnSync(process.execPath,['--input-type=module','-e',relay],{env:{},encoding:'utf8',stdio:['ignore','pipe','pipe','pipe'],timeout:5000,maxBuffer:65536});
 expect(r.error).toBeUndefined();expect(r.status).toBe(0);expect(r.signal).toBeNull();expect(r.stdout).toBe('');expect(r.stderr).toBe('');
 expect(r.output[3]).toBe('B|50|400|'+'c'.repeat(32)+'\nA|50|400|'+'c'.repeat(32)+'\n');
});

test('real EPIPE write callback rejects send and the helper exits unsuccessfully after close',async()=>{
 const source=readFileSync(new URL('./lib/production-nonroot-observed-node-launch.mjs',import.meta.url),'utf8');
 const factory=source.slice(source.indexOf('function nodeLifecyclePrimitives('),source.indexOf('\nfunction observerEntry('));
 const code="import * as fs from 'node:fs';import * as net from 'node:net';import * as crypto from 'node:crypto';"+factory+`
const p=nodeLifecyclePrimitives(fs,net,crypto,2000);let result,writeCallbackError;
const originalWrite=net.Socket.prototype.write;
// Observe the actual native callback; never supply a synthetic error/result.
net.Socket.prototype.write=function(data,callback){
 if(typeof data==='string'&&data.startsWith('B|')&&typeof callback==='function')return originalWrite.call(this,data,function(error){writeCallbackError=error?.code;return callback(error);});
 return originalWrite.apply(this,arguments);
};
try{await p.send('B|50|400|'+('c'.repeat(32))+'\\n',Date.now()+500);result={sendResolved:true,writeCallbackError};}
catch(e){result={sendResolved:false,error:e.code??e.message,writeCallbackError};process.exitCode=1;}
finally{net.Socket.prototype.write=originalWrite;}
process.stdout.write(JSON.stringify(result));`;
 const child=spawn(process.execPath,['--input-type=module','-e',code],{env:{},stdio:['ignore','pipe','pipe','pipe']});
 child.stdio[3].destroy();let out='',err='',timer;
 child.stdout.on('data',b=>{out+=b;});child.stderr.on('data',b=>{err+=b;});
 const status=await new Promise((resolve,reject)=>{
  timer=setTimeout(()=>child.kill('SIGKILL'),2000);
  child.once('error',reject);child.once('close',(code,signal)=>resolve({code,signal}));
 }).finally(()=>clearTimeout(timer));
 expect(status.signal).toBeNull();expect(err).toBe('');expect(out.length).toBeLessThan(8192);
 expect(JSON.parse(out)).toEqual({sendResolved:false,error:'EPIPE',writeCallbackError:'EPIPE'});
 expect(status.code).toBe(1);
});
