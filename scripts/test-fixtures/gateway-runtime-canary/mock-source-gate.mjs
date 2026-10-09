// Synthetic IPC fixture for shell ordering tests. This is not native canary
// provenance and is never imported by the production source gate or adapter.
import net from 'node:net';
import fs from 'node:fs';
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {gatewayCanaryDocumentHash as hash} from '../../lib/gateway-runtime-canary-resources.mjs';
const sha=v=>createHash('sha256').update(v).digest('hex');
export async function mockGatewaySourceGate({path,policyPath,reject=false}){
 const child=spawn(process.execPath,[fileURLToPath(import.meta.url),path,policyPath,String(reject)],{env:{PATH:'/usr/bin:/bin'},stdio:['ignore','pipe','pipe']});
 const closed=new Promise(resolve=>child.once('close',resolve));
 try{await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('mock gate startup timeout')),3000);child.once('error',reject);child.once('close',()=>reject(Error('mock gate startup failed')));child.stdout.once('data',chunk=>{clearTimeout(timer);String(chunk)==='ready\n'?resolve():reject(Error('mock gate startup failed'));});});}
 catch(error){child.kill('SIGKILL');await closed;throw error;}
 return {path,async close(){child.kill('SIGTERM');await closed;}};
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 const [path,policyPath,deny]=process.argv.slice(2),policy=JSON.parse(fs.readFileSync(policyPath));
 const server=net.createServer(socket=>{const chunks=[];let size=0;socket.on('error',()=>{});socket.on('data',chunk=>{
  size+=chunk.length;if(size>16388){socket.destroy();return;}chunks.push(chunk);const wire=Buffer.concat(chunks);
  if(wire.length<4||wire.length<wire.readUInt32BE(0)+4)return;
  try{
   const request=JSON.parse(wire.subarray(4)),args=request.argv;
   const accepted=deny==='false'&&request.version===1&&/^[a-f0-9]{32}$/.test(request.id)&&args.length===8&&args[0]==='gateway-runtime'&&args[1]==='verify-source'&&args[2]==='--boundary-document'&&args[4]==='--policy-version'&&args[5]==='v1'&&args[6]==='--region'&&hash(JSON.parse(args[3]))===hash(policy);
   const receipt={version:1,kind:'gateway-source-condition-verified',policyHash:hash(policy),policyVersion:'v1',evidenceHash:sha('synthetic IPC evidence'),handlerHash:sha('synthetic IPC handler'),source:{commit:'a'.repeat(40),tree:'b'.repeat(40)},coverage:['kms-source-condition','ec2-source-condition']};
   const body=Buffer.from(JSON.stringify({version:1,id:request.id,status:accepted?0:77,stdout:accepted?Buffer.from(JSON.stringify(receipt)).toString('base64'):'',stderr:''})),frame=Buffer.alloc(body.length+4);frame.writeUInt32BE(body.length);body.copy(frame,4);socket.end(frame);
  }catch{socket.destroy();}
 });});
 server.listen(path,()=>{fs.chmodSync(path,0o600);process.stdout.write('ready\n');});
}
