import net from 'node:net';
import {lstat,realpath} from 'node:fs/promises';
import {dirname,isAbsolute} from 'node:path';
import {randomBytes,createHash} from 'node:crypto';
import {expectedGatewayBoundaryPolicyDocument} from './gateway-workload-boundary.mjs';
import {gatewayCanaryDocumentHash as hash} from './gateway-runtime-canary-resources.mjs';
import {validateGatewayRuntimeCanaryEvidence} from './gateway-runtime-canary-evidence.mjs';

const need=(v,why)=>{if(!v)throw Error('GatewayRuntimeSource'+why);};
const sha=v=>createHash('sha256').update(v).digest('hex');
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.toSorted().join();
const MAX=16384;

/** Semantic half of the gate. Production may call this ONLY with material
 * returned by inspectGatewayCanaryAwsEvidence(originalOps); JSON is not origin.
 * The private broker owns that call and never selects a verifier from input. */
export function verifyGatewayRuntimeSourceMaterial(material,{boundary,contract,policyVersion,handlerSource,source}){
 need(exact(material,['evidence','expected','validation','cleanup']),'Material');
 need(/^[a-f0-9]{40}$/.test(source?.commit??'')&&/^[a-f0-9]{40}$/.test(source?.tree??''),'Source');
 const document=typeof boundary==='string'?JSON.parse(boundary):boundary;
 need(hash(document)===hash(expectedGatewayBoundaryPolicyDocument(contract)),'Boundary');
 need(hash(document)===material.expected.originalBoundaryHash&&sha(handlerSource)===material.expected.handlerHash,'ReviewedSource');
 const e=material.evidence;
 need(e.scope.accountId===contract.accountId&&e.scope.applicationRegion===contract.applicationRegion&&e.scope.partition===contract.partition,'Scope');
 need(/^v[1-9][0-9]*$/.test(policyVersion)&&[e.rounds[1].before,e.rounds[1].after].every(r=>r.boundary.versionId===policyVersion),'PolicyVersion');
 const validation=validateGatewayRuntimeCanaryEvidence(e,material.expected);
 need(hash(validation)===hash(material.validation)&&hash(validation.coverage)===hash(['kms-source-condition','ec2-source-condition']),'Validation');
 need(Array.isArray(material.cleanup)&&material.cleanup.length===1&&material.cleanup[0].Arn===e.keyArn&&material.cleanup[0].KeyState==='PendingDeletion','Cleanup');
 return Object.freeze({version:1,kind:'gateway-source-condition-verified',policyHash:hash(document),policyVersion,evidenceHash:validation.evidenceHash,handlerHash:validation.handlerHash,source:{...source},coverage:validation.coverage});
}

/** Fixed request on the existing authenticated local runner channel. This
 * operation returns a native verification receipt, never an IAM simulation.
 * An ordinary shell with no owner broker cannot enable the source gate. */
export async function requestGatewayRuntimeSourceGate({boundary,contract,policyVersion,socketPath=process.env.MEM9_BOOTSTRAP_REQUEST_SOCKET,signal}){
 const document=typeof boundary==='string'?JSON.parse(boundary):boundary;
 need(hash(document)===hash(expectedGatewayBoundaryPolicyDocument(contract))&&/^v[1-9][0-9]*$/.test(policyVersion),'Boundary');
 need(typeof socketPath==='string'&&isAbsolute(socketPath)&&Buffer.byteLength(socketPath)<104,'NativeOwnerRequired');
 const s=await lstat(socketPath),parent=await lstat(dirname(socketPath));
 need(s.isSocket()&&s.uid===process.getuid()&&(s.mode&511)===0o600&&parent.isDirectory()&&parent.uid===process.getuid()&&(parent.mode&511)===0o700&&await realpath(socketPath)===socketPath,'NativeOwnerRequired');
 const id=randomBytes(16).toString('hex'),request={version:1,id,argv:['gateway-runtime','verify-source','--boundary-document',JSON.stringify(document),'--policy-version',policyVersion,'--region',contract.applicationRegion]},raw=Buffer.from(JSON.stringify(request));
 need(raw.length<=MAX,'RequestSize');const frame=Buffer.alloc(raw.length+4);frame.writeUInt32BE(raw.length);raw.copy(frame,4);signal?.throwIfAborted();
 return new Promise((resolve,reject)=>{
  const socket=net.createConnection(socketPath),buffer=Buffer.alloc(MAX+4);let size=0,settled=false;
  const finish=(error,value)=>{if(settled)return;settled=true;clearTimeout(timer);signal?.removeEventListener('abort',abort);socket.destroy();error?reject(error):resolve(value);};
  const abort=()=>finish(Error('GatewayRuntimeSourceAborted')),timer=setTimeout(()=>finish(Error('GatewayRuntimeSourceTimeout')),15000);
  signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
  socket.on('connect',()=>socket.write(frame));
  socket.on('data',chunk=>{try{need(size+chunk.length<=buffer.length,'ResponseSize');buffer.set(chunk,size);size+=chunk.length;if(size>=4)need(buffer.readUInt32BE(0)>0&&buffer.readUInt32BE(0)<=MAX&&size<=buffer.readUInt32BE(0)+4,'ResponseSize');}catch(e){finish(e);}});
  socket.on('end',()=>{try{
   need(size>=4&&size===buffer.readUInt32BE(0)+4,'Incomplete');const body=buffer.subarray(4,size),value=JSON.parse(body.toString('utf8'));need(Buffer.from(JSON.stringify(value)).equals(body)&&exact(value,['version','id','status','stdout','stderr'])&&value.version===1&&value.id===id&&value.status===0&&value.stderr==='','Rejected');
   const text=Buffer.from(value.stdout,'base64');need(text.toString('base64')===value.stdout,'Response');const receipt=JSON.parse(text.toString('utf8'));
   need(Buffer.from(JSON.stringify(receipt)).equals(text)&&exact(receipt,['version','kind','policyHash','policyVersion','evidenceHash','handlerHash','source','coverage'])&&receipt.version===1&&receipt.kind==='gateway-source-condition-verified'&&receipt.policyHash===hash(document)&&receipt.policyVersion===policyVersion&&hash(receipt.coverage)===hash(['kms-source-condition','ec2-source-condition'])&&[receipt.evidenceHash,receipt.handlerHash].every(h=>/^[a-f0-9]{64}$/.test(h??''))&&exact(receipt.source,['commit','tree'])&&Object.values(receipt.source).every(h=>/^[a-f0-9]{40}$/.test(h)),'Receipt');finish(null,receipt);
  }catch(e){finish(e);}});
  socket.on('error',()=>finish(Error('GatewayRuntimeSourceTransport')));socket.on('close',()=>{if(!settled)finish(Error('GatewayRuntimeSourceIncomplete'));});
 });
}
