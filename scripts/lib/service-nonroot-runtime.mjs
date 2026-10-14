import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {setTimeout as wait} from 'node:timers/promises';
import {SSMClient,GetParametersCommand} from '@aws-sdk/client-ssm';
import {serviceNonrootHash as hash} from './service-nonroot.mjs';

const exec=promisify(execFile);
// The observer is a shell, so it cannot be mistaken for a Node application.
// Output contains process security attributes only, never argv or environment.
const processCommand=`/bin/sh -c 'for p in /proc/[0-9]*; do x=$(readlink "$p/exe" 2>/dev/null) || continue; case "$x" in /usr/local/bin/node|/usr/local/bin/mnemo-server) echo "MEM9_PROCESS $p"; echo "Executable: $x"; sed -n "/^Uid:/p;/^Gid:/p;/^Cap/p;/^NoNewPrivs:/p" "$p/status"; echo MEM9_PROCESS_END;; esac; done'`;
export function inspectServiceProcessOutput(output){
 const matches=[...output.matchAll(/MEM9_PROCESS (\/proc\/\d+)\r?\n([\s\S]*?)MEM9_PROCESS_END/g)];
 assert(matches.length>0&&matches.length<=64,'ApplicationProcessMissing');
 return matches.map(([,pid,body])=>{
  const rows=Object.fromEntries(body.trim().split(/\r?\n/).map(line=>{const i=line.indexOf(':');return [line.slice(0,i),line.slice(i+1).trim()];}));
  assert(['/usr/local/bin/node','/usr/local/bin/mnemo-server'].includes(rows.Executable),'ApplicationExecutableInvalid');
  for(const key of ['Uid','Gid'])assert.deepEqual(rows[key]?.split(/\s+/),['1000','1000','1000','1000'],'ApplicationIdentityInvalid');
  for(const key of ['CapInh','CapPrm','CapEff','CapBnd','CapAmb'])assert(/^0+$/.test(rows[key]??''),'ApplicationCapabilityInvalid');
  assert.equal(rows.NoNewPrivs,'1','ApplicationPrivilegeEscalationPossible');return {pid,...rows};
 });
}

/** Real read-only MCP calls. Credentials and response content stay in memory;
 * the returned receipt contains counts and hashes, never memory contents. */
export async function verifyServiceMcp({scope,authMode}){
 assert(['managed','oidc'].includes(authMode),'ExplicitAuthenticationModeRequired');
 const stage=scope.stage??'prod';assert(stage==='prod'||/^pr-[1-9][0-9]*$/.test(stage),'McpStageInvalid');
 const client=new SSMClient({region:scope.region,maxAttempts:1}),prefix='/mem9-on-aws/'+stage;
 const parameters=async names=>{
  const r=await client.send(new GetParametersCommand({Names:names,WithDecryption:true}),{abortSignal:AbortSignal.timeout(15000)});
  assert.equal(r.InvalidParameters?.length??0,0,'McpConfigurationMissing');assert.equal(r.Parameters.length,names.length);
  return Object.fromEntries(r.Parameters.map(p=>[p.Name,p.Value]));
 };
 try{
  let authPrefix=prefix+'/cognito';
  if(authMode==='oidc'){
   authPrefix=(await parameters([prefix+'/auth/provider-prefix']))[prefix+'/auth/provider-prefix'];
   assert(authPrefix.startsWith(prefix+'/auth/providers/')&&!authPrefix.includes('..'),'McpProviderPrefix');
  }
  const credentialPrefix=authPrefix+(authMode==='oidc'?'/m2m':'');
  const names=[authPrefix+'/token-endpoint',authPrefix+'/scope',credentialPrefix+'/client-id',credentialPrefix+'/client-secret',prefix+'/gateway/url'];
  const p=await parameters(names),tokenUrl=new URL(p[names[0]]),gateway=new URL(p[names[4]]);
  for(const url of [tokenUrl,gateway])assert(url.protocol==='https:'&&!url.username&&!url.password&&!url.hash);
  const readScope=p[names[1]].split(' ').find(s=>s.endsWith('/read'));assert(readScope,'McpReadScopeMissing');
  const tokenResponse=await fetch(tokenUrl,{method:'POST',redirect:'error',signal:AbortSignal.timeout(20000),headers:{'content-type':'application/x-www-form-urlencoded',authorization:'Basic '+Buffer.from(encodeURIComponent(p[names[2]])+':'+encodeURIComponent(p[names[3]])).toString('base64')},body:new URLSearchParams({grant_type:'client_credentials',scope:readScope})});
  assert.equal(tokenResponse.status,200,'McpTokenRejected');const token=await tokenResponse.json();assert(typeof token.access_token==='string'&&token.access_token.length>0,'McpTokenMissing');
  let session,id=0;
  const call=async(method,params,authenticated=true)=>{
   const response=await fetch(gateway,{method:'POST',redirect:'error',signal:AbortSignal.timeout(45000),headers:{'content-type':'application/json',accept:'application/json, text/event-stream',...(authenticated?{authorization:'Bearer '+token.access_token}:{}),...(session?{'Mcp-Session-Id':session}:{})},body:JSON.stringify({jsonrpc:'2.0',id:++id,method,params})});
   if(!authenticated){assert([401,403].includes(response.status),'UnauthenticatedMcpAccepted');await response.body?.cancel();return {status:response.status};}
   assert.equal(response.status,200,'McpRequestFailed');session=response.headers.get('Mcp-Session-Id')??session;
   const text=await response.text();assert(Buffer.byteLength(text)<=2*1024*1024,'McpResponseTooLarge');
   const value=response.headers.get('content-type')?.includes('text/event-stream')?text.split('\n').filter(x=>x.startsWith('data:')).map(x=>JSON.parse(x.slice(5))).find(x=>x.id===id):JSON.parse(text);
   assert(value&&!value.error,'McpProtocolError');return value.result;
  };
  const denied=await call('initialize',{protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'service-nonroot-verifier',version:'1'}},false);
  await call('initialize',{protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'service-nonroot-verifier',version:'1'}});
  const listed=await call('tools/list',{});assert(Array.isArray(listed.tools),'McpToolsMissing');
  const namesFound=listed.tools.filter(t=>t.name.endsWith('search_memories'));assert.equal(namesFound.length,1,'McpSearchToolAmbiguous');
  assert(!listed.tools.some(t=>t.name.endsWith('add_memory')||t.name.endsWith('ingest_messages')),'McpReadScopeOverprivileged');
  const results=[];
  for(const mode of ['semantic','keyword']){
   const response=await call('tools/call',{name:namesFound[0].name,arguments:{q:'mem9',limit:1,search_mode:mode}});
   assert(response?.isError!==true&&Array.isArray(response?.content),'McpSearchRejected');
   const block=response.content.find(b=>b.type==='text');assert(block,'McpSearchResponse');const value=JSON.parse(block.text);
   assert(Array.isArray(value.memories),'McpSearchShape');results.push({mode,returned:value.memories.length,responseHash:hash(value)});
  }
  return {kind:'service-mcp-read-verification',observedMs:Date.now(),unauthenticatedStatus:denied.status,readScopeIsolated:true,results};
 }finally{client.destroy();}
}

export async function verifyServiceRuntime(arn,{plan,deadline,aws,scope,authMode}){
 let tasks;const retiredBy=Math.min(deadline-20000,Date.now()+180000);
 do{
  tasks=await aws.inventory();
  if(tasks.length===plan.baseline.service.desiredCount&&tasks.every(t=>t.taskDefinitionArn===arn&&t.lastStatus==='RUNNING'&&t.healthStatus==='HEALTHY'))break;
  assert(Date.now()<retiredBy,'PreviousServiceTaskStillActive');await wait(5000);
 }while(true);
 const processEvidence=[];
 for(const task of tasks){
  assert(task.taskDefinitionArn===arn&&task.lastStatus==='RUNNING'&&task.healthStatus==='HEALTHY');
  for(const c of plan.target.containerDefinitions){
   const actual=task.containers.find(x=>x.name===c.name);assert(actual&&actual.image===c.image&&actual.imageDigest===c.image.split('@')[1]&&actual.healthStatus==='HEALTHY');
   assert(deadline>Date.now(),'RuntimeVerificationDeadline');
   const result=await exec('aws',['ecs','execute-command','--region',scope.region,'--cluster',scope.cluster,'--task',task.taskArn,'--container',c.name,'--interactive','--command',processCommand],{timeout:Math.min(60000,deadline-Date.now()),maxBuffer:128*1024});
   processEvidence.push({taskArn:task.taskArn,container:c.name,runtimeId:actual.runtimeId,processes:inspectServiceProcessOutput(result.stdout)});
  }
 }
 const mcp=await verifyServiceMcp({scope,authMode});
 const after=await aws.inventory();assert.equal(hash(after.map(t=>({arn:t.taskArn,definition:t.taskDefinitionArn,containers:t.containers.map(c=>({name:c.name,runtimeId:c.runtimeId,image:c.imageDigest}))}))),hash(tasks.map(t=>({arn:t.taskArn,definition:t.taskDefinitionArn,containers:t.containers.map(c=>({name:c.name,runtimeId:c.runtimeId,image:c.imageDigest}))}))),'ServingTaskChangedDuringVerification');
 await aws.persistOnce('runtime-verification.json',{processEvidence,mcp});
 return {tasks:after,evidenceHash:hash({processEvidence,mcp})};
}
