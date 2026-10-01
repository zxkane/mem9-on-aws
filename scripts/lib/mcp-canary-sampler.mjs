import {createHash} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {GetParametersCommand} from '@aws-sdk/client-ssm';
import {setTimeout as delay} from 'node:timers/promises';
import {canaryBenchmarkContent} from './canary-benchmark.mjs';
export {canaryBenchmarkContent} from './canary-benchmark.mjs';

const fail=()=>{throw Error('McpCanaryFailure');};
const queries=['development workflow','database migrations','memory storage','deployment verification','access permissions','runtime configuration','testing practices','service reliability'];
const hash=value=>createHash('sha256').update(value).digest('hex');
const secureUrl=value=>{let url;try{url=new URL(value);}catch{fail();}if(url.protocol!=='https:'||url.username||url.password||url.hash)fail();return url.href;};

export async function loadMcpCanaryConfiguration(ssm,stage){
  if(stage!=='prod'&&!/^pr-[1-9][0-9]*$/.test(stage??''))fail();
  const prefix=`/mem9-on-aws/${stage}/`,keys=['cognito/token-endpoint','cognito/client-id','cognito/client-secret','cognito/scope','gateway/url'];
  const result=await ssm.send(new GetParametersCommand({Names:keys.map(key=>prefix+key),WithDecryption:true}),{abortSignal:AbortSignal.timeout(30000)});
  if(result.InvalidParameters?.length||result.Parameters?.length!==keys.length)fail();
  const values=new Map(result.Parameters.map(parameter=>[parameter.Name,parameter.Value]));
  if(values.size!==keys.length||keys.some(key=>!values.get(prefix+key)))fail();
  return {tokenEndpoint:values.get(prefix+keys[0]),clientId:values.get(prefix+keys[1]),clientSecret:values.get(prefix+keys[2]),
    scopes:values.get(prefix+keys[3]),gatewayUrl:values.get(prefix+keys[4])};
}

async function responseText(response){
  const text=await response.text();
  if(!response.ok||Buffer.byteLength(text)>4*1024*1024)fail();return text;
}

export async function createMcpCanaryClient(config,{fetchImpl=fetch}={}){
  const tokenEndpoint=secureUrl(config.tokenEndpoint),gatewayUrl=secureUrl(config.gatewayUrl);
  if(typeof config.clientId!=='string'||!config.clientId||typeof config.clientSecret!=='string'||!config.clientSecret||
    typeof config.scopes!=='string'||!config.scopes.split(' ').some(scope=>scope.endsWith('/read'))||!config.scopes.split(' ').some(scope=>scope.endsWith('/write')))fail();
  const basic=Buffer.from(encodeURIComponent(config.clientId)+':'+encodeURIComponent(config.clientSecret)).toString('base64');
  const auth=JSON.parse(await responseText(await fetchImpl(tokenEndpoint,{method:'POST',redirect:'error',signal:AbortSignal.timeout(30000),
    headers:{Authorization:'Basic '+basic,'Content-Type':'application/x-www-form-urlencoded'},
    body:new URLSearchParams({grant_type:'client_credentials',scope:config.scopes}).toString()})));
  if(typeof auth.access_token!=='string'||!auth.access_token||!Number.isFinite(auth.expires_in)||auth.expires_in<600)fail();
  const expires=Date.now()+auth.expires_in*1000;let sequence=0,session;
  const rpc=async(method,params)=>{
    if(Date.now()+30000>=expires)fail();
    const id=++sequence,response=await fetchImpl(gatewayUrl,{method:'POST',redirect:'error',signal:AbortSignal.timeout(30000),
      headers:{Authorization:'Bearer '+auth.access_token,'Content-Type':'application/json',Accept:'application/json, text/event-stream',...(session?{'Mcp-Session-Id':session}:{})},
      body:JSON.stringify({jsonrpc:'2.0',id,method,params})});
    const raw=await responseText(response),next=response.headers.get('mcp-session-id');
    if(next){if(next.length>512||/[\r\n]/.test(next))fail();session=next;}
    let messages;
    try{messages=[JSON.parse(raw)];}catch{
      messages=raw.split(/\r?\n\r?\n/).flatMap(frame=>{
        const data=frame.split(/\r?\n/).filter(line=>line.startsWith('data:')).map(line=>line.slice(5).trimStart()).join('\n');
        if(!data)return [];try{return [JSON.parse(data)];}catch{fail();}
      });
    }
    const found=messages.filter(message=>message.id===id);
    if(found.length!==1||found[0].error||!found[0].result||found[0].result.isError)fail();return found[0].result;
  };
  await rpc('initialize',{protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'mem9-canary',version:'1'}});
  const listed=await rpc('tools/list',{});
  if(!Array.isArray(listed.tools))fail();
  const name=suffix=>{const matches=listed.tools.filter(tool=>typeof tool.name==='string'&&(tool.name===suffix||tool.name.endsWith('___'+suffix)));if(matches.length!==1)fail();return matches[0].name;};
  const readName=name('search_memories'),writeName=name('add_memory');
  const call=async(name,args)=>{
    const result=await rpc('tools/call',{name,arguments:args});
    if(!Array.isArray(result.content)||result.content.length!==1||result.content[0].type!=='text')fail();
    let value;try{value=JSON.parse(result.content[0].text);}catch{fail();}
    if(!value||typeof value!=='object'||Array.isArray(value)||value.error)fail();return value;
  };
  return {
    endpointHash:hash(gatewayUrl),
    async read(index){
      const value=await call(readName,{q:queries[index%queries.length],limit:1,search_mode:'semantic'});
      if(!Array.isArray(value.memories)||!Number.isFinite(value.total)||value.total<0)fail();
    },
    async write(content,agentId){
      const value=await call(writeName,{content,agent_id:agentId,memory_type:'pinned'}),memory=value.memory??value;
      if(typeof memory.id!=='string'||!memory.id||memory.id.length>128||memory.content!==content||memory.memory_type!=='pinned'||
        memory.state!=='active'||memory.version!==1||memory.agent_id!==agentId)fail();
      return {id:memory.id,version:memory.version,agentId,contentHash:hash(content)};
    },
  };
}

export async function sampleMcpCanaryCohort(client,{validationId,phase,samplesPerKind=100,clock=()=>performance.now(),wallClock=Date.now,sleep=delay,onWrite=async()=>{}}){
  canaryBenchmarkContent(validationId,phase,0);
  if(!Number.isInteger(samplesPerKind)||samplesPerKind<100||samplesPerKind>500)fail();
  const warmupsPerKind=5,cadenceMs=250,agentId='mem9-canary-'+validationId,samples=[],deadline=wallClock()+300000;
  let nextStart=clock();
  const operation=async(kind,index,warmup)=>{
    if(clock()<nextStart)await sleep(nextStart-clock());
    if(wallClock()>=deadline)fail();
    const startedMs=wallClock(),start=clock();
    const ref=kind==='read'?await client.read(index):await client.write(canaryBenchmarkContent(validationId,phase,index,warmup),agentId);
    const latencyMs=clock()-start,finishedMs=wallClock();
    nextStart=start+cadenceMs;
    if(!warmup)samples.push({kind,index,ok:true,startedMs,finishedMs,latencyMs});
    if(ref)await onWrite({...ref,phase,index,warmup});
  };
  for(let i=0;i<warmupsPerKind;i++){await operation('read',i,true);await operation('write_ack',i,true);}
  for(let i=0;i<samplesPerKind;i++){await operation('read',i,false);await operation('write_ack',i,false);}
  return {version:1,workloadHash:hash(JSON.stringify({version:1,queries,type:'pinned',samplesPerKind,warmupsPerKind,concurrency:1,cadenceMs})),
    samplesPerKind,warmupsPerKind,concurrency:1,cadenceMs,samples};
}
