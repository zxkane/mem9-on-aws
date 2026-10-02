import {describe,it,expect} from 'vitest';
import {loadMcpCanaryConfiguration,createMcpCanaryClient,sampleMcpCanaryCohort} from './lib/mcp-canary-sampler.mjs';

function configurationFixture(mode='managed',stage='prod'){
  const prefix=`/mem9-on-aws/${stage}/`,provider=prefix+'auth/providers/'+'a'.repeat(64);
  const activeEndpoint=mode==='oidc'?'https://id.example.com/oauth/token':'https://cognito.example.com/oauth2/token';
  const scope='mem9-mcp/read mem9-mcp/write',secret='  synthetic-secret\t';
  const values={
    [prefix+'auth/mode']:mode,[prefix+'auth/token-endpoint']:activeEndpoint,[prefix+'auth/scope']:scope,[prefix+'gateway/url']:'https://gateway.example.com/mcp',
    [prefix+'auth/provider-prefix']:provider,
    [prefix+'cognito/token-endpoint']:'https://cognito.example.com/oauth2/token',[prefix+'cognito/scope']:scope,
    [prefix+'cognito/client-id']:'managed-client',[prefix+'cognito/client-secret']:secret,
    [provider+'/token-endpoint']:activeEndpoint,[provider+'/scope']:scope,
    [provider+'/m2m/client-id']:'oidc-client',[provider+'/m2m/client-secret']:secret,
    [provider+'/browser/client-id']:'browser-client',[provider+'/browser/client-secret']:'browser-secret',
  };
  const records=new Map(Object.entries(values).map(([Name,Value])=>[Name,{Name,Value,Version:1}]));
  const calls=[];let beforeRead=()=>{},afterRead=result=>result;
  const ssm={send:async(command,options)=>{
    const input=command.input;calls.push({input:structuredClone(input),signal:options?.abortSignal});beforeRead(input,records);
    const Parameters=input.Names.filter(name=>records.has(name)).map(name=>{
      const item={...records.get(name)};
      if(name.endsWith('/client-secret')&&!input.WithDecryption)item.Value='ciphertext';
      return item;
    }).reverse();
    return afterRead({Parameters,InvalidParameters:input.Names.filter(name=>!records.has(name))},input);
  }};
  return {ssm,stage,prefix,provider,records,calls,secret,expected:{tokenEndpoint:activeEndpoint,clientId:mode==='oidc'?'oidc-client':'managed-client',clientSecret:secret,scopes:scope,gatewayUrl:values[prefix+'gateway/url']},
    beforeRead:fn=>{beforeRead=fn;},afterRead:fn=>{afterRead=fn;},
    credentialReads:()=>calls.filter(call=>call.input.Names.some(name=>name.endsWith('/client-secret')))};
}

describe('canary deployed authentication configuration',()=>{
  for(const mode of ['managed','oidc'])it(`uses the deployed ${mode} M2M client and confirms the complete selected set`,async()=>{
    const f=configurationFixture(mode);expect(await loadMcpCanaryConfiguration(f.ssm,f.stage)).toEqual(f.expected);
    const calls=f.calls.map(c=>c.input),last=calls.at(-1),secretPath=mode==='oidc'?f.provider+'/m2m/client-secret':f.prefix+'cognito/client-secret';
    expect(last.Names).toHaveLength(mode==='oidc'?9:8);expect(last.WithDecryption).toBe(true);expect(last.Names).toContain(secretPath);
    expect(last.Names).toContain(f.prefix+'auth/mode');expect(last.Names).toContain(f.prefix+'gateway/url');
    if(mode==='oidc')expect(last.Names).toContain(f.prefix+'auth/provider-prefix');
    expect(calls.every(c=>c.Names.length<=10&&new Set(c.Names).size===c.Names.length)).toBe(true);
    expect(f.calls.every(c=>c.signal instanceof AbortSignal)).toBe(true);
    expect(calls.every(c=>c.Names.every(n=>!n.includes('/browser/')))).toBe(true);
    if(mode==='oidc')expect(calls.every(c=>c.Names.every(n=>!n.includes('/cognito/')))).toBe(true);
    else expect(calls.every(c=>c.Names.every(n=>!n.includes('/auth/providers/')&&!n.endsWith('/provider-prefix')))).toBe(true);
    const publicPaths=mode==='oidc'?[f.provider+'/token-endpoint',f.provider+'/scope']:[f.prefix+'cognito/token-endpoint',f.prefix+'cognito/scope'];
    const firstSecret=calls.findIndex(c=>c.Names.includes(secretPath));
    for(const path of publicPaths)expect(calls.findIndex(c=>c.Names.includes(path))).toBeLessThan(firstSecret);
    expect(f.credentialReads().every(c=>c.input.WithDecryption===true)).toBe(true);
  });
  it('supports managed preview stages with deployed metadata',async()=>{
    const f=configurationFixture('managed','pr-7');expect(await loadMcpCanaryConfiguration(f.ssm,f.stage)).toEqual(f.expected);
  });
  it('rejects invalid stages without SSM reads',async()=>{
    for(const stage of [undefined,null,7,{},'pr-0','prod/other']){const f=configurationFixture();await expect(loadMcpCanaryConfiguration(f.ssm,stage)).rejects.toThrow('McpCanaryFailure');expect(f.calls).toHaveLength(0);}
  });
  it('does not fall back when deployed mode is unknown or absent',async()=>{
    for(const value of [undefined,'',' ','OIDC','other']){const f=configurationFixture();if(value===undefined)f.records.delete(f.prefix+'auth/mode');else f.records.get(f.prefix+'auth/mode').Value=value;await expect(loadMcpCanaryConfiguration(f.ssm,f.stage)).rejects.toThrow('McpCanaryFailure');expect(f.credentialReads()).toHaveLength(0);}
  });
  it('rejects malformed or incomplete SSM responses before credentials',async()=>{
    const changes=[r=>undefined,r=>({}),r=>({...r,Parameters:{}}),r=>({...r,Parameters:r.Parameters.slice(1)}),r=>({...r,Parameters:[...r.Parameters,r.Parameters[0]]}),r=>({...r,Parameters:[{Name:'unexpected',Value:'value',Version:1},...r.Parameters.slice(1)]}),r=>({...r,InvalidParameters:['missing']})];
    for(const change of changes){const f=configurationFixture();f.afterRead(change);await expect(loadMcpCanaryConfiguration(f.ssm,f.stage)).rejects.toThrow('McpCanaryFailure');expect(f.credentialReads()).toHaveLength(0);}
    for(const Version of [undefined,0,-1,1.5,'1']){const f=configurationFixture();f.records.get(f.prefix+'auth/mode').Version=Version;await expect(loadMcpCanaryConfiguration(f.ssm,f.stage)).rejects.toThrow('McpCanaryFailure');expect(f.credentialReads()).toHaveLength(0);}
  });
  it('rejects invalid public URLs before credential selection',async()=>{
    for(const suffix of ['auth/token-endpoint','gateway/url'])for(const value of ['http://example.com','https://user:pass@example.com','https://example.com/#fragment','not-a-url',' https://example.com']){
      const f=configurationFixture();f.records.get(f.prefix+suffix).Value=value;await expect(loadMcpCanaryConfiguration(f.ssm,f.stage)).rejects.toThrow('McpCanaryFailure');expect(f.credentialReads()).toHaveLength(0);
    }
  });
  it('rejects cross-stage, browser, traversal and malformed OIDC prefixes before credential reads',async()=>{
    for(const value of ['/mem9-on-aws/pr-7/auth/providers/'+'a'.repeat(64),'/mem9-on-aws/prod/auth/providers/'+'A'.repeat(64),'/mem9-on-aws/prod/auth/providers/'+'a'.repeat(63),'/mem9-on-aws/prod/auth/providers/'+'a'.repeat(64)+'/browser','/mem9-on-aws/prod/auth/providers/../../cognito']){
      const f=configurationFixture('oidc');f.records.get(f.prefix+'auth/provider-prefix').Value=value;await expect(loadMcpCanaryConfiguration(f.ssm,f.stage)).rejects.toThrow('McpCanaryFailure');expect(f.credentialReads()).toHaveLength(0);
    }
  });
  for(const mode of ['managed','oidc'])it(`rejects stable mixed ${mode} endpoints or scopes before fetching credentials`,async()=>{
    for(const suffix of ['token-endpoint','scope']){const f=configurationFixture(mode),selected=mode==='oidc'?f.provider:f.prefix+'cognito';f.records.get(selected+'/'+suffix).Value=suffix==='token-endpoint'?'https://other.example.com/token':'other/read other/write';await expect(loadMcpCanaryConfiguration(f.ssm,f.stage)).rejects.toThrow('McpCanaryFailure');expect(f.credentialReads()).toHaveLength(0);}
    const f=configurationFixture(mode);f.records.get(f.prefix+'auth/token-endpoint').Value='https://other.example.com/token';await expect(loadMcpCanaryConfiguration(f.ssm,f.stage)).rejects.toThrow('McpCanaryFailure');expect(f.credentialReads()).toHaveLength(0);
  });
  it('does not fall back to retained or browser credentials when OIDC M2M credentials are missing',async()=>{
    const f=configurationFixture('oidc');f.records.delete(f.provider+'/m2m/client-secret');await expect(loadMcpCanaryConfiguration(f.ssm,f.stage)).rejects.toThrow('McpCanaryFailure');expect(f.calls.every(c=>c.input.Names.every(n=>!n.includes('/cognito/')&&!n.includes('/browser/')))).toBe(true);
  });
  it('rejects value changes, version-only changes and pointer ABA observed at confirmation',async()=>{
    for(const mode of ['managed','oidc'])for(const kind of ['value','version','pointer']){
      if(kind==='pointer'&&mode!=='oidc')continue;
      const f=configurationFixture(mode),selected=mode==='oidc'?f.provider+'/m2m':f.prefix+'cognito',secret=selected+'/client-secret';
      f.beforeRead((input,records)=>{if(!input.Names.includes(f.prefix+'auth/mode')||!input.Names.includes(secret))return;const key=kind==='pointer'?f.prefix+'auth/provider-prefix':secret;const p=records.get(key);if(kind==='value')p.Value='rotated-secret';else p.Version+=2;});
      await expect(loadMcpCanaryConfiguration(f.ssm,f.stage)).rejects.toThrow('McpCanaryFailure');
    }
  });
  it('rejects malformed confirmation and sanitizes provider failures',async()=>{
    const f=configurationFixture('oidc');f.afterRead((result,input)=>input.Names.includes(f.prefix+'auth/mode')&&input.Names.includes(f.provider+'/m2m/client-secret')?{...result,Parameters:result.Parameters.slice(1)}:result);await expect(loadMcpCanaryConfiguration(f.ssm,f.stage)).rejects.toThrow('McpCanaryFailure');
    const failing={send:async()=>{throw Error('PRIVATE CLIENT SECRET AND ENDPOINT');}};
    await expect(loadMcpCanaryConfiguration(failing,'prod')).rejects.toThrow(/^McpCanaryFailure$/);
  });
});

async function fixture({mcpError=false}={}){
  let elapsed=0,id=0;const calls=[],writes=[];
  const fetchImpl=async(url,init)=>{
    calls.push({url,init});elapsed+=1;
    let value;
    if(String(url).endsWith('/oauth2/token'))value={access_token:'synthetic-private-token',expires_in:3600,token_type:'Bearer'};
    else{
      const request=JSON.parse(init.body);let result={};
      if(request.method==='tools/list')result={tools:[{name:'target___search_memories'},{name:'target___add_memory'}]};
      if(request.method==='tools/call'){
        const args=request.params.arguments;
        const body=request.params.name.endsWith('search_memories')?{memories:[{content:'PRIVATE MEMORY MUST NOT APPEAR'}],total:1}:
          {id:'synthetic-'+(++id),content:args.content,agent_id:args.agent_id,memory_type:'pinned',state:'active',version:1};
        result={isError:mcpError,content:[{type:'text',text:JSON.stringify(body)}]};
      }
      value={jsonrpc:'2.0',id:request.id,result};
    }
    return {ok:true,headers:new Headers(),text:async()=>{elapsed+=9;return JSON.stringify(value);}};
  };
  const client=await createMcpCanaryClient({tokenEndpoint:'https://auth.example.com/oauth2/token',gatewayUrl:'https://gateway.example.com/mcp',
    clientId:'synthetic-client',clientSecret:'synthetic-secret',scopes:'mem9-mcp/read mem9-mcp/write'},{fetchImpl});
  return {client,calls,writes,options:{validationId:'a'.repeat(32),phase:'baseline',clock:()=>elapsed,wallClock:()=>1700000000000+elapsed,sleep:async ms=>{elapsed+=ms;},onWrite:async row=>writes.push(row)}};
}
describe('MCP foreground canary sampler',()=>{
  it('measures full body consumption and emits no credentials or recalled memory content',async()=>{
    const f=await fixture(),result=await sampleMcpCanaryCohort(f.client,f.options);
    expect(result.samples).toHaveLength(200);expect(result.samples.every(sample=>sample.latencyMs===10)).toBe(true);
    expect(f.writes).toHaveLength(105);expect(f.calls.every(call=>call.init.redirect==='error')).toBe(true);
    expect(JSON.stringify(result)).not.toContain('PRIVATE MEMORY');expect(JSON.stringify(result)).not.toContain('synthetic-private-token');
    expect(result.samples.filter(sample=>sample.kind==='write_ack')).toHaveLength(100);
  });
  it('rejects MCP error envelopes even on HTTP success, without retrying or calling them valid samples',async()=>{
    const f=await fixture({mcpError:true});
    await expect(sampleMcpCanaryCohort(f.client,f.options)).rejects.toThrow('McpCanaryFailure');
    expect(f.writes).toEqual([]);
  });
});
