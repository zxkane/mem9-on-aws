import {describe,it,expect} from 'vitest';
import {createMcpCanaryClient,sampleMcpCanaryCohort} from './lib/mcp-canary-sampler.mjs';

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
