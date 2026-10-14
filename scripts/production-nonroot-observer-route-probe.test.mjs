import {describe,it,expect} from 'vitest';
import {OBSERVER_ROUTE_SLOTS,OBSERVER_ROUTE_LIMITS,describeObserverRouteEventWork,createObserverRouteEventCounter,inspectObserverRouteProtocol,observerPrivateStatusPath,observerMcpRequest,parseObserverMcpResponse,inspectObserverMcpInitialization,selectObserverStatusTool,inspectObserverJobStatus,inspectObserverMcpStatus} from './lib/production-nonroot-observer-route-probe.mjs';
const id='12345678-1234-1234-1234-123456789abc';
const route=()=>({privateOrigin:'http://mnemo.mem9-pr-7.local:1024',gatewayUrl:'https://gateway.example.com/mcp',jobId:id,identityHash:'a'.repeat(64),issuer:'https://issuer.example.com/',audience:'read-client',transportIssuer:'test-transport',tokenEndpoint:'https://issuer.example.com/oauth2/token',jwksUri:'https://issuer.example.com/.well-known/jwks.json',registryHash:'b'.repeat(64)});
const valid=()=>({...route(),privateOrigin:'http://mnemo.mem9-pr-7.local:8080'});
const userinfoGatewayUrl=()=>{const url=new URL('https://gateway.example.com/mcp');url.username='user';url.password='password';return url.href;};
const status=()=>({job_id:id,state:'queued',attempts:0,created_at:'2026-10-11T00:00:00Z',updated_at:'2026-10-11T00:00:00Z'});
const listed=name=>({tools:[{name,description:'Get the state and timestamps of an accepted transcript-ingest job.',inputSchema:{type:'object',properties:{job_id:{type:'string',description:'The job id returned by ingest_messages.'}},required:['job_id']}}]});
const wire=result=>Buffer.from(JSON.stringify({jsonrpc:'2.0',id:4,result}));
describe('fixed observer protocol DATA only',()=>{
 it('keeps private GET path and six distinct route slots',()=>{
  expect(inspectObserverRouteProtocol(valid(),'pr-7')).toEqual(valid());
  expect(observerPrivateStatusPath(id)).toBe('/v1alpha2/mem9s/ingest-jobs/'+id);
  expect(OBSERVER_ROUTE_SLOTS).toHaveLength(6);
  const rows=OBSERVER_ROUTE_SLOTS.slice(2).map(s=>observerMcpRequest(s,id,'backend___get_ingest_job_status'));
  expect(rows.map(r=>r.method)).toEqual(['POST','POST','POST','POST']);
  expect(rows.map(r=>r.authenticated)).toEqual([false,true,true,true]);
  expect(rows.map(r=>JSON.parse(r.body).method)).toEqual(['initialize','initialize','tools/list','tools/call']);
  expect(JSON.parse(rows[3].body).params).toEqual({name:'backend___get_ingest_job_status',arguments:{job_id:id}});
 });
 for(const [name,patch,stage]of [
  ['production',{},'prod'],['wrong private port',{privateOrigin:route().privateOrigin},'pr-7'],
  ['different private stage',{privateOrigin:'http://mnemo.mem9-pr-8.local:8080'},'pr-7'],
  ['loopback',{privateOrigin:'http://127.0.0.1:8080'},'pr-7'],
  ['metadata',{gatewayUrl:'https://169.254.169.254/mcp'},'pr-7'],
  ['userinfo',{gatewayUrl:userinfoGatewayUrl()},'pr-7'],
  ['gateway GET alias',{gatewayUrl:'https://gateway.example.com/v1alpha2/mem9s/ingest-jobs/'+id},'pr-7'],
  ['query',{gatewayUrl:'https://gateway.example.com/mcp?token=anything'},'pr-7'],
  ['foreign JWKS',{jwksUri:'https://other.example.com/.well-known/jwks.json'},'pr-7'],
  ['inline token',{accessToken:'forbidden'},'pr-7'],
 ])it('rejects '+name,()=>expect(()=>inspectObserverRouteProtocol({...valid(),...patch},stage)).toThrow());
 for(const name of ['search_memories','add_memory','ingest_messages','backend___search_memories','get_ingest_job_status/extra'])it('cannot emit a tools/call for '+name,()=>expect(()=>observerMcpRequest('ingress-job-status',id,name)).toThrow());
 it('matches source-selected unique status tool and rejects duplicates',()=>{
  expect(selectObserverStatusTool(listed('backend___get_ingest_job_status'))).toBe('backend___get_ingest_job_status');
  expect(()=>selectObserverStatusTool({tools:[...listed('get_ingest_job_status').tools,...listed('backend___get_ingest_job_status').tools]})).toThrow();
  expect(()=>selectObserverStatusTool(listed('add_memory'))).toThrow();
 });
 it('rejects a broadened status tool schema',()=>{
  const x=listed('get_ingest_job_status');x.tools[0].inputSchema.properties.content={type:'string'};
  expect(()=>selectObserverStatusTool(x)).toThrow();
 });
 it('parses actual JSON and SSE frames without a success flag',()=>{
  const result={content:[{type:'text',text:JSON.stringify(status())}]};
  expect(inspectObserverMcpStatus(parseObserverMcpResponse(wire(result),4),id)).toEqual(status());
  const sse=Buffer.from('event: message\ndata: '+wire(result).toString()+'\n\n');
  expect(parseObserverMcpResponse(sse,4)).toEqual(result);
 });
 it('rejects wrong ids, duplicate responses, errors and unbounded frames',()=>{
  expect(()=>parseObserverMcpResponse(wire({}),3)).toThrow();
  expect(()=>parseObserverMcpResponse(Buffer.from('data: '+wire({})+'\n\ndata: '+wire({})+'\n\n'),4)).toThrow();
  expect(()=>parseObserverMcpResponse(Buffer.from('{"jsonrpc":"2.0","id":4,"error":{"code":-1}}'),4)).toThrow();
  expect(()=>parseObserverMcpResponse(Buffer.alloc(1048577),4)).toThrow();
 });
 it('validates the fixed initialization protocol independently',()=>{
  const x={protocolVersion:'2025-03-26',capabilities:{tools:{}},serverInfo:{name:'test-gateway',version:'1'}};
  expect(inspectObserverMcpInitialization(x)).toEqual(x);
  expect(()=>inspectObserverMcpInitialization({...x,protocolVersion:'unselected'})).toThrow();
 });
 it.each([
  {tools:{listChanged:false},prompts:{listChanged:false},resources:{listChanged:false}},
  {tools:{},prompts:{}},
  {tools:{listChanged:true},resources:{listChanged:true}},
 ])('preserves optional gateway capability declarations without adding observer calls (%j)',capabilities=>{
  const x={protocolVersion:'2025-03-26',capabilities,serverInfo:{name:'test-gateway',version:'1'}},before=structuredClone(x);
  expect(inspectObserverMcpInitialization(x)).toBe(x);
  expect(x).toEqual(before);
  expect(JSON.parse(observerMcpRequest('ingress-job-status',id,'get_ingest_job_status').body).params)
   .toEqual({name:'get_ingest_job_status',arguments:{job_id:id}});
 });
 it.each([
  {prompts:{}},
  {tools:{},unknown:{}},
  {tools:{},prompts:null},
  {tools:{},resources:[]},
  {tools:{},prompts:{listChanged:'false'}},
  {tools:{},resources:{listChanged:0}},
  {tools:{},prompts:{unexpected:true}},
  {tools:{},resources:{unexpected:true}},
 ])('rejects missing, malformed or unrecognized gateway capabilities (%j)',capabilities=>{
  const x={protocolVersion:'2025-03-26',capabilities,serverInfo:{name:'test-gateway',version:'1'}};
  expect(()=>inspectObserverMcpInitialization(x)).toThrow();
 });
 it('retains complete allowed status fields without memory content',()=>{
  const x={...status(),state:'failed',warning_class:'retryable',error_class:'timeout',completed_at:'2026-10-11T00:00:01Z'};
  expect(inspectObserverJobStatus(x,id)).toEqual(x);
  for(const patch of [{content:'customer memory'},{job_id:'foreign'},{attempts:-1},{error_class:'sensitive/path/value'}])expect(()=>inspectObserverJobStatus({...x,...patch},id)).toThrow();
 });
 it('rejects fabricated success flags and conflicting structured result',()=>{
  const x={content:[{type:'text',text:JSON.stringify(status())}],isError:false};
  expect(()=>inspectObserverMcpStatus({...x,success:true},id)).toThrow();
  expect(()=>inspectObserverMcpStatus({...x,structuredContent:{...status(),attempts:1}},id)).toThrow();
  expect(()=>inspectObserverMcpStatus({...x,isError:true},id)).toThrow();
 });
});
describe('bounded event work DATA, never original payment or authority',()=>{
 it('keeps both4096 event limits and prepays the first rejected callback too',()=>{
  const q=describeObserverRouteEventWork();expect(q.authority).toBe(false);expect(q.maximumWireEvents).toBe(4096);expect(q.maximumBodyEvents).toBe(4096);
  expect(q.rejectedEventsPerStream).toBe(1);expect(q.logicalBytes).toBe(4097*(q.wireEventLocal+q.bodyEventLocal));expect(()=>describeObserverRouteEventWork({chunks:1})).toThrow();
  expect(OBSERVER_ROUTE_LIMITS).toMatchObject({chunks:4096,responseBytes:1048576,contextMs:30000,knownRefusalLocalBytes:131072,outputBytes:65536});
 });
 it('keeps independent wire/body accounting through4096 fragmented events',()=>{
  const counter=createObserverRouteEventCounter(8192),q=describeObserverRouteEventWork();
  for(let i=0;i<4096;i++){counter.wire(2);counter.body(1);}
  const s=counter.snapshot();expect(s).toMatchObject({authority:false,wireEvents:4096,bodyEvents:4096,wireBytes:8192,bodyBytes:4096,held:false});
  expect(s.logicalBytes).toBe(4096*(q.wireEventLocal+q.bodyEventLocal));expect(s.logicalBytes).toBeLessThan(s.prepaidLocalUpperBound);
 });
 for(const lane of ['wire','body'])it('rejects '+lane+' callback4097 before another copy/charge can proceed',()=>{
  const c=createObserverRouteEventCounter(1048576),q=describeObserverRouteEventWork();for(let i=0;i<4096;i++)c[lane](1);
  expect(()=>c[lane](1)).toThrow();const s=c.snapshot();expect(s.held).toBe(true);expect(s[lane+'Events']).toBe(4097);expect(s[lane+'Bytes']).toBe(4096);
  expect(s.logicalBytes).toBe(4097*q[lane+'EventLocal']);expect(s.logicalBytes).toBeLessThanOrEqual(q.logicalBytes);expect(()=>c[lane](0)).toThrow();
 });
 it('empty callbacks still consume bounded work and cannot bypass event count',()=>{
  const c=createObserverRouteEventCounter(1);for(let i=0;i<4096;i++)c.wire(0);expect(()=>c.wire(0)).toThrow();expect(c.snapshot().wireBytes).toBe(0);expect(c.snapshot().logicalBytes).toBeGreaterThan(0);
 });
 it('interleaving order cannot merge or reset separate stream budgets',()=>{
  const a=createObserverRouteEventCounter(10),b=createObserverRouteEventCounter(10);
  a.wire(3);a.body(4);a.wire(7);a.body(6);b.body(4);b.body(6);b.wire(3);b.wire(7);expect(a.snapshot()).toEqual(b.snapshot());
  expect(()=>a.body(1)).toThrow();expect(a.snapshot().bodyBytes).toBe(10);
 });
 for(const bytes of [-1,NaN,Infinity,1.5])it('rejects invalid event byte count '+bytes,()=>{const c=createObserverRouteEventCounter(8);expect(()=>c.body(bytes)).toThrow();expect(c.snapshot().held).toBe(true);});
 it('cannot create a counter with an unbounded response size',()=>{for(const n of [0,-1,1048577,NaN])expect(()=>createObserverRouteEventCounter(n)).toThrow();});
});
