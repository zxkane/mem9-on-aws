import {describe,it,expect} from 'vitest';
import {replayCanaryReceipts} from './consolidation-canary-replay.mjs';
const id='a'.repeat(64),namespace='60000000-0000-4000-8000-000000000001';
const result={action_id:id,status:'applied',changed_rows:2,cost:{total:2,rewrite:0,delete:1,archive:0,mark:0}};
const env={MEM9_STAGE:'prod',MEM9_CANARY_INVOCATION:'b'.repeat(32),MEM9_TENANT_ID:'synthetic-tenant',MEM9_BASE_URL:'http://backend.internal:8080',
  MEM9_SERVICE_TRANSPORT_SIGNING_KEYS:JSON.stringify({active:'a',a:'A'.repeat(43),b:'B'.repeat(43)}),
  MEM9_CANARY_ACTIONS:JSON.stringify([{id,namespace,result}])};
describe('bounded cached receipt replay',()=>{
  it('matches committed results without mislabelling cached changed_rows as new mutations',async()=>{
    const calls=[];const report=await replayCanaryReceipts(env,{fetchForScope:scope=>async(url,options)=>{
      calls.push({scope,url,options});return {ok:true,json:async()=>({...result})};
    }});
    expect(report.matched).toBe(1);expect(report).not.toHaveProperty('changedRows');
    expect(calls[0].scope.namespaceId).toBe(namespace);
    expect(JSON.parse(calls[0].options.body)).toEqual({lease_generation:1});
  });
  it('refuses a disabled response as replay evidence',async()=>{
    await expect(replayCanaryReceipts(env,{fetchForScope:()=>async()=>({ok:true,json:async()=>({status:'disabled'})})})).rejects.toThrow('CanaryReplayResultChanged');
  });
  it('rejects duplicate or oversized action inputs before making calls',async()=>{
    await expect(replayCanaryReceipts({...env,MEM9_CANARY_ACTIONS:JSON.stringify([{id,namespace,result},{id,namespace,result}])})).rejects.toThrow('InvalidCanaryReplayActions');
    await expect(replayCanaryReceipts({...env,MEM9_CANARY_ACTIONS:'x'.repeat(6501)})).rejects.toThrow('InvalidCanaryReplayActions');
  });
});
