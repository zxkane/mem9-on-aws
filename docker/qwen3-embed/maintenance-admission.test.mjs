import {createServer} from 'node:http';
import {once} from 'node:events';
import {describe,it,expect} from 'vitest';
import {createMaintenanceAdmission} from './maintenance-admission.mjs';

describe('maintenance embedding admission',()=>{
  it('holds one permit until actual work completes, including client disconnect',async()=>{
    const admission=createMaintenanceAdmission();
    let finish,started;
    const live=new Promise(resolve=>{finish=resolve;});
    const began=new Promise(resolve=>{started=resolve;});
    const server=createServer(async(_req,res)=>{
      const result=await admission.run(async()=>{started();await live;return 'ok';});
      res.writeHead(result.accepted?200:429);res.end();
    });
    server.listen(0,'127.0.0.1');await once(server,'listening');
    try{
      const endpoint='http://127.0.0.1:'+server.address().port;
      const abort=new AbortController();
      const request=fetch(endpoint,{signal:abort.signal}).catch(()=>{});
      await began;abort.abort();await request;
      expect((await fetch(endpoint)).status).toBe(429);
      finish();
      await new Promise(resolve=>setImmediate(resolve));
      expect((await fetch(endpoint)).status).toBe(200);
    }finally{finish();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
  });
  it('releases the permit after inference failure',async()=>{
    const admission=createMaintenanceAdmission();
    await expect(admission.run(async()=>{throw Error('fixture');})).rejects.toThrow('fixture');
    expect(await admission.run(async()=>42)).toEqual({accepted:true,value:42});
  });
});
