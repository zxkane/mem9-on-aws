import {randomBytes} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createServer,connect as connectTcp} from 'node:net';
import {setTimeout as delay} from 'node:timers/promises';
import pg from 'pg';
import {describe,it,expect} from 'vitest';
import {seedCarrierSqlState} from './lib/ci-carrier-sql-state.mjs';
import {auditPausedCanary} from './lib/production-canary-paused-audit.mjs';

const docker=args=>execFileSync('docker',args,{encoding:'utf8',timeout:30000,stdio:['ignore','pipe','pipe']}).trim();

// This test needs an already-present ARM64 image. It never pulls an image,
// reads production configuration, or connects outside its owned fixture.
async function withFixture(work){
  const nonce=randomBytes(16).toString('hex'),name='mem9-carrier-sql-'+nonce;
  const hostAlias='mem9-on-aws-prod-fixture.cluster-'+nonce+'.ap-northeast-1.rds.amazonaws.com';
  const image=process.env.MEM9_CARRIER_SQL_TEST_IMAGE??'pgvector/pgvector:pg17';
  expect(docker(['image','inspect',image,'--format','{{.Architecture}}'])).toBe('arm64');
  let network,container,root,relay;
  const sockets=new Set();
  const clients=new Set();
  try{
   network=docker(['network','create','--internal',name]);
   container=docker(['run','-d','--pull=never','--name',name,'--network',network,
    '--user','999:999','--read-only','--cap-drop=ALL','--security-opt','no-new-privileges:true',
    '--pids-limit','128','--memory','512m',
    '--tmpfs','/tmp:rw,nosuid,nodev,size=384m,uid=999,gid=999,mode=700',
    '--tmpfs','/var/run/postgresql:rw,nosuid,nodev,size=1m,uid=999,gid=999,mode=700',
    '-e','FIXTURE_NONCE='+nonce,'-e','FIXTURE_HOST='+hostAlias,
    '--entrypoint','/bin/sh',image,'-ec',[
     'umask 077',
     'openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=mem9-carrier-db-$FIXTURE_NONCE" -addext "subjectAltName=DNS:$FIXTURE_HOST,IP:127.0.0.1" -keyout /tmp/server.key -out /tmp/server.crt >/tmp/cert.log 2>&1',
     'initdb -D /tmp/pgdata -U postgres --auth-local=trust --auth-host=scram-sha-256 >/tmp/initdb.log',
     'printf "local all all trust\\nhostssl all postgres 0.0.0.0/0 trust\\nhostssl all all 0.0.0.0/0 scram-sha-256\\nhostnossl all all 0.0.0.0/0 reject\\n" > /tmp/pgdata/pg_hba.conf',
     'exec postgres -D /tmp/pgdata -c listen_addresses=* -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key -c log_statement=none -c log_min_error_statement=panic -c log_parameter_max_length=0 -c log_parameter_max_length_on_error=0',
    ].join('\n')]);
   let ready=false;
   for(let i=0;i<80;i++){
    try{docker(['exec',container,'pg_isready','-h','127.0.0.1','-U','postgres']);ready=true;break;}catch{
     if(docker(['inspect',container,'--format','{{.State.Running}}'])!=='true')throw Error('CarrierSqlFixtureContainerExited');
     await delay(250);
    }
   }
   expect(ready).toBe(true);
   const fixtureCa=docker(['exec',container,'cat','/tmp/server.crt']);
   // Internal Docker networks intentionally do not publish ports. This owned
   // loopback relay reaches only the inspected fixture IP and keeps egress off.
   const address=Object.values(JSON.parse(docker(['inspect',container,'--format','{{json .NetworkSettings.Networks}}'])))[0].IPAddress;
   expect(address).toMatch(/^\d+\.\d+\.\d+\.\d+$/);
   relay=createServer(socket=>{
    const peer=connectTcp({host:address,port:5432});
    for(const s of [socket,peer]){sockets.add(s);s.once('close',()=>sockets.delete(s));s.on('error',()=>{socket.destroy();peer.destroy();});}
    socket.pipe(peer).pipe(socket);
   });
   await new Promise((resolve,reject)=>{relay.once('error',reject);relay.listen(0,'127.0.0.1',resolve);});
   const connect=async(credential,database)=>{
    const client=new pg.Client({host:'127.0.0.1',port:relay.address().port,database,
     user:credential.username,password:credential.password,
     ssl:{ca:fixtureCa,rejectUnauthorized:true,servername:hostAlias},
     connectionTimeoutMillis:5000,statement_timeout:15000,query_timeout:20000});
    client.on('error',()=>{});clients.add(client);
    client.once('end',()=>clients.delete(client));
    try{await client.connect();return client;}catch(error){await client.end();throw error;}
   };
   const setup=await connect({username:'postgres'},'postgres');
   await setup.query('CREATE DATABASE runtime_credentials_test');await setup.end();
   root=await connect({username:'postgres'},'runtime_credentials_test');
   await work({root,connect,fixtureCa,hostAlias,clients,
    schemaRoot:fileURLToPath(new URL('../docker/bootstrap/',import.meta.url)),deadlineMs:Date.now()+90000});
  }finally{
    await Promise.allSettled([...clients].map(c=>c.end()));
    for(const socket of sockets)socket.destroy();
    if(relay)await new Promise(resolve=>relay.close(resolve));
    if(container)docker(['rm','-fv',container]);
    if(network)docker(['network','rm',network]);
  }
}

it.each([NaN,Infinity,0,1.5,Number.MAX_SAFE_INTEGER+1])('rejects invalid or expired fixture deadline %s before connecting',async deadlineMs=>{
 await expect(seedCarrierSqlState({deadlineMs})).rejects.toThrow('CarrierSqlFixtureExpired');
});

describe.skipIf(process.env.MEM9_CARRIER_SQL_TEST!=='1')('carrier SQL state on isolated TLS PostgreSQL',()=>{
 it('audits the real synthetic state and rejects drift without repairing it',()=>withFixture(async f=>{
   const seed=await seedCarrierSqlState(f);
   try{
   expect(seed.authority).toBe(false);
   expect(seed.parent.verification).toMatchObject({changedRows:10,receipts:5});
   const admin=await f.connect(seed.administrator,seed.rootConfig.database);
   const snapshot=async()=>JSON.stringify((await admin.query('SELECT canary_used,receipt_verification FROM mem9_maintenance.production_worker_setup WHERE singleton')).rows);
   const audit=async()=>{await admin.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');try{return await auditPausedCanary(admin,seed.rootConfig,seed.certificate);}finally{await admin.query('ROLLBACK');}};
   const before=await snapshot();
   expect((await audit()).rootIdentity).toBe(seed.rootIdentity);
   expect(await snapshot()).toBe(before);
   await seed.wrongCounter();
   const changed=await snapshot();expect(changed).not.toBe(before);
   await expect(audit()).rejects.toThrow();
   expect(await snapshot()).toBe(changed);
   await admin.end();
   await seed.close();await seed.close();
   expect(f.clients.size).toBe(1);
   }finally{await seed.close();}
 }),120000);

 it('rejects a later connection to a different database before writing there',()=>withFixture(async f=>{
  let rejected;
  await expect(seedCarrierSqlState({...f,connect:async credential=>{
   rejected=await f.connect(credential,'postgres');return rejected;
  }})).rejects.toThrow('CarrierSqlFixtureConnection');
  expect(rejected.connection.stream.destroyed).toBe(true);
  const other=await f.connect({username:'postgres'},'postgres');
  expect((await other.query("SELECT to_regclass('public.memories') AS value")).rows[0].value).toBe(null);
  await other.end();expect(f.clients.size).toBe(1);
 }),120000);

 it('closes active clients when the caller aborts an in-progress connection',()=>withFixture(async f=>{
  const controller=new AbortController();let client;
  await expect(seedCarrierSqlState({...f,signal:controller.signal,connect:async(...args)=>{
   client=await f.connect(...args);controller.abort();return client;
  }})).rejects.toThrow('CarrierSqlFixtureExpired');
  await delay(20);expect(client.connection.stream.destroyed).toBe(true);
  expect(f.root.connection.stream.destroyed).toBe(true);
 }),120000);

 it('retains cleanup failures while closing every registered client',()=>withFixture(async f=>{
  const seed=await seedCarrierSqlState(f);
  const owned=[...f.clients].filter(c=>c!==f.root);expect(owned.length).toBeGreaterThan(0);
  const failed=owned[0],end=failed.end.bind(failed);failed.end=async()=>{await end();throw Error('SyntheticCloseFailure');};
  const closing=seed.close();expect(seed.close()).toBe(closing);
  await expect(closing).rejects.toThrow('CarrierSqlFixtureCleanup');
  for(const client of owned)expect(client.connection.stream.destroyed).toBe(true);
  expect(f.clients.size).toBe(1);
 }),120000);

 it.each([false,true])('waits for a late connection and preserves close failure=%s',failedClose=>withFixture(async f=>{
  const controller=new AbortController();let client,ended=false;
  const operation=seedCarrierSqlState({...f,signal:controller.signal,connect:async(...args)=>{
   client=await f.connect(...args);
   const end=client.end.bind(client);client.end=async()=>{await end();ended=true;if(failedClose)throw Error('SyntheticLateCloseFailure');};
   controller.abort();await delay(50);return client;
  }});
  if(failedClose){
   await expect(operation).rejects.toMatchObject({message:'CarrierSqlFixtureCleanup',cleanupComplete:false});
  }else await expect(operation).rejects.toThrow('CarrierSqlFixtureExpired');
  expect(ended).toBe(true);expect(client.connection.stream.destroyed).toBe(true);
 }),120000);

 it('reports unknown cleanup when an aborted connection never settles',()=>withFixture(async f=>{
  const controller=new AbortController(),started=Date.now();
  await expect(seedCarrierSqlState({...f,signal:controller.signal,connect:()=>{
   controller.abort();return new Promise(()=>{});
  }})).rejects.toMatchObject({message:'CarrierSqlFixtureCleanup',cleanupComplete:false});
  expect(Date.now()-started).toBeLessThan(5000);
 }),120000);
});
