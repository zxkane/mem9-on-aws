import {it,describe,expect} from 'vitest';
import {mkdtemp,rm,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {X509Certificate} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {rootCertificates} from 'node:tls';
import pg from 'pg';
import {openCarrierSqlFixture,inspectCarrierSqlFixture,closeCarrierSqlFixture} from './lib/ci-carrier-sql-fixture.mjs';
import {seedCarrierSqlState} from './lib/ci-carrier-sql-state.mjs';
import {verifyCarrierSqlTlsRejection} from './lib/ci-carrier-sql-acceptance-format.mjs';

it('rejects a serialized fixture without adopting sockets or containers',()=>{
 expect(()=>inspectCarrierSqlFixture({kind:'carrier-sql-fixture'})).toThrow('CarrierSqlFixtureHandle');
});
describe.skipIf(process.env.MEM9_CARRIER_SQL_TEST!=='1')('fixed cached DB fixture and original seeder composition',()=>{
 it('correlates a real certificate refusal to one PG TLS session, not a startup failure',async()=>{
  const tempRoot=await mkdtemp(join(tmpdir(),'carrier-sql-tls-test-'));let handle,client;
  try{
   handle=await openCarrierSqlFixture({tempRoot,deadlineMs:Date.now()+120000,metadataReads:{reserveLocal(){}}});const f=inspectCarrierSqlFixture(handle);
   // Docker logs sends the server's stderr to this command's stderr. Capture
   // both streams without changing the server or its TLS configuration.
   const capture=()=>{
    const result=spawnSync('/usr/bin/docker',['--host','unix:///var/run/docker.sock','--config',tempRoot,'container','logs',f.record.containerId],{encoding:'utf8',timeout:10000,maxBuffer:1048576,stdio:['ignore','pipe','pipe'],env:{PATH:'/usr/bin:/bin',HOME:tempRoot}});expect(result.status).toBe(0);return result.stderr;
   };
   const before=capture();client=new pg.Client({host:'127.0.0.1',port:f.root.connectionParameters.port,user:'postgres',database:'runtime_credentials_test',ssl:{ca:rootCertificates[0],rejectUnauthorized:true,servername:f.hostAlias},connectionTimeoutMillis:5000});client.on('error',()=>{});
   const failure=await client.connect().then(()=>null,error=>error);expect(failure?.code).toBe('DEPTH_ZERO_SELF_SIGNED_CERT');await client.end();client=undefined;
   // The client has closed; allow the independent server/Docker log pipe to
   // finish its terminal record. This is not an additional connection/probe.
   await new Promise(resolve=>setTimeout(resolve,1000));
   const after=capture();expect(after.startsWith(before)).toBe(true);
   const proof=verifyCarrierSqlTlsRejection(after.slice(before.length),undefined,{event:'carrier_guard_rejected',stage:'legacy',code:'CarrierRejected',tlsErrorCode:failure.code});expect(proof.kind).toBe('fixture-certificate-rejection');
   expect(()=>verifyCarrierSqlTlsRejection(after.slice(before.length))).toThrow('CarrierSqlTlsCertificateRejection');
   expect((await f.root.query('SELECT 1 AS alive')).rows[0].alive).toBe(1);
  }finally{await client?.end();if(handle)await closeCarrierSqlFixture(handle);await rm(tempRoot,{recursive:true,force:true});}
 },120000);
 it('uses real loopback TLS clients, the authenticated peer and observed cleanup',async()=>{
  const tempRoot=await mkdtemp(join(tmpdir(),'carrier-sql-fixture-test-')),charges=[];let handle,seed;
  try{
   handle=await openCarrierSqlFixture({tempRoot,deadlineMs:Date.now()+180000,metadataReads:{reserveLocal(c){expect(c.ecrRequests).toBe(0);expect(c.httpBodyBytes).toBe(0);charges.push(c);}}});
   const fixture=inspectCarrierSqlFixture(handle),cert=new X509Certificate(fixture.fixtureCa);
   expect(cert.checkHost('localhost')).toBe('localhost');expect(cert.checkIP('127.0.0.1')).toBe('127.0.0.1');
   expect(fixture.root.connectionParameters.host).toBe('127.0.0.1');expect(fixture.root.connection.stream.authorized).toBe(true);
   await expect(fixture.connect({username:'postgres'},'unrelated')).rejects.toThrow('CarrierSqlConnectionInput');
   seed=await seedCarrierSqlState({...fixture,schemaRoot:fileURLToPath(new URL('../docker/bootstrap/',import.meta.url))});
   expect(seed.parent.verification).toMatchObject({changedRows:10,receipts:5});expect(seed.authority).toBe(false);
   expect(charges.length).toBeGreaterThan(10);expect(inspectCarrierSqlFixture(handle).record.relayBytes).toBeGreaterThan(0);
   await seed.close();seed=undefined;await closeCarrierSqlFixture(handle);handle=undefined;
   expect(await readdir(tempRoot)).toEqual([]);
  }finally{await seed?.close();if(handle)await closeCarrierSqlFixture(handle);await rm(tempRoot,{recursive:true,force:true});}
 },180000);
});
