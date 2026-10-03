import {describe,it,expect,vi} from 'vitest';
import {createHash} from 'node:crypto';
import {previewConfiguration} from './lib/consolidation-preview-config.mjs';
import {previewFixture,retireSeed} from './consolidation-preview-fixture.mjs';
import {assertPostRuntimeSession,assertPostRuntimeDatabase,postRuntimeDatabaseMarker,readPostRuntimeAuthority,runtimeRowsFingerprint} from './lib/post-runtime-preview-authority.mjs';
const readState=vi.hoisted(()=>vi.fn());
vi.mock('./lib/production-runtime-state.mjs',()=>({readRolloutState:readState}));
const context={kind:'post-runtime',runtimeNonce:'b'.repeat(32)},generation='c'.repeat(64);
const config=previewConfiguration('pr-7',generation,'synthetic-secret',context);
const request={...config,controlDatabase:'application'};
const state=()=>({operation_nonce:context.runtimeNonce,phase:'complete',status:'running',last_hash:'d'.repeat(64),
  proofs:{retired_credentials:true,administrator:true},identity:{stage:'pr-7',database:'application',writerEndpoint:'writer.example.com',schemaDigest:'a'.repeat(64),databaseOid:31,administratorRoleOid:41,runtimeRoleOid:51}});
const session=()=>({database:'application',database_oid:31,database_owner_oid:41,session_oid:41,direct:true,rolcanlogin:true,rolcreatedb:true,rolcreaterole:true,
  rolsuper:false,rolreplication:false,rolbypassrls:false,rds_admin:true});
describe('post-runtime preview administrator and ownership',()=>{
  it('binds the actual session administrator to the completed ledger',()=>{
    const result=assertPostRuntimeSession(state(),session(),request);
    expect(result).toMatchObject({administratorOid:41,applicationDatabaseOid:31,runtimeRoleOid:51,runtimeStateHash:'d'.repeat(64)});
    expect(JSON.stringify(result)).not.toContain(context.runtimeNonce);
  });
  it.each([
    s=>{s.operation_nonce='e'.repeat(32);},s=>{s.phase='retired';},s=>{s.status='restored';},
    s=>{s.proofs.administrator=false;},s=>{s.identity.database='foreign';},s=>{s.identity.stage='prod';},
  ])('rejects stale, intermediate and foreign ledger state before a database write',mutate=>{
    const s=state();mutate(s);expect(()=>assertPostRuntimeSession(s,session(),request)).toThrow('PreviewRuntimeAuthorityMismatch');
  });
  it.each([
    s=>{s.session_oid=42;},s=>{s.direct=false;},s=>{s.database_oid=32;},s=>{s.database_owner_oid=42;},s=>{s.rolsuper=true;},
    s=>{s.rolbypassrls=true;},s=>{s.rolcreaterole=false;},s=>{s.rds_admin=false;},
  ])('rejects a recreated, impersonated or overprivileged administrator',mutate=>{
    const s=session();mutate(s);expect(()=>assertPostRuntimeSession(state(),s,request)).toThrow('PreviewRuntimeAuthorityMismatch');
  });
  it('requires actual database ownership and a full context marker, not the old stage marker',()=>{
    const authority=assertPostRuntimeSession(state(),session(),request),row={database_oid:61,owner_oid:41,marker:postRuntimeDatabaseMarker(config)};
    expect(assertPostRuntimeDatabase(row,authority,config)).toMatchObject({databaseOid:61,ownerOid:41});
    for(const changed of [{...row,owner_oid:42},{...row,marker:'mem9-consolidation-synthetic-v1/pr-7'},
      {...row,marker:postRuntimeDatabaseMarker({...config,generation:'e'.repeat(64)})}])
      expect(()=>assertPostRuntimeDatabase(changed,authority,config)).toThrow('PreviewDatabaseOwnershipMismatch');
  });
  it('uses the sealed state reader and performs only read-only authority/readiness queries',async()=>{
    readState.mockResolvedValue(state());const calls=[];
    const db={connectionParameters:{host:'writer.example.com'},query:async(sql,args)=>{calls.push({sql,args});return {rows:sql.startsWith('SELECT current_database()')?[session()]:[{ready:true}]};}};
    expect(await readPostRuntimeAuthority(db,request)).toMatchObject({administratorOid:41});
    expect(readState).toHaveBeenCalledWith(db);
    expect(calls.every(c=>/^SELECT\b/.test(c.sql))).toBe(true);
    expect(calls.at(-1).args).toEqual(['pr-7',51,'a'.repeat(64)]);
    expect(calls.at(-1).sql).not.toContain('ready_for(');
    readState.mockResolvedValue({...state(),operation_nonce:'e'.repeat(32)});calls.length=0;
    await expect(readPostRuntimeAuthority(db,request)).rejects.toThrow('PreviewRuntimeAuthorityMismatch');expect(calls).toEqual([]);
    readState.mockResolvedValue(state());db.connectionParameters.host='foreign.example.com';
    await expect(readPostRuntimeAuthority(db,request)).rejects.toThrow('PreviewRuntimeAuthorityMismatch');expect(calls).toEqual([]);
  });
  it('fingerprints existing tenant/binding rows without returning their values',async()=>{
    const calls=[],digest='f'.repeat(64);
    const db={query:async(sql,args)=>{calls.push({sql,args});return {rows:[{digest}]};}};
    const value=await runtimeRowsFingerprint(db,config.tenantId);
    expect(value).toMatch(/^[a-f0-9]{64}$/);expect(value).not.toContain(config.tenantId);
    expect(calls).toHaveLength(2);expect(calls.every(c=>c.args[0]===config.tenantId&&c.sql.includes('LIMIT 501'))).toBe(true);
    await expect(runtimeRowsFingerprint({query:async()=>({rows:Array(501).fill({digest})})},config.tenantId)).rejects.toThrow('PreviewRuntimeRowsInvalid');
  });
  it('rejects the actual fixture entrypoint before locking or DDL under a different administrator',async()=>{
    readState.mockResolvedValue(state());const calls=[];
    const db={connectionParameters:{host:'writer.example.com'},query:async sql=>{calls.push(sql);return {rows:[{...session(),session_oid:42}]};},end:vi.fn(async()=>{})};
    const connect=vi.fn(async()=>db),credentials=Object.fromEntries(Object.entries(config.usernames).map(([kind,username])=>[kind,{username}]));
    await expect(previewFixture({connect,controlDatabase:'application',config,credentials,operation:'setup',schemaFile:'unused'})).rejects.toThrow('PreviewRuntimeAuthorityMismatch');
    expect(connect).toHaveBeenCalledTimes(1);expect(calls.every(sql=>/^SELECT\b/.test(sql))).toBe(true);
    expect(calls.some(sql=>sql.includes('advisory'))).toBe(false);expect(db.end).toHaveBeenCalledOnce();
  });
  it('bounds a busy fixture lock before creating or adopting any database',async()=>{
    readState.mockResolvedValue(state());const calls=[];
    const db={connectionParameters:{host:'writer.example.com'},query:async sql=>{calls.push(sql);return {rows:sql.startsWith('SELECT current_database()')?[session()]:sql.includes('FROM mem9_runtime.readiness')?[{ready:true}]:[{result:false}]};},end:async()=>{}};
    const credentials=Object.fromEntries(Object.entries(config.usernames).map(([kind,username])=>[kind,{username}]));
    await expect(previewFixture({connect:async()=>db,controlDatabase:'application',config,credentials,operation:'setup',schemaFile:'unused'})).rejects.toThrow('PreviewSetupBusy');
    expect(calls.some(sql=>/CREATE|ALTER|INSERT|UPDATE|DELETE/.test(sql))).toBe(false);
  });
  it('keeps the verified connection open through final evidence on an absent fixture',async()=>{
    readState.mockResolvedValue(state());let closed=false;
    const settings={log_statement:'none',log_min_duration_statement:'-1',log_min_duration_sample:'-1',log_transaction_sample_rate:'0',log_parameter_max_length_on_error:'0'};
    const db={connectionParameters:{host:'writer.example.com'},query:async sql=>{
      if(closed)throw Error('ConnectionClosedBeforeEvidence');
      if(sql.startsWith('SELECT current_database()'))return {rows:[session()]};
      if(sql.includes('FROM mem9_runtime.readiness'))return {rows:[{ready:true}]};
      if(sql.includes('pg_try_advisory_lock'))return {rows:[{result:true}]};
      if(sql.includes('pg_settings'))return {rows:Object.entries(settings).map(([name,setting])=>({name,setting}))};
      if(sql.includes('AS digest'))return {rows:[{digest:'f'.repeat(64)}]};
      return {rows:[]};
    },end:async()=>{closed=true;}};
    const credentials=Object.fromEntries(Object.entries(config.usernames).map(([kind,username])=>[kind,{username}]));
    const result=await previewFixture({connect:async()=>db,controlDatabase:'application',config,credentials,operation:'pause',schemaFile:'unused'});
    expect(result.outcome).toBe('absent');expect(result.authority.administratorOid).toBe(41);expect(closed).toBe(true);
  });
  it('does not retire an existing seed role without this fixture\'s ownership receipt',async()=>{
    const writes=[];
    const control={query:async(sql)=>{
      if(sql.startsWith('ALTER')||sql.includes('pg_terminate_backend'))writes.push(sql);
      return {rows:[{result:sql.includes('FROM pg_roles')}]};
    }};
    const db={query:async sql=>{
      if(sql.startsWith('REVOKE'))writes.push(sql);
      return {rows:sql.includes('to_regclass')?[{result:true}]:[]};
    }};
    await expect(retireSeed(control,db,config)).rejects.toThrow('PreviewCredentialOwnershipMismatch');
    expect(writes).toEqual([]);
  });
  it('retires only the recorded role OID and context marker',async()=>{
    const marker=postRuntimeDatabaseMarker(config)+'/seed';
    const original={role_name:config.usernames.seed,role_oid:61,marker_hash:createHash('sha256').update(marker).digest('hex')};
    for(const bad of [false,'oid','marker','privilege']){
      const writes=[],owned={...original},role={oid:61,rolname:config.usernames.seed,marker,rolsuper:false,rolcreatedb:false,rolcreaterole:false,rolreplication:false,rolbypassrls:false};
      if(bad==='oid')role.oid=62;if(bad==='marker')role.marker='unrelated';if(bad==='privilege')role.rolcreatedb=true;
      const control={query:async sql=>{
        if(sql.startsWith('ALTER')||sql.includes('pg_terminate_backend'))writes.push(sql);
        if(sql.includes('SELECT oid,rolname'))return {rows:[role]};
        return {rows:[{result:sql.includes('FROM pg_roles')}]};
      }};
      const db={query:async sql=>{
        if(sql.startsWith('REVOKE'))writes.push(sql);
        return {rows:sql.includes('SELECT role_name')?[owned]:[{result:true}]};
      }};
      if(bad){await expect(retireSeed(control,db,config)).rejects.toThrow('PreviewCredentialOwnershipMismatch');expect(writes).toEqual([]);}
      else{await retireSeed(control,db,config);expect(writes.some(sql=>sql.startsWith('ALTER ROLE'))).toBe(true);}
    }
  });
});
