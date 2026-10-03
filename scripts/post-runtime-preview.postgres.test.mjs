import {randomUUID,randomBytes,createHash} from 'node:crypto';
import {Socket} from 'node:net';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import pg from 'pg';
import {describe,it,expect} from 'vitest';
import {previewConfiguration} from './lib/consolidation-preview-config.mjs';
import {previewFixture} from './consolidation-preview-fixture.mjs';
import {bootstrapRuntime,approveExistingSyntheticTenant} from './runtime-bootstrap.mjs';
import {runtimeRoleName,runtimeSchemaDigest,applyBootstrapSchema} from './lib/runtime-credentials.mjs';
import {schemaAdministratorRole} from './lib/production-runtime-config.mjs';
import {prepareSchemaAdministrator} from './lib/production-runtime-credentials.mjs';
import {withRolloutLock,initializeRollout,commitRolloutPhase,recordRolloutOperation,readRolloutState} from './lib/production-runtime-state.mjs';
import {inspectApplicationOwnership,transferApplicationOwnership} from './lib/production-runtime-ownership.mjs';
import {ensureNamespaceIndexes} from './migrate-memory-namespaces.mjs';
import {readPostRuntimeAuthority,runtimeRowsFingerprint} from './lib/post-runtime-preview-authority.mjs';
import {createPlannerDatabase,runConsolidationPlanner} from './consolidation-planner.mjs';
import {runConsolidationExecutor} from './consolidation-executor.mjs';

const DSN=process.env.MEM9_RUNTIME_TEST_DSN,scalar=async(db,sql,args=[])=>(await db.query(sql,args)).rows[0]?.result;
const schemaRoot=fileURLToPath(new URL('../docker/bootstrap/',import.meta.url)),hash=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
describe.skipIf(!DSN)('post-runtime fixture on isolated PostgreSQL',()=>{
  it('preserves an old proven fixture and real runtime readiness under a new administrator',async()=>{
    const url=new URL(DSN);if(url.hostname!=='127.0.0.1'||url.pathname!=='/runtime_credentials_test')throw Error('IsolatedPostRuntimeFixtureRequired');
    const suffix=randomUUID().replaceAll('-',''),stage='pr-'+String(Math.floor(Math.random()*1000000)+1000000),database='post_'+suffix;
    const host=`mem9-on-aws-${stage}-local.cluster-example.ap-northeast-1.${['rds','amazonaws','com'].join('.')}`,secret=()=>({password:randomBytes(24).toString('hex'),salt:randomBytes(16).toString('hex')});
    const legacy={username:'old_'+suffix,...secret()},administrator={username:schemaAdministratorRole(stage),...secret()},runtime={username:runtimeRoleName(stage),...secret()};
    const connect=async(dbName,credential={username:url.username})=>{
      // Test-only DNS transport: preserve the requested RDS-shaped hostname,
      // while all traffic stays on the disposable loopback PostgreSQL server.
      const socket=new Socket(),open=socket.connect.bind(socket);
      socket.connect=(port,address)=>{if(address!==host)throw Error('ForeignFixtureHost');return open(port,'127.0.0.1');};
      const client=new pg.Client({host,port:Number(url.port),database:dbName,user:credential.username,password:credential.password,stream:socket,statement_timeout:30000});
      client.on('error',()=>{});try{await client.connect();return client;}catch(e){await client.end().catch(()=>{});throw e;}
    };
    const root=await connect('postgres'),allNames=new Set([legacy.username,administrator.username,runtime.username]),databases=[database];
    let control,admin,oldDb,template,createdRdsRole=false,createdTemplateVector=false;
    const old=previewConfiguration(stage,'a'.repeat(64),'old-fixture-key'),creds=c=>Object.fromEntries(Object.entries(c.usernames).map(([kind,username])=>[kind,{username,...secret()}]));
    const oldCredentials=creds(old);Object.values(old.usernames).forEach(n=>allNames.add(n));databases.push(old.database);
    try{
      template=await connect('template1');createdTemplateVector=!await scalar(template,"SELECT EXISTS(SELECT FROM pg_extension WHERE extname='vector') AS result");
      if(createdTemplateVector)await template.query('CREATE EXTENSION vector');await template.end();template=undefined;
      await root.query('CREATE ROLE rds_superuser NOLOGIN');createdRdsRole=true;await root.query('GRANT SET ON PARAMETER log_error_verbosity,log_min_error_statement TO rds_superuser');
      await root.query(`CREATE ROLE "${legacy.username}" LOGIN CREATEDB CREATEROLE PASSWORD '${legacy.password}'`);
      await root.query(`GRANT rds_superuser TO "${legacy.username}" WITH ADMIN OPTION`);
      for(const kind of ['planner','executor','backend','operator']){
        const role='mem9_maintenance_'+kind;
        if(!await scalar(root,'SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1) AS result',[role]))await root.query('CREATE ROLE '+role+' NOLOGIN');
        await root.query(`GRANT ${role} TO "${legacy.username}" WITH ADMIN OPTION`);
      }
      await root.query(`CREATE DATABASE "${database}" OWNER "${legacy.username}"`);
      control=await connect(database,legacy);await applyBootstrapSchema(control,schemaRoot+'schema.sql');
      const oldOptions={connect:(name,credential)=>connect(name,credential??legacy),controlDatabase:database,config:old,credentials:oldCredentials,schemaFile:schemaRoot+'schema.sql'};
      await previewFixture({...oldOptions,operation:'setup'});
      const planner=await connect(old.database,oldCredentials.planner);
      try{for(const ns of old.namespaces)await runConsolidationPlanner(createPlannerDatabase(planner,ns),{runtimeMs:170000});}finally{await planner.end();}
      const executor=await connect(old.database,oldCredentials.executor),backend=await connect(old.database,oldCredentials.backend);
      try{
        for(const ns of old.namespaces)await runConsolidationExecutor({
          claim:remaining=>scalar(executor,'SELECT mem9_maintenance.claim_action($1,120,$2) AS result',[ns,remaining]),
          apply:async action=>{
            const prepared=await scalar(backend,'SELECT mem9_maintenance.prepare_action($1,$2,$3) AS result',[ns,action.action_id,action.lease_generation]);
            if(prepared.status==='embed')await backend.query('SELECT mem9_maintenance.finish_preparation($1,$2,$3,$4,$5,$6::vector)',[ns,action.action_id,action.lease_generation,prepared.owner_token,prepared.content_hash,JSON.stringify([0,0,1,...Array(1021).fill(0)])]);
            return scalar(backend,'SELECT mem9_maintenance.apply_action($1,$2,$3) AS result',[ns,action.action_id,action.lease_generation]);
          },status:id=>scalar(backend,'SELECT mem9_maintenance.action_status($1,$2) AS result',[ns,id]),
        });
      }finally{await executor.end();await backend.end();}
      expect((await previewFixture({...oldOptions,operation:'verify-executed',batchBoundaryCrossings:1})).changedRows).toBe(150);
      await previewFixture({...oldOptions,operation:'pause'});
      oldDb=await connect(old.database);
      const oldFingerprint=async()=>hash({memories:(await oldDb.query("SELECT encode(sha256(convert_to(to_jsonb(m)::text,'UTF8')),'hex') AS digest FROM memories m ORDER BY id")).rows,
        proof:(await oldDb.query('SELECT * FROM mem9_preview.runs ORDER BY generation')).rows});
      const oldBefore=await oldFingerprint();
      const ns=randomUUID(),actor=randomUUID(),runtimeConfig={stage,database,host,port:Number(url.port),tenant:'f'.repeat(32),credentials:runtime};
      const prepareNamespaces=async db=>{
        await db.query("INSERT INTO memory_namespaces(namespace_id,slug,display_name) VALUES($1,$1,'synthetic') ON CONFLICT DO NOTHING",[ns]);
        await db.query("INSERT INTO memory_principals(principal_id,principal_key,principal_type) VALUES($1,$2,'service') ON CONFLICT DO NOTHING",[actor,hash(stage)]);
        await db.query("UPDATE memory_namespace_migration_state SET phase='application_ready',legacy_namespace_id=$1,legacy_namespace_slug=$1,legacy_namespace_display_name='synthetic',legacy_principal_id=$2,legacy_principal_key=$3 WHERE singleton_id",[ns,actor,hash(stage)]);
        await ensureNamespaceIndexes(db);await db.query(await readFile(schemaRoot+'migrations/003_enforce_memory_namespaces.sql','utf8'));
      };
      await bootstrapRuntime({db:control,config:runtimeConfig,schemaRoot,prepareNamespaces,connectRuntime:()=>connect(database,runtime),
        approveExistingTenants:db=>approveExistingSyntheticTenant(db,runtimeConfig,{MEM9_CONSOLIDATION_PREVIEW_CONFIG:JSON.stringify(old),MEM9_PREVIEW_BACKEND_CREDENTIAL:JSON.stringify(oldCredentials.backend)})});
      await prepareSchemaAdministrator(control,{stage,database,credential:administrator});
      for(const name of ['mem9_maintenance_planner','mem9_maintenance_executor','mem9_maintenance_backend','mem9_maintenance_operator',runtime.username])
        await control.query(`GRANT "${name}" TO "${administrator.username}" WITH ADMIN TRUE, INHERIT TRUE, SET TRUE`);
      const digest=await runtimeSchemaDigest(schemaRoot),nonce=randomUUID().replaceAll('-','');
      const identity={stage,database,databaseOid:Number(await scalar(control,'SELECT oid AS result FROM pg_database WHERE datname=current_database()')),
        legacyRoleOid:Number(await scalar(control,'SELECT session_user::regrole::oid AS result')),administratorRoleOid:Number(await scalar(control,'SELECT $1::regrole::oid AS result',[administrator.username])),
        runtimeRoleOid:Number(await scalar(control,'SELECT $1::regrole::oid AS result',[runtime.username])),writerEndpoint:host,
        clusterArn:`arn:aws:ecs:ap-northeast-1:123456789012:cluster/mem9-on-aws-${stage}-Fixture`,
        fallbackTaskDefinition:`arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-on-aws-${stage}-Fixture-Mem9RuntimeServer:1`,
        fallbackImageDigest:'sha256:'+'c'.repeat(64),runtimeCredentialArn:`arn:aws:ssm:ap-northeast-1:123456789012:parameter/mem9-on-aws/${stage}/runtime/database-credential`,schemaDigest:digest,operatorDigest:'d'.repeat(64)};
      const claim={nonce,epoch:1};
      await withRolloutLock(control,stage,async owns=>{
        await initializeRollout(control,{nonce,identity,owns});
        for(const [from,to]of [['prepared','maintenance'],['maintenance','runtime_prepared'],['runtime_prepared','password_fenced']])await commitRolloutPhase(control,{claim,from,to,owns});
        const inventory=await inspectApplicationOwnership(control,{legacyRoleOid:identity.legacyRoleOid});
        await commitRolloutPhase(control,{claim,from:'password_fenced',to:'transferred',owns,work:(_state,checkpoint)=>transferApplicationOwnership(control,{inventory,administrator:administrator.username,checkpoint})});
      });
      await control.end();control=undefined;
      // The native PG test creator has an automatic ADMIN grant as well as its
      // own dependent grant. Only the disposable test observer removes both.
      await root.query(`REVOKE "${administrator.username}" FROM "${legacy.username}" CASCADE`);
      // Native PostgreSQL cannot emulate Aurora master retirement authority.
      // The test observer establishes its disabled-old-login precondition;
      // genuine Aurora retirement remains a separate mandatory live gate.
      await root.query(`ALTER ROLE "${legacy.username}" NOLOGIN NOCREATEDB NOCREATEROLE`);
      await expect(connect(database,legacy)).rejects.toMatchObject({code:'28000'});
      admin=await connect(database,administrator);
      await withRolloutLock(admin,stage,async owns=>{
        await recordRolloutOperation(admin,{claim,owns,reason:'verify_administrator',verification_hash:'e'.repeat(64)});
        await commitRolloutPhase(admin,{claim,from:'transferred',to:'runtime_ready',owns});
        await commitRolloutPhase(admin,{claim,from:'runtime_ready',to:'retired',owns,evidence:{reason:'credential_fence',verification_hash:'e'.repeat(64)}});
        await commitRolloutPhase(admin,{claim,from:'retired',to:'complete',owns});
      });
      const completed=await readRolloutState(admin),context={kind:'post-runtime',runtimeNonce:nonce},fresh=previewConfiguration(stage,'b'.repeat(64),'fresh-fixture-key',context),credentials=creds(fresh);
      databases.push(fresh.database);Object.values(fresh.usernames).forEach(name=>allNames.add(name));
      const options={connect:(name,credential)=>connect(name,credential??administrator),controlDatabase:database,config:fresh,credentials,schemaFile:schemaRoot+'schema.sql'};
      const before=await runtimeRowsFingerprint(admin,fresh.tenantId);
      const runtimeProbe=async()=>{const c=await connect(database,runtime);try{return await scalar(c,'SELECT mem9_runtime.ready_for($1,$2) AS result',[stage,digest]);}finally{await c.end();}};
      expect(await scalar(admin,'SELECT mem9_runtime.ready_for($1,$2) AS result',[stage,digest])).toBe(false);
      expect(await runtimeProbe()).toBe(true);
      expect((await readPostRuntimeAuthority(admin,{...fresh,controlDatabase:database})).administratorOid).toBe(identity.administratorRoleOid);
      const created=await previewFixture({...options,operation:'setup'});expect(created.outcome).toBe('seeded');
      expect(created.authority.ownerOid).toBe(identity.administratorRoleOid);
      expect(await runtimeRowsFingerprint(admin,fresh.tenantId)).toBe(before);expect(await oldFingerprint()).toBe(oldBefore);
      expect((await readRolloutState(admin)).last_hash).toBe(completed.last_hash);expect(await runtimeProbe()).toBe(true);
      await previewFixture({...options,operation:'pause'});
      await admin.query("UPDATE mem9_runtime.readiness SET schema_digest=$1 WHERE singleton",['0'.repeat(64)]);
      await expect(readPostRuntimeAuthority(admin,{...fresh,controlDatabase:database})).rejects.toThrow('PreviewRuntimeNotReady');expect(await runtimeProbe()).toBe(false);
      await admin.query('UPDATE mem9_runtime.readiness SET schema_digest=$1 WHERE singleton',[digest]);expect(await runtimeProbe()).toBe(true);
      await expect(readPostRuntimeAuthority(admin,{...fresh,context:{...context,runtimeNonce:'0'.repeat(32)},controlDatabase:database})).rejects.toThrow('PreviewRuntimeAuthorityMismatch');
    }finally{
      await template?.end();await oldDb?.end();await admin?.end();await control?.end();
      for(const name of [...new Set(databases)].reverse())await root.query('DROP DATABASE IF EXISTS "'+name+'" WITH (FORCE)').catch(()=>{});
      const memberships=(await root.query(`SELECT granted.rolname AS granted,member.rolname AS member,grantor.rolname AS grantor
        FROM pg_auth_members m JOIN pg_roles granted ON granted.oid=m.roleid JOIN pg_roles member ON member.oid=m.member JOIN pg_roles grantor ON grantor.oid=m.grantor
        WHERE granted.rolname=ANY($1) OR member.rolname=ANY($1) OR grantor.rolname=ANY($1)`,[[...allNames]])).rows;
      const quote=s=>'"'+s.replaceAll('"','""')+'"';
      for(const row of memberships)await root.query(`REVOKE ${quote(row.granted)} FROM ${quote(row.member)} GRANTED BY ${quote(row.grantor)} CASCADE`).catch(()=>{});
      for(const name of [...allNames].reverse())await root.query('DROP ROLE IF EXISTS "'+name+'"').catch(()=>{});
      if(createdRdsRole){
        await root.query('REVOKE SET ON PARAMETER log_error_verbosity,log_min_error_statement FROM rds_superuser');
        await root.query('DROP ROLE rds_superuser');
      }
      if(createdTemplateVector){const templateCleanup=await connect('template1');try{await templateCleanup.query('DROP EXTENSION vector');}finally{await templateCleanup.end();}}
      await root.end();
    }
  },120000);
});
