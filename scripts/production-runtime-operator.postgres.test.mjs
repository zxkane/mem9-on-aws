import {randomUUID,randomBytes,createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import pg from 'pg';
import {describe,it,expect} from 'vitest';
import {runProductionOperation} from './production-runtime-operator.mjs';
import {schemaAdministratorRole} from './lib/production-runtime-config.mjs';
import {runtimeRoleName,applyBootstrapSchema} from './lib/runtime-credentials.mjs';
import {ensureNamespaceIndexes} from './migrate-memory-namespaces.mjs';
import {seedTenant} from './seed-tenant.mjs';

const dsn=process.env.MEM9_RUNTIME_TEST_DSN;
const scalar=async(db,sql,args=[])=>(await db.query(sql,args)).rows[0]?.result;
describe.skipIf(!dsn)('production operator on real PostgreSQL',()=>{
  it('runs preparation, fencing, transfer and fresh-admin replay without assuming native PostgreSQL can retire the master',async()=>{
    const url=new URL(dsn);if(url.hostname!=='127.0.0.1'||url.pathname!=='/runtime_credentials_test')throw Error('IsolatedOperatorFixtureRequired');
    const suffix=randomUUID().replaceAll('-',''),database='operator_'+suffix,legacy='legacy_'+suffix,stage='pr-'+String(Math.floor(Math.random()*10000000)+1);
    const secret=()=>({password:randomBytes(24).toString('hex'),salt:randomBytes(16).toString('hex')});
    const original={username:legacy,...secret()},administrator={username:schemaAdministratorRole(stage),...secret()},runtimeCredential={username:runtimeRoleName(stage),...secret()};
    let injectLegacy=false,injected;
    const connect=async(credential,dbName=database)=>{
      const db=new pg.Client({host:url.hostname,port:Number(url.port),database:dbName,user:credential.username,password:credential.password});db.on('error',()=>{});
      try{
        await db.connect();const query=db.query.bind(db);
        db.query=async(...args)=>{
          const result=await query(...args);
          if(injectLegacy&&credential.username===legacy&&typeof args[0]==='string'&&args[0].includes('CREATE SCHEMA IF NOT EXISTS mem9_runtime')&&args[0].includes('grant_runtime')){
            injectLegacy=false;injected=await connect(original);
          }
          return result;
        };
        return db;
      }catch(error){await db.end().catch(()=>{});throw error;}
    };
    const root=await connect({username:url.username},'postgres');let setup;
    const namespace=randomUUID(),principal=randomUUID(),tenant='a'.repeat(32),host=`mem9-on-aws-${stage}-fixture.cluster-example.ap-northeast-1.${['rds','amazonaws','com'].join('.')}`;
    try{
      await root.query('CREATE ROLE rds_superuser NOLOGIN');
      await root.query('GRANT SET ON PARAMETER log_error_verbosity,log_min_error_statement TO rds_superuser');
      await root.query(`CREATE ROLE "${legacy}" LOGIN CREATEDB CREATEROLE PASSWORD '${original.password}'`);
      await root.query(`GRANT rds_superuser TO "${legacy}" WITH ADMIN OPTION`);
      for(const role of ['planner','executor','backend','operator']){
        const name='mem9_maintenance_'+role;
        if(!await scalar(root,'SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1) AS result',[name]))await root.query('CREATE ROLE '+name+' NOLOGIN');
        await root.query(`GRANT ${name} TO "${legacy}" WITH ADMIN OPTION`);
      }
      await root.query(`CREATE DATABASE "${database}" OWNER "${legacy}"`);
      const extensions=await connect({username:url.username});await extensions.query('CREATE EXTENSION vector');await extensions.end();
      setup=await connect(original);
      const schemaRoot=fileURLToPath(new URL('../docker/bootstrap/',import.meta.url));
      await applyBootstrapSchema(setup,schemaRoot+'schema.sql');
      await setup.query("INSERT INTO memory_namespaces(namespace_id,slug,display_name) VALUES($1,$1,'synthetic')",[namespace]);
      const key=createHash('sha256').update(stage).digest('hex');
      await setup.query("INSERT INTO memory_principals(principal_id,principal_key,principal_type) VALUES($1,$2,'service')",[principal,key]);
      await setup.query("UPDATE memory_namespace_migration_state SET phase='application_ready',legacy_namespace_id=$1,legacy_namespace_slug=$1,legacy_namespace_display_name='synthetic',legacy_principal_id=$2,legacy_principal_key=$3 WHERE singleton_id",[namespace,principal,key]);
      await ensureNamespaceIndexes(setup);await setup.query(await readFile(schemaRoot+'migrations/003_enforce_memory_namespaces.sql','utf8'));
      await seedTenant(setup,{tenant,host,port:5432,database,credentials:original});await setup.end();setup=undefined;
      const config={stage,database,original,administrator,transition:secret(),runtime:{stage,database,host,port:5432,tenant,credentials:runtimeCredential}};
      const nonce=randomUUID().replaceAll('-',''),operatorDigest='d'.repeat(64),target={
        clusterArn:`arn:aws:ecs:ap-northeast-1:123456789012:cluster/mem9-on-aws-${stage}-Fixture`,writerEndpoint:host,masterUsername:legacy,
        fallbackTaskDefinition:`arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-on-aws-${stage}-Fixture-Mem9RuntimeServer:2`,
        fallbackImageDigest:'sha256:'+'c'.repeat(64),runtimeCredentialArn:`arn:aws:ssm:ap-northeast-1:123456789012:parameter/mem9-on-aws/${stage}/runtime/database-credential`};
      let state;
      const invoke=async(operation,extra={})=>state=await runProductionOperation({config,connect,schemaRoot,operatorDigest,
        request:{operation,nonce,epoch:state?.epoch??1,deadline:Date.now()+300000,...extra}});
      expect(await invoke('inspect-preparation')).toBeNull();
      expect((await invoke('prepare',{target})).phase).toBe('prepared');
      expect((await invoke('inspect-preparation')).phase).toBe('prepared');
      await invoke('begin');await invoke('assert-quiescent');
      injectLegacy=true;
      await expect(invoke('runtime')).rejects.toThrow('LegacySessionsRemain');
      await injected.end();injected=undefined;
      expect((await invoke('status')).phase).toBe('maintenance');
      await invoke('recover');await invoke('repair');await invoke('restored');await invoke('resume');
      expect((await invoke('runtime')).phase).toBe('runtime_prepared');
      await invoke('fence');await invoke('verify-fence');await invoke('drain-legacy');
      expect((await invoke('transfer')).phase).toBe('transferred');
      await invoke('revoke');await invoke('verify-admin');
      expect((await invoke('runtime-ready',{verification_hash:'e'.repeat(64),task_definition:target.fallbackTaskDefinition})).phase).toBe('runtime_ready');
      await expect(invoke('retire')).rejects.toMatchObject({code:'42501'});
      expect((await invoke('status')).phase).toBe('runtime_ready');
      expect(await scalar(root,'SELECT rolcanlogin AS result FROM pg_roles WHERE rolname=$1',[legacy])).toBe(true);
    }finally{
      await injected?.end();await setup?.end();await root.query('DROP DATABASE IF EXISTS "'+database+'" WITH (FORCE)');
      await root.query(`REVOKE mem9_maintenance_backend FROM "${runtimeCredential.username}" GRANTED BY "${administrator.username}" CASCADE`).catch(()=>{});
      for(const name of [administrator.username,runtimeCredential.username,legacy])await root.query('DROP ROLE IF EXISTS "'+name+'"');
      await root.query('REVOKE SET ON PARAMETER log_error_verbosity,log_min_error_statement FROM rds_superuser');
      await root.query('DROP ROLE IF EXISTS rds_superuser');await root.end();
    }
  },30000);
});
