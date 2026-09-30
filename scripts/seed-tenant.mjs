import pg from 'pg';
import {pathToFileURL} from 'node:url';
import {checkCredentialLogging} from './lib/consolidation-preview-secrets.mjs';

export async function seedTenant(db,{tenant,host,port,database,credentials,name='mem9-on-aws'}){
  if(!/^[a-f0-9]{32}$/.test(tenant||'')||!host||!Number.isInteger(port)||port<1||port>65535||!database||
    typeof credentials?.username!=='string'||typeof credentials?.password!=='string')throw Error('InvalidTenantSeed');
  await db.query(`INSERT INTO tenants(id,name,db_host,db_port,db_user,db_password,db_name,db_tls,provider,status,schema_version)
    VALUES($1,$2,$3,$4,$5,$6,$7,true,'self-hosted','active',1)
    ON CONFLICT(id) DO UPDATE SET db_host=EXCLUDED.db_host,db_port=EXCLUDED.db_port,db_user=EXCLUDED.db_user,
      db_password=EXCLUDED.db_password,db_name=EXCLUDED.db_name,db_tls=EXCLUDED.db_tls,status='active',updated_at=NOW()`,
  [tenant,name,host,port,credentials.username,credentials.password,database]);
}
async function main(){
  const env=process.env,credentials=JSON.parse(env.MEM9_DB_SECRET||'null');
  const db=new pg.Client({host:env.MEM9_DB_HOST,port:Number(env.MEM9_DB_PORT),database:env.MEM9_DB_NAME,
    user:credentials?.username,password:credentials?.password,ssl:{rejectUnauthorized:true},connectionTimeoutMillis:8000,
    statement_timeout:30000,query_timeout:35000,application_name:'mem9-tenant-bootstrap'});
  try{
    await db.connect();
    await checkCredentialLogging(db);
    await seedTenant(db,{tenant:env.MEM9_TENANT_ID,host:env.MEM9_DB_HOST,port:Number(env.MEM9_DB_PORT),database:env.MEM9_DB_NAME,credentials});
    process.stdout.write('bootstrap: tenant binding applied\n');
  }finally{await db.end();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(()=>{process.stderr.write('bootstrap: tenant binding failed\n');process.exitCode=1;});
