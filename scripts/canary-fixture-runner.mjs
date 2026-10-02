import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import pg from 'pg';
import {runtimeSchemaDigest,runtimeRoleName} from './lib/runtime-credentials.mjs';
import {schemaAdministratorRole} from './lib/production-runtime-config.mjs';
import {productionOperatorDigest} from './production-runtime-operator.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
import {createHash} from 'node:crypto';

const execute=promisify(execFile),fail=code=>{throw Error(code);};
export const fixtureCaseNames=Object.freeze([
  'audits a paused frozen parent in a genuinely read-only snapshot without a new witness',
  'continues through canonical APIs without rewriting the root proof, binding or budget',
  'rejects wrong parent and incompatible witness before installing or changing continuation state',
  'binds an actual atomic apply receipt to the admitted attempt without charging a replay',
  'rolls back memory and counter updates when an actual apply has no attempt admission',
  'enforces one twenty-row lifetime allowance across parent and child receipts',
  'installs owner-only continuation metadata without changing runtime readiness',
  'rejects default grants before adding continuation tables',
  'keeps attempt headers and event history immutable and rejects reopening a frozen attempt',
  'rejects canary re-admission before changing a frozen parent or policy epochs',
  'does not overwrite a frozen legacy proof with new release identity',
  'does not re-prepare a setup after capturing its immutable validation baseline',
  'cleans only unchanged owned benchmark rows and safely repeats cleanup',
  'reconciles committed writes with lost responses and duplicate Gateway deliveries',
  'rejects late dispatchers from every earlier admission after pause and re-enable',
  'requires matching conservation and performance evidence before committing promotion',
  'prepares restricted logins, requires verification before canary and can pause through evidence drift',
]);
export function fixtureChecksFromReport(report){
  const count=fixtureCaseNames.length,results=report?.testResults;
  if(report?.success!==true||report.numTotalTests!==count||report.numPassedTests!==count||report.numFailedTests!==0||report.numPendingTests!==0||
    !Array.isArray(results)||results.length!==1||results[0].status!=='passed')fail('CanaryFixtureTestsIncomplete');
  const assertions=results[0].assertionResults;
  if(!Array.isArray(assertions)||assertions.length!==count||assertions.some(t=>t.status!=='passed')||
    hash(assertions.map(t=>t.title).sort())!==hash([...fixtureCaseNames].sort()))fail('CanaryFixtureTestsIncomplete');
  const passed=new Set(assertions.map(t=>t.title));
  const mapping={frozenParent:[9,10,11],continuation:[1,2,8],budgetCap:[5],receiptAdmission:[3,4,14],
    parentPreservation:[1,6,7,10],readOnlyAudit:[0],commitWindow:[1,15],steadyState:[1]};
  return Object.fromEntries(Object.entries(mapping).map(([key,indices])=>[key,indices.every(i=>passed.has(fixtureCaseNames[i]))]));
}
export function parseCanaryFixtureIdentity(raw){
  let value;try{if(typeof raw!=='string'||Buffer.byteLength(raw)>2048)throw Error();value=JSON.parse(raw);}catch{fail('CanaryFixtureIdentityInvalid');}
  const keys=['stage','runId','runAttempt','commit','sourceTree','coordinatorDigest','schemaDigest','operatorDigest','nonce','deadlineMs'];
  if(!value||Array.isArray(value)||Object.keys(value).sort().join()!==keys.sort().join()||!/^pr-[1-9][0-9]*$/.test(value.stage??'')||
    !/^[1-9][0-9]*$/.test(value.runId??'')||!Number.isSafeInteger(value.runAttempt)||value.runAttempt<1||!/^[a-f0-9]{32}$/.test(value.nonce??'')||
    !Number.isSafeInteger(value.deadlineMs)||value.deadlineMs<1)fail('CanaryFixtureIdentityInvalid');
  for(const key of ['commit','sourceTree'])if(!/^[a-f0-9]{40}$/.test(value[key]??''))fail('CanaryFixtureIdentityInvalid');
  for(const key of ['coordinatorDigest','schemaDigest','operatorDigest'])if(!/^[a-f0-9]{64}$/.test(value[key]??''))fail('CanaryFixtureIdentityInvalid');
  return value;
}

async function cleanFixtureRoles(){
  const db=new pg.Client({host:'127.0.0.1',port:5432,database:'runtime_credentials_test',user:'postgres',connectionTimeoutMillis:5000,statement_timeout:5000});
  try{
    await db.connect();
    const databases=Number((await db.query("SELECT count(*) AS count FROM pg_database WHERE datname~'^prod_workers_[0-9a-f]{32}$'")).rows[0].count);
    if(databases!==0)fail('CanaryFixtureDatabaseResidue');
    const shared=['mem9_maintenance_planner','mem9_maintenance_executor','mem9_maintenance_backend','mem9_maintenance_operator'];
    const roles=(await db.query('SELECT rolname,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=ANY($1)',[shared])).rows;
    if(roles.length!==shared.length||roles.some(r=>['rolcanlogin','rolsuper','rolcreatedb','rolcreaterole','rolreplication','rolbypassrls'].some(k=>r[k])))fail('CanaryFixtureRoleMismatch');
    for(const role of shared)await db.query('DROP ROLE '+role);
    const suffix=createHash('sha256').update('prod').digest('hex').slice(0,12);
    const names=[...shared,schemaAdministratorRole('prod'),runtimeRoleName('prod'),'mem9_planner_'+suffix,'mem9_executor_'+suffix];
    const remaining=Number((await db.query("SELECT count(*) AS count FROM pg_roles WHERE rolname=ANY($1) OR rolname~'^legacy_[0-9a-f]{32}$'",[names])).rows[0].count);
    if(remaining!==0)fail('CanaryFixtureRoleResidue');return {databases,roles:remaining};
  }finally{await db.end().catch(()=>{});}
}

async function main(){
  const identity=parseCanaryFixtureIdentity(process.env.MEM9_CANARY_FIXTURE_IDENTITY);
  if(Date.now()>=identity.deadlineMs||identity.deadlineMs>Date.now()+1200000)fail('CanaryFixtureExpired');
  if(process.env.MEM9_STAGE!==identity.stage||['MEM9_DB_SECRET','MEM9_RUNTIME_DB_SECRET','MEM9_TENANT_ID'].some(k=>process.env[k]))fail('CanaryFixtureIsolationRequired');
  if(await runtimeSchemaDigest('/bootstrap')!==identity.schemaDigest||await productionOperatorDigest()!==identity.operatorDigest)fail('CanaryFixturePackagedCodeMismatch');
  const directory=await mkdtemp('/tmp/mem9-canary-fixture-');
  try{
    const output=directory+'/results.json';
    // This is the same localhost-only harness as local verification. The fixture
    // has no Aurora credentials, and its fabricated cutover ledger is synthetic.
    await execute(process.execPath,['node_modules/vitest/vitest.mjs','run','scripts/production-consolidation-operator.postgres.test.mjs',
      '--no-file-parallelism','--reporter=json','--outputFile',output],{cwd:'/bootstrap/operator',timeout:Math.max(1,Math.min(600000,identity.deadlineMs-Date.now())),maxBuffer:4*1024*1024,
      env:{...process.env,MEM9_RUNTIME_TEST_DSN:'postgres://postgres@127.0.0.1:5432/runtime_credentials_test'}});
    const report=JSON.parse(await readFile(output,'utf8')),checks=fixtureChecksFromReport(report),cleanup=await cleanFixtureRoles();
    if(Date.now()>=identity.deadlineMs)fail('CanaryFixtureExpired');
    process.stdout.write(JSON.stringify({event:'canary_fixture_database',phase:'complete',identity,checks:{...checks,cleanup:true},
      databaseHash:hash({nonce:identity.nonce,cleanup}),cases:fixtureCaseNames.length,completedMs:Date.now()})+'\n');
  }finally{await rm(directory,{recursive:true,force:true});}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(()=>{
  process.stdout.write(JSON.stringify({event:'canary_fixture_database',phase:'failed',errorClass:'CanaryFixtureFailed'})+'\n');process.exitCode=1;
});
