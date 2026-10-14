import {it,expect,vi,afterEach} from 'vitest';
import {Readable} from 'node:stream';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {nonrootHash as hash,NONROOT_LIMITS_HASH} from './lib/production-nonroot-contracts.mjs';
import {inspectCiSmokeReaderConfig,sourceAllowanceLocation,withCiSmokeSourceAllowance,verifyCiSmokeSourceAllowanceResponse} from './lib/ci-smoke-source-allowance.mjs';
import {STSClient} from '@aws-sdk/client-sts';
import {createFutureFundingPlan,inspectFutureFundingPlan,createFutureSourceReader,FUTURE_OWNER_PUBLICATION,verifyFutureGrantSet} from './lib/ci-smoke-grants.mjs';
import {zero,sha,addCounters} from './lib/ci-smoke-acquisition-format.mjs';
import {withCiSmokeAllowanceReadSession,buildCiSmokeAllowanceReadPolicy} from './lib/ci-smoke-session.mjs';
import {makeCiStartupRunBinding,ciStartupCheckpointSelection} from './lib/ci-smoke-startup.mjs';
import {ciSmokeEvidenceFixture} from './ci-smoke-evidence.fixture.mjs';
import {encodeCiSmokeEnvelope,ciSmokeArchiveKey,getCiSmokeEnvelope} from './lib/ci-smoke-private-archive.mjs';

const NOW=1700000000000,account='123456789012',region='us-east-1';
const roots=[];let sequence=0;afterEach(async()=>{vi.restoreAllMocks();for(const root of roots.splice(0))await rm(root,{recursive:true,force:true});});
function ownerStatuses(f){
 const b=f.binding.source,base={id:1,url:`https://api.github.com/repos/${b.repository}/statuses/${b.mainRevision}`,creator:{id:42}};
 const rows=[{...base,context:'mem9/prepaid/'+f.config.startup.grantSetId,state:'success',description:'binding:'+hash(f.binding),target_url:`https://github.com/${b.repository}/actions/runs/${b.runId}`}];
 // Synthetic owner selection is separate from upload success. The inbox
 // permits duplicate names; only its fixed first selection gets announced.
 if(f.artifact&&f.ownerWinner){const selected=ciStartupCheckpointSelection(f.config.startup,f.binding,f.scope,f.ownerWinner);rows.unshift({...base,id:2,...selected.announcement.payload});}
 return rows;
}

function fixture(){
 const scope={kind:'source',jobKey:'build-image-transition-control',route:'build-image-transition-control',phase:'source',checkpoint:'build-image-transition-control/source'};
 const descriptor={version:3,stage:'prod',account,region,controlSourceTree:'2'.repeat(40),dataRevision:'3'.repeat(40),dataSourceTree:'4'.repeat(40),dataSourceTag:'mem9-3333333',images:{},runtimeNonce:'1'.repeat(32),authorizationId:'2'.repeat(32),issuedMs:NOW-1000,expiresMs:NOW+600000,
  transition:{version:2,kind:'image-security-nonroot-upgrade',proofHash:'a'.repeat(64),predecessorHash:'b'.repeat(64),limitsHash:NONROOT_LIMITS_HASH}};
 for(const k of ['parentProofHash','backendBindingHash','generation','targetsHash','schemaDigest','operatorDigest','buildInputsHash','securityEvidenceHash','policyHash'])descriptor[k]='b'.repeat(64);
 for(const k of ['llm-proxy','mnemo-server','qwen3-embed'])descriptor.images[k]={rootDigest:'sha256:'+'c'.repeat(64),arm64Digest:'sha256:'+'d'.repeat(64)};
 const startup={version:1,kind:'owner-prepaid-startup-config',grantSetId:hash({synthetic:++sequence}),grantHash:'2'.repeat(64),ledgerStartHash:'3'.repeat(64),catalogHash:'4'.repeat(64),descriptorHash:hash(descriptor),proofHash:descriptor.transition.proofHash,
  source:{repository:'example/repository',prNumber:17,candidateRevision:'1'.repeat(40),candidateTree:descriptor.controlSourceTree,baseRevision:'3'.repeat(40)},consumers:[scope],ownerGithubActorId:42,notAfter:NOW+300000};
 const config={version:2,kind:'owner-ci-acquisition-config',startup,target:{kind:'production-data-release',descriptor,parameterVersion:2},account,region,ownerRoot:{runtimeNonce:descriptor.runtimeNonce,authorizationId:descriptor.authorizationId},
  storage:{bucket:'example-ci-reader',kmsKeyArn:`arn:aws:kms:${region}:${account}:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee`,bucketKeyEnabled:true},bootstrap:[{checkpoint:scope.checkpoint,responseBytes:1048576}]};
 const roleArn=`arn:aws:iam::${account}:role/github-actions-mem9-on-aws-prod`;
 const env={GITHUB_ACTIONS:'true',GITHUB_SERVER_URL:'https://github.com',GITHUB_REPOSITORY:startup.source.repository,GITHUB_RUN_ID:'77',GITHUB_RUN_ATTEMPT:'1',GITHUB_JOB:scope.jobKey,GITHUB_SHA:'4'.repeat(40),GITHUB_WORKFLOW_SHA:'4'.repeat(40),GITHUB_EVENT_NAME:'push',GITHUB_REF:'refs/heads/main',AWS_REGION:region,
  ACTIONS_ID_TOKEN_REQUEST_TOKEN:'synthetic-oidc-request',ACTIONS_ID_TOKEN_REQUEST_URL:'https://pipelines.actions.githubusercontent.com/synthetic/_apis/distributedtask/hubs/build/plans/00000000-0000-4000-8000-000000000001/jobs/00000000-0000-4000-8000-000000000002/idtoken?api-version=2.0',MEM9_CI_ACQUISITION_CONFIG:JSON.stringify(config)};
 return {config,scope,roleArn,env};
}
function stsHttp(f,{mutate=()=>{}}={}){
 const calls=[],bodies=[];let name,arn;const handler={destroy:vi.fn(),async handle(request){
  const p=new URLSearchParams(request.body??''),action=p.get('Action')??'oidc';calls.push({action,body:request.body,policy:p.get('Policy')});let text;
  if(action==='oidc')text=JSON.stringify({value:'synthetic.header.signature'});
  else if(action==='AssumeRoleWithWebIdentity'){
   name=p.get('RoleSessionName');arn=`arn:aws:sts::${account}:assumed-role/github-actions-mem9-on-aws-prod/${name}`;
   text=`<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIASYNTHETIC</AccessKeyId><SecretAccessKey>synthetic-secret</SecretAccessKey><SessionToken>synthetic-session</SessionToken><Expiration>${new Date(NOW+900000).toISOString()}</Expiration></Credentials><AssumedRoleUser><Arn>${arn}</Arn><AssumedRoleId>AROASYNTHETIC:${name}</AssumedRoleId></AssumedRoleUser></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`;
  }else text=`<GetCallerIdentityResponse><GetCallerIdentityResult><Account>${account}</Account><Arn>${arn}</Arn><UserId>AROASYNTHETIC:${name}</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`;
  const response={statusCode:200,headers:{'content-type':action==='oidc'?'application/json':'text/xml'},body:Readable.from([Buffer.from(text)])};bodies.push(response.body);mutate(action,response);return {response};
 }};return {handler,calls,bodies};
}
it('pins complete v2 config and derives one allowance key without a caller key or policy',()=>{
 const f=fixture(),c=inspectCiSmokeReaderConfig(f.config);expect(Object.isFrozen(c.startup)).toBe(true);
 const l=sourceAllowanceLocation({config:c,scope:f.scope,roleArn:f.roleArn});
 expect(l.key).toBe(`data-authorizations/${c.ownerRoot.runtimeNonce}/${c.ownerRoot.authorizationId}/ci-grants/${c.startup.grantSetId}/${hash(f.scope.checkpoint)}/response.json`);
 const p=JSON.parse(buildCiSmokeAllowanceReadPolicy({config:c,scope:f.scope,roleArn:f.roleArn}).Policy);
 expect(p.Statement.find(s=>s.Effect==='Allow'&&s.Action==='s3:GetObject').Resource).toBe(l.objectArn);
 expect(p.Statement.some(s=>s.Effect==='Allow'&&JSON.stringify(s).includes('PutObject'))).toBe(false);
});
it.each(['missing','version','extra','descriptor','root','kms','caps','future-key'])('rejects malformed protected config before reader setup: %s',defect=>{
 const f=fixture();if(defect==='missing')delete f.config.startup;if(defect==='version')f.config.version=1;if(defect==='extra')f.config.allow=true;
 if(defect==='descriptor')f.config.startup.descriptorHash='0'.repeat(64);if(defect==='root')f.config.ownerRoot.authorizationId='0'.repeat(32);
 if(defect==='kms')f.config.storage.kmsKeyArn=f.config.storage.kmsKeyArn.replace(account,'0'.repeat(12));if(defect==='caps')f.config.bootstrap[0].responseBytes++;
 if(defect==='future-key')f.config.storage.key='another-object';expect(()=>inspectCiSmokeReaderConfig(f.config)).toThrow();
});
it('has two fixed reader sessions, finite serial polling and one unknown charge, no source request Put',()=>{
 const p=createFutureSourceReader({version:1,kind:'source-two-reader',terminalResponseBytes:1048576});
 expect(p.operations.filter(c=>c.action==='AssumeRoleWithWebIdentity')).toEqual([expect.objectContaining({count:1,requestBytes:131072,responseBytes:131072}),expect.objectContaining({count:1,requestBytes:131072,responseBytes:131072})]);
 expect(p.operations.filter(c=>c.action==='GetCallerIdentity')).toHaveLength(2);
 expect(p.operations.filter(c=>c.purpose.startsWith('allowance-')&&c.action==='GetObject').reduce((n,c)=>n+c.count,0)).toBe(12);
 expect(p.operations.some(c=>c.action==='PutObject')).toBe(false);expect(p.unknownOvershoots).toBe(1);
});
it('uses real SDK serialization for the closed second STS reader and erases credentials',async()=>{
 const f=fixture(),m=stsHttp(f);let held;
 await withCiSmokeAllowanceReadSession({config:f.config,scope:f.scope,roleArn:f.roleArn,env:f.env,deadlineMs:NOW+90000},({credentials})=>{held=credentials;},{now:()=>NOW,requestHandler:m.handler});
 expect(m.calls.map(c=>c.action)).toEqual(['oidc','AssumeRoleWithWebIdentity','GetCallerIdentity']);
 expect(Buffer.byteLength(m.calls[2].body)).toBeGreaterThan(0);expect(m.calls.every(c=>Buffer.byteLength(c.body??'')<=131072)).toBe(true);
 expect(held.sessionToken).toBe('');expect(m.handler.destroy).toHaveBeenCalled();expect(m.bodies.every(b=>b.closed)).toBe(true);
});
it('rejects an unfunded source scope and ambient credentials with zero HTTP calls',async()=>{
 for(const defect of ['scope','credentials']){
  const f=fixture(),m=stsHttp(f);if(defect==='scope')f.scope.checkpoint+='-other';else f.env.AWS_ACCESS_KEY_ID='synthetic';
  await expect(withCiSmokeAllowanceReadSession({config:f.config,scope:f.scope,roleArn:f.roleArn,env:f.env,deadlineMs:NOW+90000},()=>{}, {now:()=>NOW,requestHandler:m.handler})).rejects.toThrow();expect(m.calls).toEqual([]);
 }
});
it('rejects missing production config before any source capture or startup artifact',async()=>{
 const f=fixture();delete f.env.MEM9_CI_ACQUISITION_CONFIG;const host={env:f.env,api:vi.fn(),run:vi.fn(),checkout:vi.fn()};
 await expect(withCiSmokeSourceAllowance({env:f.env,scope:f.scope,host,config:{},commitment:{},jobExpiresMs:NOW+60000},()=>{}, {now:()=>NOW})).rejects.toThrow();expect(host.api).not.toHaveBeenCalled();
});

function smokeEnvelope(){
 const f=ciSmokeEvidenceFixture(),records={result:f.json(f.result),source:f.json({identity:f.expected.identity}),isolation:f.json({isolationHash:f.expected.isolationHash}),observations:f.json(f.expected),commandBindings:f.json({invocationId:f.expected.invocationId}),commandCatalog:f.json(f.expected.commandCatalog)};
 const objects=new Map(),visit=v=>{if(!v||typeof v!=='object')return;if(v.bytesHash&&v.canonicalHash){if(objects.has(v.bytesHash))return;const raw=f.objects.get(v.bytesHash);objects.set(v.bytesHash,raw);visit(JSON.parse(raw));return;}if(v.sha256&&(v.bytesLength!==undefined||v.gitMode)){objects.set(v.sha256,f.objects.get(v.sha256));return;}Object.values(v).forEach(visit);};visit(records);
 return encodeCiSmokeEnvelope({records,objects:[...objects].map(([sha256,bytes])=>({sha256,bytes}))});
}
async function flowFixture({responseBytes=1048576}={}){
 const f=fixture(),root=await mkdtemp(join(tmpdir(),'ci-source-allowance-'));roots.push(root);f.env.RUNNER_TEMP=root;f.clock=NOW;f.events=[];
 f.config.bootstrap[0].responseBytes=responseBytes;
 f.funding=fundedGrant(f);Object.assign(f.config.startup,f.funding.expected);f.env.MEM9_CI_ACQUISITION_CONFIG=JSON.stringify(f.config);
 const s=f.config.startup.source,main=f.env.GITHUB_SHA,parents=[s.baseRevision,s.candidateRevision];
 const source={repository:s.repository,event:'push',ref:'refs/heads/main',checkout:{sha:main,tree:s.candidateTree,parents,clean:true},main:{sha:main,tree:s.candidateTree},
  run:{id:77,attempt:1,event:'push',headSha:main,repository:s.repository,path:'.github/workflows/infra-ci.yml',workflowSha:main},
  pullRequest:{number:s.prNumber,state:'closed',merged:true,headSha:s.candidateRevision,headRepository:s.repository,baseRef:'main',mergeCommitSha:main}};
 f.source=source;f.binding=makeCiStartupRunBinding(f.config.startup,source);const bindingHash=hash(f.binding);
 const run={id:77,run_attempt:1,status:'in_progress',event:'push',head_sha:main,head_branch:'main',path:source.run.path,repository:{full_name:s.repository},head_repository:{full_name:s.repository}};
 f.host={env:f.env,checkout:async()=>({revision:main,tree:s.candidateTree}),run:vi.fn(async(file,args)=>{
  expect(file).toBe('git');if(args[0]==='diff')return '';if(args[0]==='show')return [main,s.candidateTree,parents.join(' ')].join('\n');throw Error('UnexpectedGit');
 }),api:vi.fn(async path=>{
  if(path==='commits/main'||path==='commits/'+main)return {sha:main,commit:{tree:{sha:s.candidateTree}},parents:parents.map(sha=>({sha}))};
  if(path==='pulls/'+s.prNumber)return {number:s.prNumber,state:'closed',merged:true,head:{sha:s.candidateRevision,repo:{full_name:s.repository}},base:{ref:'main'},merge_commit_sha:main};
  if(path==='actions/runs/77'||path==='actions/runs/77/attempts/1')return run;
  if(path.startsWith('commits/'+main+'/statuses?'))return ownerStatuses(f);
  if(path==='actions/artifacts/'+f.artifact?.id)return f.artifact;throw Error('UnexpectedGithub');
 })};
 const artifactClient={async uploadArtifact(name,files){
  f.events.push('artifact');f.claim=JSON.parse(await readFile(files[0],'utf8'));const id=(f.artifact?.id??122)+1,artifactDigest=id===123?'e'.repeat(64):hash({id,nonce:f.claim.nonce});f.artifact={id,name,size_in_bytes:256,digest:'sha256:'+artifactDigest,expired:false,created_at:new Date(NOW).toISOString(),expires_at:new Date(NOW+86400000).toISOString(),workflow_run:{id:77,head_sha:main,head_branch:'main'}};
  f.ownerWinner??={...f.claim,artifactId:id,artifactDigest};return {id,size:256,digest:artifactDigest};
 }};
 const encoded=smokeEnvelope(),commitment=encoded.commitment,c=f.config;
 const readerConfig={stage:'pr-17',account,region,bucket:c.storage.bucket,bucketArn:'arn:aws:s3:::'+c.storage.bucket,objectArn:'arn:aws:s3:::'+c.storage.bucket+'/'+ciSmokeArchiveKey('pr-17',commitment),roleArn:f.roleArn,encryption:{algorithm:'aws:kms',keyArn:c.storage.kmsKeyArn,bucketKeyEnabled:true}};
 f.smoke=stsHttp(f,{mutate:action=>f.events.push('first-'+action)});f.allowance=stsHttp(f,{mutate:action=>{expect(f.smoke.handler.destroy).toHaveBeenCalled();expect(f.firstCredentials.sessionToken).toBe('');f.events.push('second-'+action);}});
 f.smokeObject={destroy:vi.fn(),handle:vi.fn(async request=>{f.events.push('smoke-get');expect(request.method).toBe('GET');return {response:{statusCode:200,headers:{'content-type':'application/json','content-length':String(encoded.bytes.length),'x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':c.storage.kmsKeyArn,'x-amz-server-side-encryption-bucket-key-enabled':'true'},body:Readable.from([encoded.bytes])}};})};
 f.allowanceObject={destroy:vi.fn(),handle:vi.fn(async request=>{f.events.push('allowance-get');expect(request.path).toBe('/'+c.storage.bucket+'/'+sourceAllowanceLocation({config:c,scope:f.scope,roleArn:f.roleArn}).key);return {response:{statusCode:404,headers:{'content-type':'application/xml'},body:Readable.from([Buffer.from('<Error><Code>NoSuchKey</Code><Message>absent</Message></Error>')])}};})};
 f.input={env:f.env,scope:f.scope,host:f.host,config:readerConfig,commitment,jobExpiresMs:NOW+500000};
 f.seams={now:()=>f.clock,sleep:vi.fn(async ms=>{f.events.push('sleep');f.clock+=ms;}),artifactClient,smokeSessionTransport:f.smoke.handler,allowanceSessionTransport:f.allowance.handler,smokeObjectTransport:f.smokeObject,allowanceObjectTransport:f.allowanceObject};
 f.verifySmoke=async ctx=>{f.firstCredentials=ctx.credentials;const decoded=await getCiSmokeEnvelope(commitment,{config:readerConfig,...ctx,now:()=>f.clock});f.events.push('smoke-verified');return {raw:decoded.envelopeBytes,checked:{source:{isolationHash:'f'.repeat(64)}}};};
 return f;
}
it('uses both real SDK readers serially, polling only twelve known 404s with the original nonce',async()=>{
 const f=await flowFixture();await expect(withCiSmokeSourceAllowance(f.input,f.verifySmoke,f.seams)).rejects.toThrow('CiSmokeReadSessionHeld');
 expect(f.events[0]).toBe('artifact');expect(f.events.indexOf('smoke-verified')).toBeLessThan(f.events.indexOf('second-oidc'));
 expect(f.smoke.calls.map(c=>c.action)).toEqual(['oidc','AssumeRoleWithWebIdentity','GetCallerIdentity']);expect(f.allowance.calls.map(c=>c.action)).toEqual(['oidc','AssumeRoleWithWebIdentity','GetCallerIdentity']);
 expect(f.smokeObject.handle).toHaveBeenCalledTimes(1);expect(f.allowanceObject.handle).toHaveBeenCalledTimes(12);expect(f.seams.sleep).toHaveBeenCalledTimes(11);
 expect(f.clock).toBe(NOW+55000);expect(f.claim.scopeHash).toBe(hash({bindingHash:hash(f.binding),scope:f.scope}));expect(f.allowance.handler.destroy).toHaveBeenCalled();
 expect(f.env.AWS_ACCESS_KEY_ID).toBeUndefined();expect(f.env.MEM9_CI_SMOKE_SOURCE_RECEIPT).toBeUndefined();
});
it.each(['smoke-failure','smoke-cleanup','source-expired','config-changed'])('does not open the second reader after %s',async defect=>{
 const f=await flowFixture();let verify=f.verifySmoke;
 if(defect==='smoke-failure')verify=async ctx=>{await f.verifySmoke(ctx);throw Error('synthetic-private-failure');};
 if(defect==='smoke-cleanup')f.smokeObject.destroy=()=>{throw Error('synthetic-private-cleanup');};
 if(defect==='source-expired')verify=async ctx=>{const out=await f.verifySmoke(ctx);f.clock=NOW+900000;return out;};
 if(defect==='config-changed')verify=async ctx=>{const out=await f.verifySmoke(ctx);f.env.MEM9_CI_ACQUISITION_CONFIG='{}';return out;};
 await expect(withCiSmokeSourceAllowance(f.input,verify,f.seams)).rejects.toThrow();expect(f.allowance.calls).toEqual([]);expect(f.smoke.handler.destroy).toHaveBeenCalled();
});
it.each([429,500,302])('never polls or retries HTTP %s',async statusCode=>{
 const f=await flowFixture();f.allowanceObject.handle=vi.fn(async()=>({response:{statusCode,headers:{'content-type':'application/xml'},body:Readable.from([Buffer.from('<Error><Code>AccessDenied</Code></Error>')])}}));
 await expect(withCiSmokeSourceAllowance(f.input,f.verifySmoke,f.seams)).rejects.toThrow();expect(f.allowanceObject.handle).toHaveBeenCalledTimes(1);expect(f.seams.sleep).not.toHaveBeenCalled();
});
it('rejects oversized raw error bodies, never parses or replays them',async()=>{
 const f=await flowFixture();f.allowanceObject.handle=vi.fn(async()=>({response:{statusCode:404,headers:{'content-type':'application/xml'},body:Readable.from([Buffer.alloc(16385)])}}));
 await expect(withCiSmokeSourceAllowance(f.input,f.verifySmoke,f.seams)).rejects.toThrow();expect(f.allowanceObject.handle).toHaveBeenCalledTimes(1);expect(f.seams.sleep).not.toHaveBeenCalled();
});
it('rejects manual events before artifact or any reader network',async()=>{
 const f=await flowFixture();f.env.GITHUB_EVENT_NAME='workflow_dispatch';await expect(withCiSmokeSourceAllowance(f.input,f.verifySmoke,f.seams)).rejects.toThrow();
 expect(f.events).toEqual([]);expect(f.smoke.calls).toEqual([]);
});
it('rejects an oversized serialized Query request before STS dispatch',async()=>{
 const f=fixture(),m=stsHttp(f),send=STSClient.prototype.send;
 vi.spyOn(STSClient.prototype,'send').mockImplementation(function(command,...args){
  command.middlewareStack.add(next=>async input=>{input.request.body+='x'.repeat(131072);return next(input);},{step:'finalizeRequest',name:'syntheticBodyOverflow'});
  return send.call(this,command,...args);
 });
 await expect(withCiSmokeAllowanceReadSession({config:f.config,scope:f.scope,roleArn:f.roleArn,env:f.env,deadlineMs:NOW+90000},()=>{}, {now:()=>NOW,requestHandler:m.handler})).rejects.toMatchObject({reason:'CiSmokeReadSessionBodyLimit'});
 expect(m.calls.map(c=>c.action)).toEqual(['oidc']);expect(m.handler.destroy).toHaveBeenCalled();
});
function responseFor(f,grantSet={}){
 const bindingHash=hash(f.binding),scopeHash=hash({bindingHash,scope:f.scope}),pending={bindingHash,scope:f.scope,nonce:'f'.repeat(64),scopeHash,artifactId:123,artifactName:'mem9-start-'+hash({grantSetId:f.config.startup.grantSetId,checkpoint:f.scope.checkpoint}),artifactDigest:'e'.repeat(64),notAfter:f.config.startup.notAfter};
 const response={version:1,kind:'owner-ci-allowance-response',runBinding:structuredClone(f.binding),scope:structuredClone(f.scope),nonce:pending.nonce,artifactId:pending.artifactId,requestHash:hash({nonce:pending.nonce,scopeHash}),grantSet,expiresMs:f.config.startup.notAfter};
 return {response,config:f.config,binding:f.binding,pending,now:NOW,deadlineMs:NOW+600000};
}
it.each(['nonce','scope','run','artifact','descriptor','proof','authority','extra'])('rejects a mismatched response %s before considering funding',async defect=>{
 const f=await flowFixture(),args=responseFor(f);
 if(defect==='nonce')args.response.nonce='0'.repeat(64);if(defect==='scope')args.response.scope={...f.scope,checkpoint:'deploy-prod/source'};
 if(defect==='run')args.response.runBinding.source.runId=78;if(defect==='artifact')args.response.artifactId=124;
 if(defect==='descriptor')args.response.runBinding.descriptorHash='0'.repeat(64);if(defect==='proof')args.response.runBinding.proofHash='0'.repeat(64);
 if(defect==='authority')args.response.authority=true;if(defect==='extra')args.response.paid=true;
 expect(()=>verifyCiSmokeSourceAllowanceResponse(args)).toThrow();
});
function fundedGrant(f,{legacy=false}={}){
 const ledgerBinding={owner:'a'.repeat(32),executionId:'b'.repeat(32),planHash:'c'.repeat(64),publicationHash:'d'.repeat(64)},reserve={ecrRequests:100,logicalBytes:100000000,httpBodyBytes:500000000,uncompressedBytes:100000000,processedEntries:1000};
 const start={version:1,kind:'custody-ledger-start',binding:ledgerBinding,startingCounters:zero(),reserve,deadlineMs:NOW+2700000,mode:'adoption'},startRaw=Buffer.from(JSON.stringify(start));
 const identity={version:1,id:'identity',kind:'EXACT',action:'GetCallerIdentity',request:{},requestBytes:1024,responseBytes:4096,count:1,ecr:false};
 const catalog={version:1,kind:'future-ci-profile-catalog',source:f.config.startup.source,ledgerBinding,consumers:[legacy?{scope:f.scope,profiles:[identity],localBudget:zero(),handshake:{terminalResponseBytes:1048576}}:{scope:f.scope,reader:{version:1,kind:'source-two-reader',terminalResponseBytes:f.config.bootstrap[0].responseBytes},localBudget:zero()}],owner:{publication:FUTURE_OWNER_PUBLICATION,localBudget:zero()},finalization:{profiles:[identity],localBudget:zero()},localBudget:zero()};
 const plan=createFutureFundingPlan({binding:{grantSetId:f.config.startup.grantSetId,source:f.config.startup.source,anchors:{predecessorParameterHash:'a'.repeat(64),rootBindingHash:'b'.repeat(64),copyCheckpointHash:'c'.repeat(64),authorizationId:f.config.ownerRoot.authorizationId,nextParameterVersion:2}},catalogRaw:Buffer.from(JSON.stringify(catalog)).toString('base64'),ledgerStartHash:sha(startRaw),ownerGithubActorId:42,ownerStateDirectory:'/synthetic/grant-'+f.config.startup.grantSetId,issuedMs:NOW-1000});
 const funding=inspectFutureFundingPlan(plan),spent=addCounters(start.startingCounters,plan.budget),remaining=Object.fromEntries(Object.entries(reserve).map(([k,v])=>[k,v-plan.budget[k]]));
 const event={version:1,sequence:1,...ledgerBinding,previousHash:null,type:'prepayment',data:{allocationId:funding.planHash,planHash:funding.planHash,scopeHash:funding.scopeHash,charge:plan.budget,reserveDebit:plan.budget},spent,remaining};
 const checkpoint={binding:ledgerBinding,startingCounters:start.startingCounters,counters:spent,remainingReservation:remaining,eventCount:1,lastEventHash:hash(event),active:0,sealed:false};
 const grantSet={...plan,version:2,kind:'owner-prepaid-future-grant-set',authority:false,planHash:funding.planHash,allocationId:funding.planHash,debit:{start,startRaw:startRaw.toString('base64'),events:[event],checkpoint}};
 const expected={grantSetId:plan.grantSetId,grantHash:hash(grantSet),ledgerStartHash:plan.ledgerStartHash,catalogHash:plan.catalogHash};
 return {grantSet,expected};
}
it('rejects the old SOURCE catalog that only prepaid the private request handshake',()=>{
 expect(()=>fundedGrant(fixture(),{legacy:true})).toThrow();
});
it('verifies the full original grant/debit, independent four roots and exact response bindings',async()=>{
 const f=await flowFixture(),args=responseFor(f,f.funding.grantSet),verified=verifyCiSmokeSourceAllowanceResponse(args);
 expect(verified).toMatchObject({grantHash:f.funding.expected.grantHash,bindingHash:hash(f.binding),scope:f.scope,notAfter:f.config.startup.notAfter});
 for(const key of ['grantHash','grantSetId','ledgerStartHash','catalogHash']){
  const config=structuredClone(args.config);config.startup[key]='0'.repeat(64);expect(()=>verifyCiSmokeSourceAllowanceResponse({...args,config})).toThrow();
 }
 const shortConfig=structuredClone(args.config);shortConfig.bootstrap[0].responseBytes=8192;
 expect(()=>verifyCiSmokeSourceAllowanceResponse({...args,config:shortConfig})).toThrow('CiFutureAllowanceBootstrapBudget');
});
it('finishes both real SDK readers with the actual grant verifier and clears credentials before return',async()=>{
 const f=await flowFixture();let secondCredentials,encodedResponseBytes;
 f.allowanceObject.handle=vi.fn(async request=>{
  f.events.push('allowance-get');const args=responseFor(f,f.funding.grantSet);Object.assign(args.response,{nonce:f.claim.nonce,requestHash:hash(f.claim)});
  const raw=Buffer.from(JSON.stringify(args.response));encodedResponseBytes=raw.length;expect(raw.length).toBeLessThan(f.config.bootstrap[0].responseBytes);
  expect(request.method).toBe('GET');secondCredentials=request.headers;
  return {response:{statusCode:200,headers:{'content-type':'application/json','content-length':String(raw.length),'x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':f.config.storage.kmsKeyArn,'x-amz-server-side-encryption-bucket-key-enabled':'true'},body:Readable.from([raw])}};
 });
 const result=await withCiSmokeSourceAllowance(f.input,f.verifySmoke,f.seams);
 expect(result.allowance.nonce).toBe(f.claim.nonce);expect(result.allowance.grantHash).toBe(f.funding.expected.grantHash);expect(result.observed.raw).toBeInstanceOf(Uint8Array);
 expect(encodedResponseBytes).toBeGreaterThan(8192);
 expect(result.expiresMs).toBe(f.config.startup.notAfter);expect(f.smokeObject.handle).toHaveBeenCalledTimes(1);expect(f.allowanceObject.handle).toHaveBeenCalledTimes(1);
 expect(f.allowance.handler.destroy).toHaveBeenCalled();expect(f.allowanceObject.destroy).toHaveBeenCalled();expect(secondCredentials.authorization).toBeUndefined();expect(secondCredentials['x-amz-security-token']).toBeUndefined();
 expect(f.env.AWS_ACCESS_KEY_ID).toBeUndefined();expect(f.env.AWS_SESSION_TOKEN).toBeUndefined();
 await expect(withCiSmokeSourceAllowance(f.input,f.verifySmoke,f.seams)).rejects.toThrow('CiStartupAlreadyAttempted');
 expect(f.smokeObject.handle).toHaveBeenCalledTimes(1);expect(f.allowanceObject.handle).toHaveBeenCalledTimes(1);
});
it('rejects a genuinely funded response cap too small for its complete grant and debit bytes',async()=>{
 const f=await flowFixture({responseBytes:4096}),args=responseFor(f,f.funding.grantSet);
 expect(verifyFutureGrantSet(f.funding).consumer).toBeUndefined();
 expect(Buffer.byteLength(JSON.stringify(args.response))).toBeGreaterThan(4096);
 expect(()=>verifyCiSmokeSourceAllowanceResponse(args)).toThrow('CiFutureAllowanceEnvelope');
});
it('bounds the original HTTP body even when its canonical JSON response would fit',async()=>{
 const f=await flowFixture();let body;
 f.allowanceObject.handle=vi.fn(async()=>{
  const args=responseFor(f,f.funding.grantSet);Object.assign(args.response,{nonce:f.claim.nonce,requestHash:hash(f.claim)});
  const raw=Buffer.from(JSON.stringify(args.response)),cap=f.config.bootstrap[0].responseBytes;
  expect(raw.length).toBeLessThan(cap);body=Readable.from([raw,Buffer.alloc(cap+1-raw.length,32)]);
  return {response:{statusCode:200,headers:{'content-type':'application/json','x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':f.config.storage.kmsKeyArn,'x-amz-server-side-encryption-bucket-key-enabled':'true'},body}};
 });
 await expect(withCiSmokeSourceAllowance(f.input,f.verifySmoke,f.seams)).rejects.toThrow();
 expect(f.allowanceObject.handle).toHaveBeenCalledTimes(1);expect(f.seams.sleep).not.toHaveBeenCalled();expect(body.closed).toBe(true);expect(f.allowance.handler.destroy).toHaveBeenCalled();
});
it('includes reader setup and time spent on known 404s in the single ninety-second allowance deadline',async()=>{
 const f=await flowFixture(),handle=f.allowanceObject.handle;
 f.allowanceObject.handle=vi.fn(async(...args)=>{const result=await handle(...args);f.clock+=15000;return result;});
 await expect(withCiSmokeSourceAllowance(f.input,f.verifySmoke,f.seams)).rejects.toThrow();
 expect(f.allowanceObject.handle.mock.calls.length).toBeLessThan(12);expect(f.clock).toBeLessThanOrEqual(NOW+95000);expect(f.allowance.handler.destroy).toHaveBeenCalled();
});
it('holds an unclosed allowance stream after bounded abort/drain and clears signed request credentials',async()=>{
 const f=await flowFixture();let release,headers;
 const body=new Readable({read(){},destroy(error,callback){release=()=>callback(error);}});
 f.allowanceObject.handle=vi.fn(async request=>{headers=request.headers;return {response:{statusCode:200,headers:{'content-type':'application/json'},body}};});
 const verify=async ctx=>{const result=await f.verifySmoke(ctx);f.clock=f.config.startup.notAfter-100;return result;};
 try{
  await expect(withCiSmokeSourceAllowance(f.input,verify,f.seams)).rejects.toMatchObject({code:'ECLEANUP'});
  expect(f.allowanceObject.handle).toHaveBeenCalledTimes(1);expect(f.seams.sleep).not.toHaveBeenCalled();expect(f.allowance.handler.destroy).toHaveBeenCalled();
  expect(headers.authorization).toBeUndefined();expect(headers['x-amz-security-token']).toBeUndefined();expect(f.env.MEM9_CI_SMOKE_SOURCE_RECEIPT).toBeUndefined();
 }finally{release?.();await new Promise(resolve=>setImmediate(resolve));}
 expect(body.closed).toBe(true);
});
it('R6 accepts a fully received exact-key 403 as pending, then verifies the 200 response',async()=>{
 const f=await flowFixture();let calls=0;
 f.allowanceObject.handle=vi.fn(async()=>{
  if(++calls===1)return {response:{statusCode:403,headers:{'content-type':'application/xml'},body:Readable.from([Buffer.from('<Error><Code>NotAnAbsenceAssertion</Code></Error>')])}};
  const args=responseFor(f,f.funding.grantSet);Object.assign(args.response,{nonce:f.claim.nonce,requestHash:hash(f.claim)});const raw=Buffer.from(JSON.stringify(args.response));
  return {response:{statusCode:200,headers:{'content-type':'application/json','content-length':String(raw.length),'x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':f.config.storage.kmsKeyArn,'x-amz-server-side-encryption-bucket-key-enabled':'true'},body:Readable.from([raw])}};
 });
 const out=await withCiSmokeSourceAllowance(f.input,f.verifySmoke,f.seams);expect(out.allowance.nonce).toBe(f.claim.nonce);expect(calls).toBe(2);expect(f.seams.sleep).toHaveBeenCalledExactlyOnceWith(5000);
});
it('R6 permanent 403 stops at twelve inclusive without another reader or a renewed deadline',async()=>{
 const f=await flowFixture();f.allowanceObject.handle=vi.fn(async()=>({response:{statusCode:403,headers:{'content-type':'application/xml'},body:Readable.from([Buffer.from('<Error><Code>AccessDenied</Code></Error>')])}}));
 await expect(withCiSmokeSourceAllowance(f.input,f.verifySmoke,f.seams)).rejects.toThrow();expect(f.allowanceObject.handle).toHaveBeenCalledTimes(12);expect(f.seams.sleep).toHaveBeenCalledTimes(11);expect(f.clock).toBe(NOW+55000);
});
it.each(['overflow','incomplete','deadline'])('R6 403 %s is terminal, never another pending poll',async fault=>{
 const f=await flowFixture();f.allowanceObject.handle=vi.fn(async()=>{if(fault==='deadline')f.clock=f.config.startup.notAfter;return {response:{statusCode:403,headers:{'content-type':'application/xml',...(fault==='incomplete'?{'content-length':'999'}:{})},body:Readable.from([fault==='overflow'?Buffer.alloc(16385):Buffer.from('<Error><Code>AccessDenied</Code></Error>')])}};});
 await expect(withCiSmokeSourceAllowance(f.input,f.verifySmoke,f.seams)).rejects.toThrow();expect(f.allowanceObject.handle).toHaveBeenCalledTimes(1);expect(f.seams.sleep).not.toHaveBeenCalled();
});
it('R6 does not apply pending polling to the original CI evidence object',async()=>{
 const f=await flowFixture();f.smokeObject.handle=vi.fn(async()=>({response:{statusCode:403,headers:{'content-type':'application/xml'},body:Readable.from([Buffer.from('<Error><Code>AccessDenied</Code></Error>')])}}));
 await expect(withCiSmokeSourceAllowance(f.input,f.verifySmoke,f.seams)).rejects.toThrow();expect(f.smokeObject.handle).toHaveBeenCalledTimes(1);expect(f.allowance.calls).toEqual([]);expect(f.seams.sleep).not.toHaveBeenCalled();
});

it('duplicate artifact-name uploads both succeed, but a different owner-selected upload makes SOURCE do zero AWS',async()=>{
 const f=await flowFixture(),name='mem9-start-'+hash({grantSetId:f.config.startup.grantSetId,checkpoint:f.scope.checkpoint}),seed=join(f.env.RUNNER_TEMP,'other-process.json');
 await import('node:fs/promises').then(fs=>fs.writeFile(seed,JSON.stringify({nonce:'a'.repeat(64),scopeHash:hash({bindingHash:hash(f.binding),scope:f.scope})}),{mode:0o600}));
 const first=await f.seams.artifactClient.uploadArtifact(name,[seed]);
 await expect(withCiSmokeSourceAllowance(f.input,f.verifySmoke,f.seams)).rejects.toThrow();
 expect(first.id).toBe(123);expect(f.artifact.id).toBe(124);expect(f.artifact.digest).not.toBe('sha256:'+first.digest);expect(f.artifact.name).toBe(name);expect(f.smoke.calls).toEqual([]);expect(f.allowance.calls).toEqual([]);
});
