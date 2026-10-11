import {it,expect,vi,afterEach} from 'vitest';
import {mkdtemp,writeFile,readFile,readdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Readable} from 'node:stream';
import {NodeHttpHandler} from '@smithy/node-http-handler';
import {GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import {GetParametersCommand} from '@aws-sdk/client-ssm';
import {openCiSmokeAcquisition,acquisitionOwnerKey} from './lib/ci-smoke-acquisition.mjs';
import {hash,sha,zero,prepaidSlotBudget} from './lib/ci-smoke-acquisition-format.mjs';
import {createNonrootBudgetedReads} from './lib/production-nonroot-budget-transport.mjs';
import {PRODUCTION_DATA_RELEASE_PARAMETER as parameterName} from './lib/production-data-issuance.mjs';
const directories=[];
afterEach(async()=>{vi.restoreAllMocks();for(const path of directories.splice(0))await rm(path,{recursive:true,force:true});});

// Synthetic budget custody only. These records cannot pass the separate
// production proof/source/runtime admission verifiers.
async function fixture(){
 const root=await mkdtemp(join(tmpdir(),'nonroot-budget-bridge-'));directories.push(root);
 const put=async(name,value)=>{const raw=Buffer.from(JSON.stringify(value)),path=join(root,name);await writeFile(path,raw,{mode:0o600});return {path,sha256:sha(raw)};};
 const now=Date.now(),proof={synthetic:'budget-only'},descriptor={version:3,stage:'prod',account:'123456789012',region:'us-east-1',runtimeNonce:'a'.repeat(32),authorizationId:'b'.repeat(32),expiresMs:now+600000,transition:{proofHash:hash(proof)}};
 const scope={descriptorHash:hash(descriptor),proofHash:hash(proof),sourceTree:'c'.repeat(40),repository:'example/repository',mainRevision:'d'.repeat(40),runId:77,runAttempt:1,jobKey:'deploy-prod',route:'deploy-prod',phase:'preupdate',checkpoint:'deploy-prod/9',account:descriptor.account,region:descriptor.region};
 const binding={owner:'e'.repeat(32),executionId:'f'.repeat(32),planHash:'1'.repeat(64),publicationHash:'2'.repeat(64)};
 const seed={version:1,kind:'owner-ci-acquisition-seed',expected:{scope,ledgerBinding:binding,ledgerStartHash:'0'.repeat(64),catalogHash:'3'.repeat(64)},descriptor,parameterVersion:3,expiresMs:now+300000,
  allocation:{bucket:'example-owned-artifacts',key:'',sha256:'0'.repeat(64),bytesLength:1,requestBytes:4096,responseBytes:65536,kmsKeyArn:'arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',bucketKeyEnabled:true}};
 seed.allocation.key=acquisitionOwnerKey(seed);
 const calls=[{action:'GetObject',request:{Bucket:seed.allocation.bucket,Key:seed.allocation.key,ExpectedBucketOwner:scope.account},requestBytes:4096,responseBytes:65536,ecr:false},
  {action:'GetCallerIdentity',request:{},requestBytes:2048,responseBytes:8192,ecr:false},
  {action:'GetParameters',request:{Names:[parameterName],WithDecryption:true},requestBytes:2048,responseBytes:32768,ecr:false}];
 const localBudget=zero(),budget=prepaidSlotBudget(calls,localBudget),plan={version:1,kind:'named-prepayment-plan',catalogHash:seed.expected.catalogHash,ledgerBinding:binding,scope,calls,localBudget,budget},allocationId=hash(plan);
 const start={version:1,kind:'custody-ledger-start',binding,startingCounters:zero(),reserve:budget,deadlineMs:now+180000,mode:'adoption'},startRaw=Buffer.from(JSON.stringify(start));seed.expected.ledgerStartHash=sha(startRaw);
 const event={version:1,sequence:1,...binding,previousHash:null,type:'prepayment',data:{allocationId,planHash:hash(plan),scopeHash:hash(scope),charge:budget,reserveDebit:budget},spent:budget,remaining:zero()};
 const allocation={version:2,kind:'owner-prepaid-named-allocation',authority:false,allocationId,plan,runEvidence:{observedMs:now-1000,run:{id:scope.runId,run_attempt:1,head_sha:scope.mainRevision,head_branch:'main',event:'push',path:'.github/workflows/infra-ci.yml',status:'in_progress',created_at:new Date(now-10000).toISOString(),repository:{full_name:scope.repository}},commit:{sha:scope.mainRevision,tree:{sha:scope.sourceTree}}},
  debit:{start,startRaw:startRaw.toString('base64'),events:[event],checkpoint:{binding,startingCounters:zero(),counters:budget,remainingReservation:zero(),eventCount:1,lastEventHash:hash(event),active:0,sealed:false}}};
 const allocationRaw=Buffer.from(JSON.stringify(allocation));seed.allocation.sha256=sha(allocationRaw);seed.allocation.bytesLength=allocationRaw.length;
 const sourceReceipt={current:{repository:scope.repository,runId:77,runAttempt:1,job:scope.jobKey,revision:scope.mainRevision},checkout:{revision:scope.mainRevision,tree:scope.sourceTree},observedMs:now-500,expiresMs:seed.expiresMs},sourceRef=await put('source.json',sourceReceipt);
 const config={version:1,kind:'owner-ci-acquisition-config',account:scope.account,region:scope.region,ownerRoot:{runtimeNonce:descriptor.runtimeNonce,authorizationId:descriptor.authorizationId},ledgerBinding:binding,ledgerStartHash:seed.expected.ledgerStartHash,catalogHash:seed.expected.catalogHash,expiresMs:seed.expiresMs,target:{kind:'production-data-release',descriptor,parameterVersion:3},storage:Object.fromEntries(['bucket','requestBytes','responseBytes','kmsKeyArn','bucketKeyEnabled'].map(k=>[k,seed.allocation[k]]))};
 const env={STAGE:'prod',GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:scope.repository,GITHUB_RUN_ID:'77',GITHUB_RUN_ATTEMPT:'1',GITHUB_JOB:scope.jobKey,GITHUB_SHA:scope.mainRevision,AWS_REGION:scope.region,RUNNER_TEMP:root,
  MEM9_CI_ACQUISITION_CONFIG:JSON.stringify(config),MEM9_CI_SMOKE_SOURCE_RECEIPT:sourceRef.path,MEM9_CI_SMOKE_SOURCE_RECEIPT_HASH:sourceRef.sha256,
  AWS_ACCESS_KEY_ID:'synthetic-access',AWS_SECRET_ACCESS_KEY:'synthetic-secret',AWS_SESSION_TOKEN:'synthetic-session'};
 const response={InvalidParameters:[],Parameters:[{Name:parameterName,Type:'SecureString',ARN:`arn:aws:ssm:${scope.region}:${scope.account}:parameter${parameterName}`,Version:3,Value:JSON.stringify(descriptor)}]};
 let account=scope.account;const observed=[];
 vi.spyOn(NodeHttpHandler.prototype,'handle').mockImplementation(async request=>{
  let raw,headers;
  if(request.hostname.startsWith('s3.')){expect(request.path).toBe('/'+seed.allocation.bucket+'/'+seed.allocation.key);raw=allocationRaw;headers={'x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':seed.allocation.kmsKeyArn,'x-amz-server-side-encryption-bucket-key-enabled':'true','content-length':String(raw.length)};}
  else if(request.hostname.startsWith('sts.')){raw=Buffer.from(`<GetCallerIdentityResponse><GetCallerIdentityResult><Account>${account}</Account><Arn>arn:aws:sts::${account}:assumed-role/example/test</Arn><UserId>synthetic</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`);headers={'content-type':'text/xml'};}
  else{expect(request.hostname).toBe('ssm.us-east-1.amazonaws.com');raw=Buffer.from(JSON.stringify(response));headers={'content-type':'application/x-amz-json-1.1'};}
  observed.push({hostname:request.hostname,rawHash:sha(raw)});return {response:{statusCode:200,headers,body:Readable.from([raw])}};
 });
 const host={env,checkout:async()=>sourceReceipt.checkout},slot=await openCiSmokeAcquisition({env,scope:{route:scope.route,phase:scope.phase,checkpoint:scope.checkpoint},sourceReceipt,host});
 const reads=createNonrootBudgetedReads({region:scope.region,env,metadataReads:slot});
 return {root,scope,slot,reads,response,observed,changeAccount(v){account=v;},async bundle(){return put('phase-bundle.json',{kind:'image-security-nonroot-deployment-bundle',source:{checkout:{sha:scope.mainRevision,tree:scope.sourceTree}},parameter:{Value:JSON.stringify(descriptor)},proof,
  phaseReceipt:{phase:scope.phase,sourceReceiptHash:sourceRef.sha256,observedMs:Date.now(),expiresMs:seed.expiresMs}});}};
}
it('composes actual Gibbs acquisition with actual SDK responses and finishes using the new bundle reference',async()=>{
 const f=await fixture();try{
  expect((await f.reads.clients.sts.send(new GetCallerIdentityCommand({}))).Account).toBe(f.scope.account);
  const response=await f.reads.clients.ssm.send(new GetParametersCommand({Names:[parameterName],WithDecryption:true}));expect(response.Parameters).toEqual(f.response.Parameters);
  expect(f.reads.reserveLocal(zero())).toEqual(zero());
  const bundleRef=await f.bundle(),finished=await f.slot.finish({bundleRef});expect(finished.authority).toBe(false);
  const receipt=JSON.parse(await readFile(finished.receiptRef.path,'utf8'));expect(receipt.bundleRef).toEqual(bundleRef);expect(receipt.ownerRefund).toBe(0);
  expect(f.observed.map(r=>r.hostname)).toEqual(['s3.us-east-1.amazonaws.com','sts.us-east-1.amazonaws.com','ssm.us-east-1.amazonaws.com']);
 }finally{f.reads.close();}
});
it.each(['caller','descriptor'])('actual bridge rejects a different %s and records HOLD',async defect=>{
 const f=await fixture();try{
  if(defect==='caller')f.changeAccount('0'.repeat(12));
  else{await f.reads.clients.sts.send(new GetCallerIdentityCommand({}));f.response.Parameters[0].Version++;}
  await expect(defect==='caller'?f.reads.clients.sts.send(new GetCallerIdentityCommand({})):f.reads.clients.ssm.send(new GetParametersCommand({Names:[parameterName],WithDecryption:true}))).rejects.toThrow('NonrootBudgetReadFailed');
  expect((await readdir(join(f.root,'mem9-ci-acquisitions'))).some(name=>name.endsWith('-held.json'))).toBe(true);
  await expect(f.slot.finish({bundleRef:await f.bundle()})).rejects.toThrow();
 }finally{f.reads.close();}
});
