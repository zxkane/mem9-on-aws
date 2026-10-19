import {describe,it,expect} from 'vitest';
import net from 'node:net';
import {execFile,execFileSync,spawn} from 'node:child_process';
import {chmod,lstat,mkdir,mkdtemp,readFile,readdir,rm,writeFile} from 'node:fs/promises';
import {existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {expectedGatewayBoundaryPolicyDocument} from './lib/gateway-workload-boundary.mjs';
import {gatewayCanaryDocumentHash as hash} from './lib/gateway-runtime-canary-resources.mjs';
import {requestGatewayRuntimeSourceGate} from './lib/gateway-runtime-source-gate.mjs';
import {encodeGatewaySourceBrokerFrame,parseGatewaySourceBrokerRequest,gatewaySourceBrokerContract,gatewayBoundaryStatementsHash,startGatewayRuntimeSourceBroker,
  gatewaySourceBrokerOwnerEnvironment,resolveGatewaySourceBrokerOwner,gatewaySourceBrokerExitCode,gatewaySourceBrokerSessionTags,
  answerGatewayRuntimeSourceRequest,createGatewaySourceBrokerAwsCli,gatewayCanaryPlanDifference,gatewaySourceBrokerDetail,gatewaySourceBrokerOwnerSessionWarnings} from './lib/gateway-runtime-source-broker.mjs';
import {compileGatewayRuntimeCanaryScope,renderGatewayRuntimeCanaryTemplate,verifyGatewayRuntimeCanaryPlan} from './lib/gateway-runtime-canary-resources.mjs';
import {resolveApplicationRegion} from './lib/application-region.mjs';
import {GATEWAY_CANARY_OPERATOR_ROLE_NAME} from './lib/gateway-canary-operator-role.mjs';
import {startSimulatedBroker,createSyntheticBrokerCheckout,gitExecutable} from './test-fixtures/gateway-runtime-canary/simulated-broker.mjs';
import {installFakeAwsCli} from './test-fixtures/gateway-runtime-canary/fake-aws-cli.mjs';

const here=dirname(fileURLToPath(import.meta.url));
const contract={partition:'aws',accountId:'123456789012',applicationRegion:'ap-northeast-1',policyRevision:'r1'};
const reviewed=expectedGatewayBoundaryPolicyDocument(contract);
const MUTATIONS=['create-stack','update-stack','delete-stack','create-policy','delete-policy'];
const OPERATOR_ARN=`arn:aws:iam::123456789012:role/${GATEWAY_CANARY_OPERATOR_ROLE_NAME}`;
// Built at runtime: only 123456789012 may appear as a literal account, and no literal may look like an access key.
const FOREIGN_ACCOUNT='0'.repeat(12),OBSERVE_KEY='ASIA'+'OBSERVE'.padEnd(16,'0');
const CANARY_MS=60_000;

async function workspace(test,live=reviewed){
  const directory=await mkdtemp(join(tmpdir(),'gateway-broker-'));test.onTestFinished(()=>rm(directory,{recursive:true,force:true}));
  const liveBoundaryPath=join(directory,'live-boundary.json');await writeFile(liveBoundaryPath,JSON.stringify(live));
  return {directory,liveBoundaryPath};
}
async function setup(test,{live,...options}={}){
  const w=await workspace(test,live),logs=[];
  const f=await startSimulatedBroker({...w,log:m=>logs.push(m),...options});
  test.onTestFinished(()=>f.broker.close({abort:true}));
  return {...f,...w,logs};
}
/** A broker whose startup canary must fail: no socket, everything retained for review. */
async function failedStart(test,{live,onFixture,...options}={}){
  const w=await workspace(test,live),logs=[];let fixture;
  const error=await startSimulatedBroker({...w,log:m=>logs.push(m),onFixture:x=>{fixture=x;onFixture?.(x);},...options}).then(()=>null,e=>e);
  expect(error).toBeInstanceOf(Error);
  const root=join(w.directory,'evidence'),directories=existsSync(root)?(await readdir(root)).map(n=>join(root,n)):[];
  return {...w,...fixture,error,logs,directories};
}
const request=(f,overrides={})=>requestGatewayRuntimeSourceGate({boundary:reviewed,contract,policyVersion:'v1',socketPath:f.broker.socketPath,
  expectedSource:{commit:f.checkout.commit,tree:f.checkout.tree},...overrides});
function raw(socketPath,bytes){
  return new Promise((resolve,reject)=>{
    const socket=net.createConnection(socketPath),chunks=[];
    socket.on('connect',()=>socket.write(bytes));socket.on('data',c=>chunks.push(c));
    // A refused connection may reset before the write completes; that is a refusal too.
    socket.on('error',error=>{if(!['EPIPE','ECONNRESET'].includes(error.code))reject(error);});
    socket.on('close',()=>{const wire=Buffer.concat(chunks);resolve(wire.length>=4?JSON.parse(wire.subarray(4)):null);});
  });
}
const frame=value=>encodeGatewaySourceBrokerFrame(value);
const verifyRequest=(document,policyVersion='v1',region=contract.applicationRegion,id='c'.repeat(32))=>({version:1,id,argv:['gateway-runtime','verify-source','--boundary-document',JSON.stringify(document),'--policy-version',policyVersion,'--region',region]});
const actions=f=>f.aws.calls().map(c=>c.action);
const readJson=async path=>JSON.parse(await readFile(path,'utf8'));
const requestJournal=async f=>(await readFile(join(f.broker.evidenceDirectory,'requests.jsonl'),'utf8')).trim().split('\n').filter(Boolean).map(l=>JSON.parse(l));

describe('Gateway source broker',()=>{
  it('TC-GW-BROKER-001 runs one native A/B/A canary on separate lanes before publishing, then answers from it without AWS mutation',async test=>{
    const f=await setup(test);
    // The canary and its cleanup are complete before the socket exists.
    expect(f.aws.state().deleted).toBe(true);expect(f.aws.state().sessionPolicies).toEqual({});
    const before=f.aws.calls().length;
    const started=Date.now(),receipt=await request(f);
    expect(Date.now()-started).toBeLessThan(15_000);
    expect(receipt).toEqual({...f.broker.receipt,policyHash:hash(reviewed),policyVersion:'v1'});
    expect(receipt).toEqual({version:1,kind:'gateway-source-condition-verified',policyHash:hash(reviewed),policyVersion:'v1',
      evidenceHash:expect.stringMatching(/^[a-f0-9]{64}$/),handlerHash:expect.stringMatching(/^[a-f0-9]{64}$/),
      source:{commit:f.checkout.commit,tree:f.checkout.tree},coverage:['kms-source-condition','ec2-source-condition']});
    const answered=f.aws.calls().slice(before);
    expect(answered.map(c=>c.service+' '+c.action)).toEqual(['sts get-caller-identity','iam get-policy','iam get-policy-version']);
    expect(answered.every(c=>c.lane===null)).toBe(true);
    const calls=f.aws.calls().slice(0,before),lanes=Object.groupBy(calls,c=>c.lane??'owner');
    // The owner identity reads the live boundary itself and only issues sessions.
    expect(new Set(lanes.owner.map(c=>c.service+' '+c.action))).toEqual(new Set(['sts get-caller-identity','iam get-role','ec2 describe-vpcs','iam get-policy','iam get-policy-version','sts assume-role',
      'iam list-role-policies','iam list-attached-role-policies','iam get-role-policy','iam simulate-custom-policy',
      'organizations list-parents','organizations list-policies-for-target','organizations describe-policy']));
    // The owner's own identity documents are simulated for every operator permission before any session.
    const simulations=lanes.owner.filter(c=>c.action==='simulate-custom-policy');
    // Each case runs with the operator's own policy first, then the owner's documents.
    expect(simulations.length).toBe(44);
    expect(simulations.filter((_,i)=>i%2===0).every(s=>s.request.PolicyInputList.length===1&&JSON.parse(s.request.PolicyInputList[0]).Statement.length===21)).toBe(true);
    for(const s of simulations.filter((_,i)=>i%2===1)){
      expect(s.request.PolicyInputList.map(p=>JSON.parse(p).Statement[0].Sid??JSON.parse(p).Statement[0].Effect)).toEqual(['BlastRadiusGuard','Allow']);
      expect(s.request.ContextEntries).toContainEqual({ContextKeyName:'aws:PrincipalArn',ContextKeyValues:[f.aws.ownerRoleArn],ContextKeyType:'string'});
    }
    expect(calls.findLastIndex(c=>c.action==='simulate-custom-policy')).toBeLessThan(calls.findIndex(c=>c.action==='assume-role'));
    // The operator role is read once; its trust and policy are verified before any lane.
    expect(lanes.owner.filter(c=>c.request.RoleName===GATEWAY_CANARY_OPERATOR_ROLE_NAME).map(c=>c.action)).toEqual(['get-role','list-role-policies','list-attached-role-policies','get-role-policy']);
    expect(new Set(lanes.provision.map(c=>c.action))).toEqual(new Set(['create-stack','update-stack','delete-stack']));
    expect(lanes.bootstrap.every(c=>c.service==='iam')).toBe(true);
    expect(lanes.bootstrap.map(c=>c.action)).toEqual(expect.arrayContaining(['create-policy','delete-policy']));
    expect(lanes.observe.some(c=>MUTATIONS.includes(c.action))).toBe(false);
    const issued=Object.fromEntries(lanes.owner.filter(c=>c.action==='assume-role').map(c=>[c.request.RoleSessionName.split('-')[2],c.request]));
    expect(Object.keys(issued).sort()).toEqual(['bootstrap','observe','provision']);
    // Lanes assume the dedicated operator role, never the owner role itself.
    for(const r of Object.values(issued)){expect(r.RoleArn).toBe(OPERATOR_ARN);expect(r.RoleArn).not.toBe(f.aws.ownerRoleArn);expect(r.DurationSeconds).toBe(3600);}
    expect(f.broker.operator.roleArn).toBe(OPERATOR_ARN);
    expect(f.logs).toContain('organization policies: principal-neutral (2 scanned)');
    // The trust admits every owner session; the broker says so, and nothing more for a plain role session.
    expect(f.logs.filter(m=>m.startsWith('warning: '))).toEqual(['warning: '+gatewaySourceBrokerOwnerSessionWarnings({owner:f.broker.owner,sessionName:'owner-session'})[0]]);
    // Organizations reads happen as the owner, before any session.
    expect(calls.findLastIndex(c=>c.service==='organizations')).toBeLessThan(calls.findIndex(c=>c.action==='assume-role'));
    expect(issued.provision.PolicyArns).toEqual([{arn:expect.stringMatching(/^arn:aws:iam::123456789012:policy\/mem9-on-aws-gateway-check-session-[a-f0-9]{12}$/)}]);
    expect(issued.observe.Policy).toBe('<Policy>');expect(issued.observe.PolicyArns).toBeUndefined();
    // The simulation names both comparison rounds A1; the boundary mode selects behaviour.
    expect(f.services.invocations.map(i=>[i.phase,i.accessKeyId])).toEqual([['A1',OBSERVE_KEY],['B',OBSERVE_KEY],['A1',OBSERVE_KEY]]);
    const directory=f.broker.evidenceDirectory;
    for(const name of ['journal.jsonl','evidence.json','receipt.json','outcome.json','canary-outcome.json','requests.jsonl'])expect((await lstat(join(directory,name))).mode&0o777).toBe(0o600);
    expect((await lstat(directory)).mode&0o777).toBe(0o700);
    expect(existsSync(join(directory,'sessions'))).toBe(false);
    expect(await readJson(join(directory,'receipt.json'))).toEqual(f.broker.receipt);
    expect(await readJson(join(directory,'outcome.json'))).toMatchObject({status:'VERIFIED',reason:null,policyVersion:'v1',policyRevision:'r1',source:{commit:f.checkout.commit}});
    const journal=(await readFile(join(directory,'journal.jsonl'),'utf8')).trim().split('\n').map(l=>JSON.parse(l));
    expect(journal.filter(j=>j.source==='lifecycle').map(j=>j.event)).toEqual(expect.arrayContaining(['create-intent','cleanup-complete']));
    expect(journal.filter(j=>j.source==='session-policy').map(j=>j.event).at(-1)).toBe('session-policy-deleted');
    expect(JSON.stringify(journal)).not.toContain('s'.repeat(40));
    expect(await requestJournal(f)).toEqual([expect.objectContaining({status:'RECEIPT_ISSUED',policyHash:hash(reviewed),policyRevision:'r1'})]);
  },CANARY_MS);

  it('TC-GW-BROKER-002 never trusts the requested document: request, live and contract must all agree',async test=>{
    const f=await setup(test,{maxRequests:3});
    const drifted=structuredClone(reviewed);drifted.Statement.push({Effect:'Deny',Action:'sns:Publish',Resource:'*'});
    await writeFile(f.liveBoundaryPath,JSON.stringify(drifted));
    // The live boundary differs from the reviewed request.
    await expect(request(f)).rejects.toThrow(/GatewayRuntimeSourceRejected/);
    // A request equal to the (drifted) live document is not the reviewed contract.
    expect((await raw(f.broker.socketPath,frame(verifyRequest(drifted)))).status).toBe(1);
    // The reviewed document at a policy version other than the live default.
    await writeFile(f.liveBoundaryPath,JSON.stringify(reviewed));
    await expect(request(f,{policyVersion:'v2'})).rejects.toThrow(/GatewayRuntimeSourceRejected/);
    expect((await requestJournal(f)).map(r=>r.reason)).toEqual(['GatewaySourceBrokerLiveDocumentMismatch','GatewaySourceBrokerRequestedDocument','GatewaySourceBrokerLiveVersionMismatch']);
    expect((await f.broker.closed).requests.map(r=>r.status)).toEqual(['FAILED','FAILED','FAILED']);
  },CANARY_MS);

  it('TC-GW-BROKER-003 checks the request against the owner account and region, and normalizes only the revision Sid',()=>{
    const ok=parseGatewaySourceBrokerRequest(frame(verifyRequest(reviewed)).subarray(4)),scope={accountId:contract.accountId,applicationRegion:contract.applicationRegion};
    expect(gatewaySourceBrokerContract(ok,scope).contract).toEqual(contract);
    expect(()=>gatewaySourceBrokerContract(ok,{...scope,accountId:FOREIGN_ACCOUNT})).toThrow(/RequestedDocument/);
    expect(()=>gatewaySourceBrokerContract({...ok,region:'us-west-2'},scope)).toThrow(/RequestedRegion/);
    const later=expectedGatewayBoundaryPolicyDocument({...contract,policyRevision:'r17'});
    expect(gatewaySourceBrokerContract({...ok,document:later},scope).contract.policyRevision).toBe('r17');
    const two=structuredClone(later);two.Statement.push({Sid:'Gr18',Effect:'Deny',Action:'*',Resource:'*'});
    expect(()=>gatewaySourceBrokerContract({...ok,document:two},scope)).toThrow(/RequestedRevision/);
    expect(gatewayBoundaryStatementsHash(later)).toBe(gatewayBoundaryStatementsHash(reviewed));
    expect(hash(later)).not.toBe(hash(reviewed));
    const changed=structuredClone(later);changed.Statement.at(-1).Action='ec2:Describe*';
    expect(gatewayBoundaryStatementsHash(changed)).not.toBe(gatewayBoundaryStatementsHash(reviewed));
    expect(()=>gatewayBoundaryStatementsHash(two)).toThrow(/RequestedRevision/);
    // Only the Gr<rev> Sid is normalized: the rest of that statement still counts.
    expect(later.Statement[1].Sid).toBe('Gr17');
    for(const mutate of [s=>{s.NotAction=s.NotAction.slice(1);},s=>{s.NotAction=[...s.NotAction,'sns:Publish'];},s=>{s.Effect='Allow';},s=>{s.Resource='arn:aws:s3:::*';},s=>{s.Condition={Bool:{'aws:SecureTransport':'true'}};}]){
      const copy=structuredClone(later);mutate(copy.Statement[1]);
      expect(copy.Statement[1].Sid).toBe('Gr17');
      expect(gatewayBoundaryStatementsHash(copy)).not.toBe(gatewayBoundaryStatementsHash(later));
    }
  });

  it('TC-GW-BROKER-018 issues a receipt for the verified statements at a later revision and version, after a rewrite',async test=>{
    const f=await setup(test);
    const later=expectedGatewayBoundaryPolicyDocument({...contract,policyRevision:'r17'});
    await writeFile(f.liveBoundaryPath,JSON.stringify(later));f.aws.setLiveVersion('v2');
    const receipt=await request(f,{boundary:later,contract:{...contract,policyRevision:'r17'},policyVersion:'v2'});
    expect(receipt).toEqual({...f.broker.receipt,policyHash:hash(later),policyVersion:'v2'});
    expect(receipt.evidenceHash).toBe(f.broker.receipt.evidenceHash);
  },CANARY_MS);

  it('TC-GW-BROKER-019 refuses to start when the live boundary is not the reviewed document, before any session',async test=>{
    const drifted=structuredClone(reviewed);drifted.Statement.push({Effect:'Deny',Action:'sns:Publish',Resource:'*'});
    const f=await failedStart(test,{live:drifted});
    expect(f.error.message).toBe('GatewaySourceBrokerLiveNotReviewed');expect(f.error.held).toBe(false);
    expect(actions(f).some(a=>a==='assume-role'||MUTATIONS.includes(a))).toBe(false);
    expect(f.logs.some(m=>m.includes('canary FAILED (GatewaySourceBrokerLiveNotReviewed)'))).toBe(true);
  },CANARY_MS);

  it.for(['unexpected-B','invoke-transport'])('TC-GW-BROKER-004 publishes nothing when the startup lifecycle fails (%s), and still closes cleanup',async(defect,test)=>{
    const f=await failedStart(test,{defect});
    expect(f.error.held).toBe(false);
    expect(f.aws.state().deleted).toBe(true);expect(f.aws.state().sessionPolicies).toEqual({});
    const [directory]=f.directories;
    expect(existsSync(join(directory,'receipt.json'))).toBe(false);expect(existsSync(join(directory,'evidence.json'))).toBe(false);
    const outcome=await readJson(join(directory,'canary-outcome.json'));
    expect(outcome.status).toBe('FAILED');expect(outcome.lifecycle.status).toBe('HELD');expect(outcome.lifecycle.cleanupComplete).toBe(true);
    expect(outcome.sessionPolicy.status).toBe('CLOSED');
  },CANARY_MS);

  it('TC-GW-BROKER-005 fails before any mutation when the owner role cannot issue its scoped sessions',async test=>{
    const f=await failedStart(test,{faults:{trustDenied:true}});
    expect(actions(f).some(a=>MUTATIONS.includes(a))).toBe(false);
  },CANARY_MS);

  it('TC-GW-BROKER-006 publishes nothing when the live boundary version changes during the canary',async test=>{
    const f=await failedStart(test,{faults:{liveVersionAfterCanary:'v2'}});
    expect(f.error.message).toBe('GatewaySourceBrokerBoundaryChangedDuringCanary');
    expect(existsSync(join(f.directories[0],'receipt.json'))).toBe(false);
  },CANARY_MS);

  it('TC-GW-BROKER-007 publishes a 0600 socket in a 0700 directory and removes both at the request limit',async test=>{
    const f=await setup(test,{maxRequests:1});
    const socket=await lstat(f.broker.socketPath),parent=await lstat(dirname(f.broker.socketPath));
    expect(socket.isSocket()).toBe(true);expect(socket.mode&0o777).toBe(0o600);expect(socket.uid).toBe(process.getuid());
    expect(parent.mode&0o777).toBe(0o700);expect(parent.uid).toBe(process.getuid());
    await request(f);
    expect(await f.broker.closed).toEqual({requests:[{id:expect.stringMatching(/^[a-f0-9]{32}$/),status:'RECEIPT_ISSUED'}]});
    expect(existsSync(f.broker.socketPath)).toBe(false);expect(existsSync(dirname(f.broker.socketPath))).toBe(false);
  },CANARY_MS);

  it('TC-GW-BROKER-008 stops accepting at its deadline',async test=>{
    const f=await setup(test,{deadlineMs:200});
    expect(await f.broker.closed).toEqual({requests:[]});
    expect(existsSync(f.broker.socketPath)).toBe(false);
    await expect(request(f)).rejects.toThrow();
  },CANARY_MS);

  it('TC-GW-BROKER-009 frames exactly one request: oversize, trailing, malformed and concurrent connections get no receipt',async test=>{
    const f=await setup(test);f.aws.setFaults({delayIdentityMs:1500});
    const huge=Buffer.alloc(8);huge.writeUInt32BE(16385);
    expect(await raw(f.broker.socketPath,huge)).toBe(null);
    expect(await raw(f.broker.socketPath,Buffer.concat([frame(verifyRequest(reviewed)),Buffer.from('x')]))).toBe(null);
    expect(await raw(f.broker.socketPath,frame({version:1,id:'d'.repeat(32),argv:['gateway-runtime','simulate-custom-policy']}))).toEqual({version:1,id:'d'.repeat(32),status:64,stdout:'',stderr:''});
    expect(await raw(f.broker.socketPath,frame({version:2,id:'d'.repeat(32),argv:[]}))).toBe(null);
    // One request in flight: a second connection is refused, not queued.
    const first=raw(f.broker.socketPath,frame(verifyRequest(reviewed,'v9')));
    await new Promise(resolve=>setTimeout(resolve,300));
    expect(await raw(f.broker.socketPath,frame(verifyRequest(reviewed)))).toBe(null);
    expect((await first).status).toBe(1);
  },CANARY_MS);

  it('TC-GW-BROKER-010 refuses a dirty checkout at start and a checkout changed under it per request',async test=>{
    const directory=await mkdtemp(join(tmpdir(),'gateway-broker-dirty-'));test.onTestFinished(()=>rm(directory,{recursive:true,force:true}));
    const checkout=createSyntheticBrokerCheckout(directory),aws=installFakeAwsCli({directory,liveBoundaryPath:join(directory,'absent.json')});
    await writeFile(join(checkout.root,'untracked.txt'),'synthetic');
    const start=()=>startGatewayRuntimeSourceBroker({repoRoot:checkout.root,awsExecutable:aws.awsExecutable,gitExecutable,evidenceRoot:join(directory,'evidence'),socketParent:tmpdir(),environment:{PATH:process.env.PATH}});
    await expect(start()).rejects.toThrow(/GatewaySourceBrokerDirtyCheckout/);
    expect(aws.calls()).toEqual([]);
    const f=await setup(test),before=f.aws.calls().length;
    await writeFile(join(f.checkout.root,'scripts/test-fixtures/gateway-runtime-canary/handler.cjs'),'exports.handler=async()=>({});\n');
    await expect(request(f)).rejects.toThrow(/GatewayRuntimeSourceRejected/);
    expect(f.aws.calls().slice(before)).toEqual([]);
    expect((await requestJournal(f)).map(r=>r.reason)).toEqual(['GatewaySourceBrokerDirtyCheckout']);
  },CANARY_MS);

  it('TC-GW-BROKER-011 the CLI refuses a dirty checkout before any AWS call and rejects invalid options',async test=>{
    const directory=await mkdtemp(join(tmpdir(),'gateway-broker-cli-'));test.onTestFinished(()=>rm(directory,{recursive:true,force:true}));
    const marker=join(directory,'aws-called');
    await writeFile(join(directory,'git'),`#!/bin/sh\nfor a in "$@"; do [ "$a" = status ] && { echo '?? synthetic-untracked'; exit 0; }; done\nexec ${gitExecutable} "$@"\n`);
    await writeFile(join(directory,'aws'),`#!/bin/sh\ntouch ${marker}\nexit 1\n`);
    await chmod(join(directory,'git'),0o755);await chmod(join(directory,'aws'),0o755);
    const run=args=>new Promise(resolve=>execFile(process.execPath,[join(here,'run-gateway-runtime-source-broker.mjs'),...args],
      {env:{PATH:`${directory}:${process.env.PATH}`,HOME:directory},timeout:20_000},(error,stdout,stderr)=>resolve({code:error?.code??0,stdout,stderr})));
    const dirty=await run(['--evidence-dir',join(directory,'evidence')]);
    expect(dirty.code).toBe(1);expect(dirty.stderr).toContain('GatewaySourceBrokerDirtyCheckout');expect(dirty.stdout).toBe('');
    expect(existsSync(marker)).toBe(false);
    for(const args of [['--max-requests','4'],['--deadline-minutes','0'],['--evidence-dir','relative'],['positional']])expect((await run(args)).code).toBe(2);
    expect((await run(['--help'])).stdout).toContain('--max-requests');
  },CANARY_MS);

  it('TC-GW-BROKER-013 an interrupt during the startup canary publishes nothing, and cleanup still closes stack and session policy',async test=>{
    const controller=new AbortController();let aws;
    const watch=(async()=>{
      while(!aws?.calls().some(c=>c.status==='CREATE_IN_PROGRESS'))await new Promise(resolve=>setTimeout(resolve,50));
      // Abort while the lifecycle waits between stack polls. An abort that kills
      // an in-flight CLI call may instead hold cleanup if the call cannot be joined.
      await new Promise(resolve=>setTimeout(resolve,1500));controller.abort();
    })();
    const f=await failedStart(test,{signal:controller.signal,faults:{createInProgressPolls:1},onFixture:x=>{aws=x.aws;}});
    await watch;
    expect(f.error.held).toBe(false);
    expect(aws.state().deleted).toBe(true);expect(aws.state().sessionPolicies).toEqual({});
    const outcome=await readJson(join(f.directories[0],'canary-outcome.json'));
    expect(outcome.lifecycle.cleanupComplete).toBe(true);expect(outcome.sessionPolicy.status).toBe('CLOSED');
    expect(existsSync(join(f.directories[0],'receipt.json'))).toBe(false);
  },CANARY_MS);

  it('TC-GW-BROKER-014 reports HELD, keeps the session policy and publishes nothing when stack cleanup cannot be confirmed',async test=>{
    const f=await failedStart(test,{faults:{deleteStackDenied:true}});
    expect(f.error.held).toBe(true);
    // The provisioning restriction is retained while canary resources may remain.
    expect(Object.keys(f.aws.state().sessionPolicies)).toHaveLength(1);
    const [directory]=f.directories,outcome=await readJson(join(directory,'canary-outcome.json'));
    expect(outcome.status).toBe('HELD');expect(outcome.lifecycle.cleanupComplete).toBe(false);
    expect(outcome.sessionPolicy).toMatchObject({status:'HELD',cleanupComplete:false});
    expect(existsSync(join(directory,'receipt.json'))).toBe(false);expect(existsSync(join(directory,'evidence.json'))).toBe(false);
    expect(existsSync(join(directory,'sessions'))).toBe(false);
    expect(f.logs.some(m=>m.includes('need owner review'))).toBe(true);
  },CANARY_MS);

  it('TC-GW-BROKER-015 a complete canary whose session policy cannot be deleted is HELD and publishes nothing',async test=>{
    const f=await failedStart(test,{faults:{deletePolicyDenied:true}});
    expect(f.error.held).toBe(true);
    const outcome=await readJson(join(f.directories[0],'canary-outcome.json'));
    expect(outcome.lifecycle).toMatchObject({status:'OBSERVATIONS_COMPLETE',cleanupComplete:true});
    expect(outcome.status).toBe('HELD');expect(outcome.reason).toBe('GatewayRuntimeCanarySessionCleanupHeld');
    expect(existsSync(join(f.directories[0],'receipt.json'))).toBe(false);
  },CANARY_MS);

  it('TC-GW-BROKER-016 owner credentials must be an unredirected assumed role, unchanged between requests',async test=>{
    for(const key of ['AWS_ENDPOINT_URL','AWS_ENDPOINT_URL_STS','AWS_ENDPOINT_URL_IAM'])expect(()=>gatewaySourceBrokerOwnerEnvironment({PATH:'/bin',[key]:'http://127.0.0.1:1'})).toThrow(/OwnerEndpointOverride/);
    expect(()=>gatewaySourceBrokerOwnerEnvironment({AWS_USE_FIPS_ENDPOINT:'true'})).toThrow(/OwnerEndpointOverride/);
    expect(gatewaySourceBrokerOwnerEnvironment({AWS_USE_FIPS_ENDPOINT:'false'}).AWS_IGNORE_CONFIGURED_ENDPOINT_URLS).toBe('true');
    const owner=arn=>resolveGatewaySourceBrokerOwner({call:async(env,service)=>service==='sts'?{Account:'123456789012',Arn:arn}:{Role:{RoleName:'operator',Arn:'arn:aws:iam::123456789012:role/operator'}},environment:{},directory:'/'});
    for(const arn of ['arn:aws:iam::123456789012:user/operator','arn:aws:iam::123456789012:root',`arn:aws:sts::${FOREIGN_ACCOUNT}:assumed-role/operator/s`])await expect(owner(arn)).rejects.toThrow(/OwnerIdentity/);
    await expect(owner('arn:aws:sts::123456789012:assumed-role/operator/session')).resolves.toEqual({accountId:'123456789012',roleName:'operator',roleArn:'arn:aws:iam::123456789012:role/operator'});
    const f=await setup(test),before=f.aws.calls().length;
    f.aws.setFaults({callerArn:'arn:aws:sts::123456789012:assumed-role/other-operator/session',callerRole:'other-operator'});
    await expect(request(f)).rejects.toThrow(/GatewayRuntimeSourceRejected/);
    expect((await requestJournal(f)).map(r=>r.reason)).toEqual(['GatewaySourceBrokerOwnerChanged']);
    expect(f.aws.calls().slice(before).map(c=>c.action)).toEqual(['get-caller-identity']);
  },CANARY_MS);

  it('TC-GW-BROKER-017 a new commit after start fails the request before any AWS read, and the CLI status reflects outcomes',async test=>{
    const f=await setup(test),before=f.aws.calls().length;
    execFileSync(gitExecutable,['-C',f.checkout.root,'commit','-q','--allow-empty','-m','later'],{env:{PATH:process.env.PATH,HOME:f.directory,GIT_AUTHOR_NAME:'s',GIT_AUTHOR_EMAIL:'s@example.com',GIT_COMMITTER_NAME:'s',GIT_COMMITTER_EMAIL:'s@example.com'}});
    await expect(request(f)).rejects.toThrow(/GatewayRuntimeSourceRejected/);
    expect(f.logs.some(m=>/FAILED \(GatewaySourceBrokerCheckoutChanged\)/.test(m))).toBe(true);
    expect(f.aws.calls().slice(before)).toEqual([]);
    expect(gatewaySourceBrokerExitCode([])).toBe(0);
    expect(gatewaySourceBrokerExitCode([{status:'RECEIPT_ISSUED'}])).toBe(0);
    expect(gatewaySourceBrokerExitCode([{status:'RECEIPT_ISSUED'},{status:'FAILED'}])).toBe(1);
    expect(gatewaySourceBrokerExitCode([{status:'FAILED'},{status:'HELD'}])).toBe(3);
  },CANARY_MS);

  it('TC-GW-BROKER-020 selects how lane sessions carry the CC_PROJECT/CC_USAGE tags the operator trust requires',()=>{
    const tags=[{Key:'Project',Value:'mem9-on-aws'},{Key:'usage',Value:'cc-mem9-on-aws'}],base={CC_PROJECT:'mem9-on-aws',CC_USAGE:'cc-mem9-on-aws'};
    expect(gatewaySourceBrokerSessionTags({})).toBe(null);
    expect(gatewaySourceBrokerSessionTags({CC_PROJECT:'',CC_USAGE:''})).toBe(null);
    expect(gatewaySourceBrokerSessionTags(base)).toEqual({mode:'transitive',tags});
    expect(gatewaySourceBrokerSessionTags({...base,GATEWAY_CANARY_SESSION_TAGS:'transitive'})).toEqual({mode:'transitive',tags});
    expect(gatewaySourceBrokerSessionTags({...base,GATEWAY_CANARY_SESSION_TAGS:'explicit'})).toEqual({mode:'explicit',tags});
    expect(gatewaySourceBrokerSessionTags({CC_PROJECT:'mem9-on-aws',CC_USAGE:'codex-mem9-on-aws'}).tags[1].Value).toBe('codex-mem9-on-aws');
    for(const environment of [{CC_PROJECT:'mem9-on-aws'},{CC_USAGE:'cc-mem9-on-aws'},{CC_PROJECT:'Mem9',CC_USAGE:'cc-Mem9'},{CC_PROJECT:'mem9-on-aws',CC_USAGE:'cc-other'},
      {CC_PROJECT:'mem9-on-aws',CC_USAGE:'ci-mem9-on-aws'},{CC_PROJECT:'a'.repeat(65),CC_USAGE:'cc-'+'a'.repeat(65)},
      {...base,GATEWAY_CANARY_SESSION_TAGS:'both'},{GATEWAY_CANARY_SESSION_TAGS:'explicit'},{GATEWAY_CANARY_SESSION_TAGS:'transitive'}])
      expect(()=>gatewaySourceBrokerSessionTags(environment)).toThrow(/SessionTags/);
  });

  // The local credential helper's chained session forwards these as transitive tags.
  const TRANSITIVE=[{Key:'usage',Value:'cc-mem9-on-aws'},{Key:'User',Value:'synthetic-user'},{Key:'Host',Value:'synthetic-host'},{Key:'Project',Value:'mem9-on-aws'}];
  const TAGGED={CC_PROJECT:'mem9-on-aws',CC_USAGE:'cc-mem9-on-aws'},TRUST_TAGS=[{Key:'Project',Value:'mem9-on-aws'},{Key:'usage',Value:'cc-mem9-on-aws'}];
  it('TC-GW-BROKER-020 transitive mode: a chained caller passes no explicit tags and its transitive tags satisfy the trust',async test=>{
    const f=await setup(test,{environment:TAGGED,faults:{requireSessionTags:TRUST_TAGS,callerTransitiveTags:TRANSITIVE}});
    const issued=f.aws.calls().filter(c=>c.action==='assume-role');
    expect(issued).toHaveLength(3);expect(issued.every(c=>c.request.Tags===undefined)).toBe(true);
    expect(f.logs).toContain('lane session tags: transitive (forwarded from the calling session)');
    expect((await request(f)).evidenceHash).toBe(f.broker.receipt.evidenceHash);
  },CANARY_MS);
  it('TC-GW-BROKER-020 explicit mode: tags are passed on each AssumeRole for a non-chained caller',async test=>{
    const f=await setup(test,{environment:{...TAGGED,GATEWAY_CANARY_SESSION_TAGS:'explicit'},faults:{requireSessionTags:TRUST_TAGS}});
    expect(f.aws.calls().filter(c=>c.action==='assume-role').map(c=>c.request.Tags)).toEqual([TRUST_TAGS,TRUST_TAGS,TRUST_TAGS]);
  },CANARY_MS);
  it.for([
    // Re-setting a transitive key is an STS conflict; the failing operation and code are visible.
    [{...TAGGED,GATEWAY_CANARY_SESSION_TAGS:'explicit'},{callerTransitiveTags:TRANSITIVE},'sts AssumeRole: InvalidParameterValue'],
    // A non-chained caller in transitive mode has no tags for the trust to match.
    [TAGGED,{},'sts AssumeRole: AccessDenied'],
  ])('TC-GW-BROKER-020 a tag mode that does not fit the caller fails at the first lane, naming the operation and error (%j)',async([environment,faults,detail],test)=>{
    const f=await failedStart(test,{environment,faults:{requireSessionTags:TRUST_TAGS,...faults}});
    expect(f.error.message).toBe('GatewaySourceBrokerAwsServiceError');expect(f.error.awsDetail).toBe(detail);
    expect(f.logs).toContain(`canary FAILED (GatewaySourceBrokerAwsServiceError; ${detail})`);
    const journal=(await readFile(join(f.directories[0],'journal.jsonl'),'utf8')).trim().split('\n').map(l=>JSON.parse(l));
    expect(journal.at(-1)).toMatchObject({event:'canary-complete',status:'FAILED',awsDetail:detail});
    // The detail is the operation and error code only: no message body, ARN or account.
    expect(JSON.stringify(journal.at(-1))).not.toMatch(/conflicts|not authorized|arn:aws|123456789012/);
    expect(f.aws.calls().some(c=>MUTATIONS.includes(c.action))).toBe(false);
  },CANARY_MS);
  it('TC-GW-BROKER-020 an operator trust that requires tags is refused without them, before any session',async test=>{
    const denied=await failedStart(test,{faults:{requireSessionTags:TRUST_TAGS}});
    expect(denied.error.message).toBe('GatewaySourceBrokerOperatorTrust');
    expect(denied.aws.calls().some(c=>c.action==='assume-role'||MUTATIONS.includes(c.action))).toBe(false);
  },CANARY_MS);

  it.for([
    [{operatorMissing:true},/GatewaySourceBroker(AwsServiceError|OperatorRole)/],
    [{operatorTrustOwner:'arn:aws:iam::123456789012:role/someone-else'},/^GatewaySourceBrokerOperatorTrust$/],
    [{operatorPolicyDrift:true},/^GatewaySourceBrokerOperatorPolicy$/],
    // The operator is administrator-equivalent: an owner lacking any of its permissions is refused.
    [{ownerDenies:['cloudformation:CreateStack']},/^GatewaySourceBrokerOwnerLacksOperatorPermission$/],
    [{ownerDenies:['kms:ScheduleKeyDeletion']},/^GatewaySourceBrokerOwnerLacksOperatorPermission$/],
    [{ownerNarrow:true},/^GatewaySourceBrokerOwnerLacksOperatorPermission$/],
    [{ownerBoundary:{Version:'2012-10-17',Statement:[{Effect:'Allow',NotAction:'iam:*',Resource:'*'}]}},/^GatewaySourceBrokerOwnerLacksOperatorPermission$/],
    [{ownerExtraPolicies:10},/^GatewaySourceBrokerOwnerPoliciesUnverifiable$/],
    [{ownerListTruncated:true},/^GatewaySourceBrokerOwnerPoliciesUnverifiable$/],
    [{ownerTagDeny:true},/^GatewaySourceBrokerOwnerLacksOperatorPermission$/],
    // A simulator or compiler drift in the operator's own decisions is refused, not skipped.
    [{operatorSimulationDeny:'cloudformation:CreateStack'},/^GatewaySourceBrokerOperatorSimulationDrift$/],
    [{orgOu:true,orgPrincipalScoped:{filter:'SERVICE_CONTROL_POLICY',content:{Version:'2012-10-17',Statement:[{Effect:'Deny',Action:'*',Resource:'*',Condition:{StringNotLike:{'aws:PrincipalArn':'arn:aws:iam::*:role/AWSReservedSSO_Admin*'}}}]}}},/^GatewaySourceBrokerOrgPolicyPrincipalScoped$/],
    [{orgPrincipalScoped:{filter:'RESOURCE_CONTROL_POLICY',content:{Version:'2012-10-17',Statement:[{Effect:'Deny',Principal:'*',Action:'s3:*',Resource:'*',Condition:{StringNotEquals:{'aws:PrincipalTag/team':'platform'}}}]}}},/^GatewaySourceBrokerOrgPolicyPrincipalScoped$/],
    ...['gateway-canary-operator-mem9-on-aws','mem9-on-aws-prod-Mem9ProxyFnRole-x','Mem9-On-Aws-x','github-actions-mem9-on-aws','github-actions-mem9-on-aws-prod'].map(name=>
      [{callerArn:`arn:aws:sts::123456789012:assumed-role/${name}/session`,callerRole:name},/^GatewaySourceBrokerOwnerRoleRefused$/]),
    // Path variants: only the role's path, not its name, is a CI-reachable prefix.
    ...[['mem9-on-aws-ops','Admin'],['github-actions-mem9-on-aws','x'],['ops/Mem9-On-Aws-team','Admin']].map(([callerPath,name])=>
      [{callerArn:`arn:aws:sts::123456789012:assumed-role/${name}/session`,callerRole:name,callerPath},/^GatewaySourceBrokerOwnerRoleRefused$/]),
  ])('TC-GW-BROKER-022 refuses to start unless the operator role trusts exactly this owner and holds exactly the lane union (%j)',async([faults,reason],test)=>{
    const f=await failedStart(test,{faults});
    expect(f.error.message).toMatch(reason);
    expect(f.aws.calls().some(c=>c.action==='assume-role'||MUTATIONS.includes(c.action))).toBe(false);
    expect(f.directories).toEqual([]);
  },CANARY_MS);

  it('TC-GW-BROKER-030 refuses to start without the Organizations acknowledgement, before any AWS call, and reports what it scanned',async test=>{
    const f=await failedStart(test,{environment:{GATEWAY_CANARY_ORG_POLICIES_PRINCIPAL_NEUTRAL:''}});
    expect(f.error.message).toBe('GatewaySourceBrokerOrgPoliciesNotAcknowledged');expect(f.aws.calls()).toEqual([]);
    const unreadable=await setup(test,{faults:{orgUnreadable:true}});
    expect(unreadable.logs).toContain('organization policies are not fully readable; relying on GATEWAY_CANARY_ORG_POLICIES_PRINCIPAL_NEUTRAL=true');
    expect((await request(unreadable)).policyHash).toBe(hash(reviewed));
  },CANARY_MS);

  it('TC-GW-BROKER-023 issues no receipt when the request journal cannot record it',async test=>{
    const f=await setup(test),directory=await mkdtemp(join(tmpdir(),'gateway-broker-journal-'));test.onTestFinished(()=>rm(directory,{recursive:true,force:true}));
    const handlerSource=await readFile(join(f.checkout.root,'scripts/test-fixtures/gateway-runtime-canary/handler.cjs'),'utf8');
    const appended=[],context=journal=>({call:createGatewaySourceBrokerAwsCli({awsExecutable:f.aws.awsExecutable,region:contract.applicationRegion}),
      ownerEnvironment:gatewaySourceBrokerOwnerEnvironment({PATH:process.env.PATH,HOME:f.directory}),
      source:{repoRoot:f.checkout.root,commit:f.checkout.commit,tree:f.checkout.tree,handlerSource},owner:f.broker.owner,region:contract.applicationRegion,
      repoRoot:f.checkout.root,gitExecutable,journal,directory});
    const verified={receipt:f.broker.receipt,statementsHash:gatewayBoundaryStatementsHash(reviewed)};
    const parsed=parseGatewaySourceBrokerRequest(frame(verifyRequest(reviewed)).subarray(4));
    await expect(answerGatewayRuntimeSourceRequest(context({append:async()=>{throw Error('synthetic disk full');}}),verified,parsed)).rejects.toThrow(/^GatewaySourceBrokerJournalWriteFailed$/);
    // Positive control: the same request with a working journal is answered and recorded first.
    const receipt=await answerGatewayRuntimeSourceRequest(context({append:async v=>{appended.push(v);}}),verified,parsed);
    expect(receipt.policyHash).toBe(hash(reviewed));
    expect(appended).toEqual([expect.objectContaining({status:'RECEIPT_ISSUED',policyHash:hash(reviewed)})]);
  },CANARY_MS);

  it('TC-GW-BROKER-024 the real CLI stops on SIGINT during the startup canary: cleanup completes, exit 1, no export line',async test=>{
    const directory=await mkdtemp(join(tmpdir(),'gateway-broker-signal-'));test.onTestFinished(()=>rm(directory,{recursive:true,force:true}));
    const region=await resolveApplicationRegion(),liveBoundaryPath=join(directory,'live-boundary.json');
    await writeFile(liveBoundaryPath,JSON.stringify(expectedGatewayBoundaryPolicyDocument({...contract,applicationRegion:region})));
    const aws=installFakeAwsCli({directory,region,liveBoundaryPath,faults:{createInProgressPolls:1}});
    // This worktree may hold uncommitted work; report it clean. Every other git
    // call is real, so HEAD and the committed canary sources still bind.
    const gitDirectory=join(directory,'git-bin');await mkdir(gitDirectory,{mode:0o700});
    await writeFile(join(gitDirectory,'git'),`#!/bin/sh\nfor a in "$@"; do [ "$a" = status ] && exit 0; done\nexec ${gitExecutable} "$@"\n`);await chmod(join(gitDirectory,'git'),0o755);
    const child=spawn(process.execPath,[join(here,'run-gateway-runtime-source-broker.mjs'),'--evidence-dir',join(directory,'evidence'),'--max-requests','1'],
      {env:{PATH:`${gitDirectory}:${aws.bin}:${process.env.PATH}`,HOME:directory,TMPDIR:directory,GATEWAY_CANARY_ORG_POLICIES_PRINCIPAL_NEUTRAL:'true'},stdio:['ignore','pipe','pipe']});
    let stdout='',stderr='';child.stdout.on('data',c=>{stdout+=c;});child.stderr.on('data',c=>{stderr+=c;});
    const exited=new Promise(resolve=>child.once('close',code=>resolve(code)));
    while(!aws.calls().some(c=>c.status==='CREATE_IN_PROGRESS')){
      if(child.exitCode!==null)throw Error('broker exited early: '+stderr);
      await new Promise(resolve=>setTimeout(resolve,50));
    }
    await new Promise(resolve=>setTimeout(resolve,1500));child.kill('SIGINT');
    expect(await exited,stderr).toBe(1);
    expect(stdout).toBe('');expect(stderr).toContain('stopping');
    expect(aws.state().deleted).toBe(true);expect(aws.state().sessionPolicies).toEqual({});
    const [run]=await readdir(join(directory,'evidence'));
    const outcome=await readJson(join(directory,'evidence',run,'canary-outcome.json'));
    expect(outcome.lifecycle.cleanupComplete).toBe(true);expect(outcome.sessionPolicy.status).toBe('CLOSED');
    expect((await readdir(directory)).some(n=>n.startsWith('mem9-gw-'))).toBe(false);
  },CANARY_MS);

  // IAM returns a policy document with its own key order (and CloudFormation
  // serializes the template's order), not the order of the reviewed compiler.
  const reorder=v=>Array.isArray(v)?v.map(reorder):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).reverse().map(([k,x])=>[k,reorder(x)])):v;
  it('TC-GW-BROKER-033 accepts the live boundary in IAM key order: the plan is rendered from the reviewed document',async test=>{
    const live=reorder(reviewed);
    expect(JSON.stringify(live)).not.toBe(JSON.stringify(reviewed));expect(hash(live)).toBe(hash(reviewed));
    const f=await setup(test,{live});
    expect(f.broker.receipt.policyHash).toBe(hash(reviewed));
    expect((await request(f)).policyHash).toBe(hash(reviewed));
  },CANARY_MS);

  it('TC-GW-BROKER-033 a plan rendered from a reordered document is what the lifecycle rejects, and the difference is named',async()=>{
    const scope=compileGatewayRuntimeCanaryScope({accountId:contract.accountId,applicationRegion:contract.applicationRegion,verificationId:'abcdef012345',vpcId:'vpc-12345678',ownerRoleArn:OPERATOR_ARN});
    const handlerSource=await readFile(join(here,'test-fixtures/gateway-runtime-canary/handler.cjs'),'utf8');
    const good=renderGatewayRuntimeCanaryTemplate({scope,originalBoundary:reviewed,handlerSource});
    const bad=renderGatewayRuntimeCanaryTemplate({scope,originalBoundary:reorder(reviewed),handlerSource});
    expect(()=>verifyGatewayRuntimeCanaryPlan(good)).not.toThrow();
    expect(()=>verifyGatewayRuntimeCanaryPlan(bad)).toThrow(/^GatewayRuntimeCanaryPlanChanged$/);
    const detail=gatewayCanaryPlanDifference(bad,good);
    expect(detail).toMatch(/^differs: /);expect(detail).toContain('templateBody');expect(detail).toContain('Resources.ComparisonBoundary');
    expect(detail).not.toContain('scope');
    // The detail is plain names, so it survives the broker's redaction.
    expect(gatewaySourceBrokerDetail({detail})).toBe(detail);
    expect(gatewaySourceBrokerDetail({detail:'arn:aws:iam::123456789012:role/x'})).toBe(null);
    expect(gatewayCanaryPlanDifference(good,good)).toBe('differs: ');
  });

  it('TC-GW-BROKER-035 warns that the operator trust admits any owner session, and flags Identity Center and federated sessions',async test=>{
    const plain=gatewaySourceBrokerOwnerSessionWarnings({owner:{roleName:'operator',roleArn:'arn:aws:iam::123456789012:role/operators/operator'},sessionName:'cli'});
    expect(plain).toHaveLength(1);expect(plain[0]).toContain('equivalent to an unrestricted session of the owner role');
    expect(plain[0]).toContain('never grant a narrowed owner session sts:AssumeRole or sts:TagSession');
    const sso=gatewaySourceBrokerOwnerSessionWarnings({owner:{roleName:'AWSReservedSSO_Admin_0123456789abcdef',
      roleArn:'arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_0123456789abcdef'},sessionName:'admin@example.com'});
    expect(sso).toHaveLength(3);expect(sso[1]).toContain('IAM Identity Center');expect(sso[2]).toContain('looks federated');
    // Through the broker: the warnings are logged at start, before the operator check runs.
    const name='AWSReservedSSO_Admin_0123456789abcdef';
    const f=await failedStart(test,{faults:{callerArn:`arn:aws:sts::123456789012:assumed-role/${name}/admin@example.com`,callerRole:name,callerPath:'aws-reserved/sso.amazonaws.com'}});
    expect(f.logs.filter(m=>m.startsWith('warning: '))).toHaveLength(3);
    expect(f.error.message).toBe('GatewaySourceBrokerOperatorTrust');
  },CANARY_MS);
});
