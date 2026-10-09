import {it,expect,afterEach} from 'vitest';
import {mkdtemp,mkdir,writeFile,readFile,symlink,link,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {parseSmokeArguments,parseSmokeLineage,extractSmokeCommitment,smokeArchiveConfig,smokeGuardRow,verifySmokePhaseBundle,findCiSmokeCheckpoint,main} from './verify-ci-smoke-isolation.mjs';
import {buildCiSmokePromotionRoutes} from './lib/ci-smoke-isolation.mjs';
import {readFileSync} from 'node:fs';
import {smokePrivateRead,smokePrivateWrite,smokeDirectory,removeSmokeDirectory} from './lib/ci-smoke-host.mjs';

const roots=[];afterEach(async()=>{for(const root of roots.splice(0))await rm(root,{recursive:true,force:true});});
const h='a'.repeat(64),g='b'.repeat(40),now=1800000000000;
const commitment=()=>({version:1,kind:'ci-smoke-private-commitment',runId:1,runAttempt:1,sourceRevision:g,sourceTree:g,buildJobId:2,smokeJobId:3,
 outputDigest:'sha256:'+h,arm64Digest:'sha256:'+'b'.repeat(64),configDigest:'sha256:'+'c'.repeat(64),resultHash:h,envelopeSha256:h,bytesLength:100});
it('requires fixed commands, routes, phases and argument sets',()=>{
 expect(parseSmokeArguments(['guard','--route','deploy-prod','--phase','preupdate','--step','deploy-prod/13'])).toEqual({mode:'guard',route:'deploy-prod',phase:'preupdate',step:'deploy-prod/13'});
 for(const args of [[],['shell'],['source'],['source','--route','foreign'],['source','--route','deploy-prod','--route','deploy-prod'],['guard','--route','deploy-prod','--phase','source'],['cleanup-smoke','--path','/tmp'],['target','--route','deploy-prod','--phase','future']])expect(()=>parseSmokeArguments(args)).toThrow();
});
it('rejects fabricated CI environment before any host operation',async()=>{
 await expect(main(['source','--route','deploy-prod'],{})).rejects.toThrow('CiSmokeHostIdentity');
});
it('keeps frozen origin and baseline identities explicit and closed',()=>{
 const value={originRevision:g,originTree:g,baselineRevision:g,baselineTree:g};expect(parseSmokeLineage(JSON.stringify(value))).toEqual(value);
 for(const v of [{...value,allow:true},{...value,originRevision:'main'},{originRevision:g}])expect(()=>parseSmokeLineage(JSON.stringify(v))).toThrow();
});
it('reads exactly one public-safe commitment, not echoed script text or a PASS flag',()=>{
 const c=commitment(),line='2026-10-08T00:00:00.0000000Z MEM9_CI_SMOKE_COMMITMENT '+JSON.stringify(c);
 expect(extractSmokeCommitment(line)).toEqual(c);
 for(const value of [line+'\n'+line,'echo MEM9_CI_SMOKE_COMMITMENT '+JSON.stringify(c),'MEM9_CI_SMOKE_COMMITMENT '+JSON.stringify({...c,account:'123456789012'}),'MEM9_CI_SMOKE_COMMITMENT {"passed":true}'])expect(()=>extractSmokeCommitment(value)).toThrow();
});
it('uses the existing expiring private prefix and an exact account/key mapping',()=>{
 const env={MEM9_CI_EVIDENCE_ROLE_ARN:'arn:aws:iam::123456789012:role/github-actions-mem9-on-aws-prod',AWS_REGION:'ap-northeast-1',MEM9_CI_EVIDENCE_KMS_KEY_ARN:'arn:aws:kms:ap-northeast-1:123456789012:key/11111111-1111-4111-8111-111111111111'};
 const c=smokeArchiveConfig(env,'pr-7',commitment());expect(c.key).toBe('decisions/pr-7/ci-smoke/1/1/'+h+'.json');expect(c.expectedBucketOwner).toBe('123456789012');
 expect(()=>smokeArchiveConfig({...env,MEM9_CI_EVIDENCE_KMS_KEY_ARN:undefined},'pr-7',commitment())).toThrow();
 expect(()=>smokeArchiveConfig({...env,AWS_REGION:'us-west-2'},'pr-7',commitment())).toThrow();
 expect(()=>smokeArchiveConfig(env,'pr-7/../prod',commitment())).toThrow();
});
it('binds local guards to one exact reviewed operation and phase',()=>{
 expect(smokeGuardRow({route:'deploy-prod',step:'deploy-prod/13',phase:'preupdate'}).name).toBe('Remove conflicting Pulumi installation');
 for(const input of [{route:'deploy-prod',step:'deploy-prod/8',phase:'preupdate'},{route:'deploy-prod',step:'deploy-prod/13',phase:'presst'},{route:'deploy-preview',step:'deploy-prod/13',phase:'preupdate'}])expect(()=>smokeGuardRow(input)).toThrow();
});
it('rejects absent, swapped and duplicate named checkpoint identities before acquisition',()=>{
 const baseline=JSON.parse(readFileSync(new URL('./fixtures/ci-smoke-baseline.json',import.meta.url),'utf8'));
 const built=buildCiSmokePromotionRoutes(baseline),workflow={jobs:built.jobs},action=built.actions['.github/actions/runtime-cutover/action.yml'];
 expect(findCiSmokeCheckpoint(workflow,action,{route:'deploy-prod',phase:'preupdate',checkpoint:'deploy-prod/9'})).toEqual({route:'deploy-prod',phase:'preupdate',checkpoint:'deploy-prod/9'});
 const child={route:'runtime-cutover-preview',phase:'preupdate',checkpoint:'runtime-cutover-preview/6/.github/actions/runtime-cutover/action.yml/2'};
 expect(findCiSmokeCheckpoint(workflow,action,child)).toEqual(child);
 const original=workflow.jobs['deploy-prod'].steps.find(s=>s.env?.MEM9_CI_SMOKE_CHECKPOINT==='deploy-prod/9');
 expect(original.uses).toBe('./.github/actions/ci-smoke-gate');
 for(const mutate of [
  step=>{step.with.phase='presst';},step=>{step.with.mode='source';},
  step=>{step.with.route='deploy-preview';},step=>{step.uses='./.github/actions/other';},
  step=>{step.run='node unrelated.mjs';},step=>{step.shell='bash';},
 ]){
  const changed=structuredClone(workflow);mutate(changed.jobs['deploy-prod'].steps.find(s=>s.env?.MEM9_CI_SMOKE_CHECKPOINT==='deploy-prod/9'));
  expect(()=>findCiSmokeCheckpoint(changed,action,{route:'deploy-prod',phase:'preupdate',checkpoint:'deploy-prod/9'})).toThrow();
 }
 for(const changed of [{route:'deploy-prod',phase:'preupdate'},{route:'deploy-prod',phase:'presst',checkpoint:'deploy-prod/9'},{...child,checkpoint:'runtime-cutover-prod/7/.github/actions/runtime-cutover/action.yml/2'}])expect(()=>findCiSmokeCheckpoint(workflow,action,changed)).toThrow();
 const duplicated=structuredClone(workflow),step=duplicated.jobs['deploy-prod'].steps.find(s=>s.env?.MEM9_CI_SMOKE_CHECKPOINT==='deploy-prod/9');duplicated.jobs['deploy-prod'].steps.push(step);
 expect(()=>findCiSmokeCheckpoint(duplicated,action,{route:'deploy-prod',phase:'preupdate',checkpoint:'deploy-prod/9'})).toThrow('CiSmokeCheckpointBinding');
});
function phaseBundle(){
 const data={version:3,expiresMs:now+10000},review={expiresMs:now+5000},proof={synthetic:'proof'},deploymentSource={synthetic:'deployment'};
 const phaseEvidence={phase:'preupdate',observedMs:now-1000,expiresMs:now+4000};
 return {kind:'image-security-nonroot-deployment-bundle',phase:'deployment',sourceReceiptHash:h,source:{checkout:{tree:g}},parameter:{Value:JSON.stringify(data),Version:2},proof,deploymentSource,phaseEvidence,operation:{authorization:{review}},
 phaseReceipt:{version:1,kind:'image-deployment-phase-receipt',phase:'preupdate',sourceReceiptHash:h,descriptorHash:hash(data),parameterVersion:2,proofHash:hash(proof),reviewHash:hash(review),deploymentSourceHash:hash(deploymentSource),phaseEvidenceHash:hash(phaseEvidence),observedMs:now-1000,expiresMs:now+4000}};
}
it('checks receipt joins locally without renewing the observation or authority window',()=>{
 const b=phaseBundle(),expected={sourceReceiptHash:h,phase:'preupdate',sourceTree:g,now,effect:'workload-mutation'};
 expect(verifySmokePhaseBundle(b,expected).observedMs).toBe(now-1000);
 for(const alter of [v=>{v.phaseReceipt.expiresMs=now;},v=>{v.phaseReceipt.expiresMs=now+6000;},v=>{v.phaseEvidence.phase='presst';v.phaseReceipt.phaseEvidenceHash=hash(v.phaseEvidence);},v=>{v.phaseReceipt.sourceReceiptHash='b'.repeat(64);},v=>{v.phaseReceipt.extra=true;},v=>{v.parameter.Version=3;}]){const value=phaseBundle();alter(value);expect(()=>verifySmokePhaseBundle(value,expected)).toThrow();}
});
it('creates owner-only evidence and refuses symlinks, hardlinks and unexpected cleanup entries',async()=>{
 const root=await mkdtemp(join(tmpdir(),'ci-smoke-host-'));roots.push(root);const env={RUNNER_TEMP:root},directory=await smokeDirectory(env,'mem9-ci-smoke-source',{create:true});
 const file=join(directory,'receipt.json');await smokePrivateWrite(file,{test:1});expect((await smokePrivateRead(file)).toString()).toBe('{"test":1}');
 const alias=join(root,'alias');await symlink(file,alias);await expect(smokePrivateRead(alias)).rejects.toThrow('CiSmokePrivatePath');
 const hardlink=join(root,'hardlink');await link(file,hardlink);await expect(smokePrivateRead(file)).rejects.toThrow('CiSmokePrivateFile');await rm(hardlink);
 await writeFile(join(directory,'unexpected'),'kept',{mode:0o600});await expect(removeSmokeDirectory(env,'mem9-ci-smoke-source')).rejects.toThrow('CiSmokeCleanupUnknownEntry');
 expect(await readFile(join(directory,'unexpected'),'utf8')).toBe('kept');
 expect(await readFile(file,'utf8')).toBe('{"test":1}');
});
it('retains a lost private Put result and its evidence during cleanup',async()=>{
 const root=await mkdtemp(join(tmpdir(),'ci-smoke-unknown-'));roots.push(root);const env={GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:'example/project',GITHUB_SHA:g,GITHUB_RUN_ID:'1',GITHUB_RUN_ATTEMPT:'1',RUNNER_TEMP:root};
 const directory=await smokeDirectory(env,'mem9-ci-smoke-state',{create:true});await smokePrivateWrite(join(directory,'put-intent.json'),{commitment:commitment()});
 await expect(main(['cleanup-smoke'],env)).rejects.toThrow('CiSmokePrivatePutUnresolved');
 expect(await readFile(join(directory,'put-intent.json'),'utf8')).toContain('ci-smoke-private-commitment');
});
