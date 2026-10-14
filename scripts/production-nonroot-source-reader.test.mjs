import {describe,it,expect} from 'vitest';
import {createHash} from 'node:crypto';
import {captureNonrootMainSource,createNonrootActualMainRecord} from './lib/production-nonroot-source-reader.mjs';
import {verifyNonrootActualMain} from './lib/production-nonroot-provenance.mjs';
import {nonrootHash} from './lib/production-nonroot-contracts.mjs';
const expected={repository:'example/project',candidateRevision:'a'.repeat(40),candidateTree:'b'.repeat(40),baseRevision:'c'.repeat(40),prNumber:7};
const main='d'.repeat(40),env={GITHUB_REPOSITORY:expected.repository,GITHUB_EVENT_NAME:'push',GITHUB_REF:'refs/heads/main',GITHUB_SHA:main,GITHUB_WORKFLOW_SHA:main,GITHUB_RUN_ID:'11',GITHUB_RUN_ATTEMPT:'1'};
function fixture({parents=[expected.baseRevision,expected.candidateRevision],mutate=()=>{},change=false}={}){
 const calls=[];let mains=0;
 return {calls,git:async args=>args[0]==='show'?[main,expected.candidateTree,parents.join(' ')].join('\n')+'\n':'',api:async path=>{
  calls.push(path);let value;
  if(path==='commits/main'){mains++;value={sha:change&&mains===2?'f'.repeat(40):main,commit:{tree:{sha:expected.candidateTree}}};}
  else if(path.startsWith('commits/'))value={sha:main,commit:{tree:{sha:expected.candidateTree}},parents:parents.map(sha=>({sha}))};
  else if(path.startsWith('pulls/'))value={number:7,state:'closed',merged:true,head:{sha:expected.candidateRevision,repo:{full_name:expected.repository}},base:{ref:'main'},merge_commit_sha:main};
  else value={id:11,run_attempt:1,event:'push',head_sha:main,head_repository:{full_name:expected.repository},path:'.github/workflows/infra-ci.yml'};
  mutate(path,value);return value;
 }};
}
describe('actual-main fixed source capture',()=>{
 it.each([[expected.baseRevision,expected.candidateRevision],[expected.baseRevision]])('joins actual merge/squash facts to the independent verifier: %j',async(...parents)=>{
  const f=fixture({parents}),source=await captureNonrootMainSource(f,env,expected),bytes=Buffer.from(JSON.stringify(source));
  const ref={bytesHash:createHash('sha256').update(bytes).digest('hex'),canonicalHash:nonrootHash(source),bytesLength:bytes.length};
  const record=createNonrootActualMainRecord(source,ref,expected);
  expect(await verifyNonrootActualMain(record,{expected,resolveJson:async()=>bytes,resolveBytes:async()=>{throw Error('unused');}})).toMatchObject({mainRevision:main,mainTree:expected.candidateTree});
 });
 it('rejects pull-request execution before any GitHub requests',async()=>{
  const f=fixture();await expect(captureNonrootMainSource(f,{...env,GITHUB_EVENT_NAME:'pull_request'},expected)).rejects.toThrow();expect(f.calls).toEqual([]);
 });
 it('rejects a moving main or an unreviewed parent',async()=>{
  await expect(captureNonrootMainSource(fixture({change:true}),env,expected)).rejects.toThrow();
  await expect(captureNonrootMainSource(fixture({parents:['f'.repeat(40)]}),env,expected)).rejects.toThrow();
 });
 it.each([
  ['pulls/',v=>{v.head.sha='f'.repeat(40);}],['pulls/',v=>{v.head.repo.full_name='foreign/project';}],
  ['actions/',v=>{v.run_attempt=2;}],['actions/',v=>{v.path='.github/workflows/unreviewed.yml';}],
  ['actions/',v=>{v.event='workflow_dispatch';}],['commits/'+main,v=>{v.commit.tree.sha='f'.repeat(40);}],
 ])('rejects inconsistent authenticated %s facts',async(prefix,mutate)=>{
  await expect(captureNonrootMainSource(fixture({mutate:(path,value)=>{if(path.startsWith(prefix))mutate(value);}}),env,expected)).rejects.toThrow();
 });
});
