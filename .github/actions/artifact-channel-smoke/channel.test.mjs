import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,rm,readdir,writeFile,readFile,stat,unlink,chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import archiver from 'archiver';
import {BRANCH,WORKFLOW,LIMITS,bindingFor,statusFor,artifactName,runChannel,hash,selectionFor,scopeHashFor,readWinner,CHANNEL_SCOPE} from './channel.mjs';
import {ownerArguments,ownerStatus} from './owner.mjs';
import {ownerChoice,readClaimZip} from './owner-choice.mjs';

// Synthetic local test responses only. No GitHub/S3 channel acceptance is
// fabricated by these tests; the real manual branch experiment remains required.
const sha=b=>createHash('sha256').update(b).digest('hex');
const deferred=()=>{let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};};
async function zip(payload,{name='claim.json',extra=false,level=0}={}){
 const z=archiver.create('zip',{zlib:{level}}),chunks=[];
 const done=new Promise((resolve,reject)=>{z.on('data',c=>chunks.push(c));z.on('error',reject);z.on('end',()=>resolve(Buffer.concat(chunks)));});
 z.append(Buffer.from(payload),{name,date:new Date(1700000000000),mode:0o100600});if(extra)z.append('extra',{name:'extra.json'});await z.finalize();return done;
}
async function fixture(t){
 const root=await mkdtemp(join(tmpdir(),'winner-channel-test-'));t.after(()=>rm(root,{recursive:true,force:true}));const now=Date.now();
 const request={repository:'example/repository',runId:77,runAttempt:1,challenge:'a'.repeat(64)},config={...request,initiatingActorId:42},revision='b'.repeat(40),tree='c'.repeat(40);
 const run={id:77,run_attempt:1,event:'workflow_dispatch',head_branch:BRANCH,path:WORKFLOW,repository:{full_name:request.repository},status:'in_progress',actor:{id:42},head_sha:revision,created_at:new Date(now-10000).toISOString()},commit={sha:revision,tree:{sha:tree},parents:[{sha:'d'.repeat(40)}]};
 const binding=bindingFor(config,run,commit),initial={id:1,creator:{id:42},url:`https://api.github.com/repos/${request.repository}/statuses/${revision}`,...statusFor(binding)};
 const env={GITHUB_ACTIONS:'true',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_REF:'refs/heads/'+BRANCH,GITHUB_SERVER_URL:'https://github.com',GITHUB_API_URL:'https://api.github.com',RUNNER_ENVIRONMENT:'github-hosted',GITHUB_REPOSITORY:request.repository,GITHUB_RUN_ID:'77',GITHUB_RUN_ATTEMPT:'1',GITHUB_ACTOR_ID:'42',GITHUB_SHA:revision,GITHUB_WORKFLOW_SHA:revision,RUNNER_TEMP:root,ACTIONS_RUNTIME_TOKEN:'synthetic',ACTIONS_RESULTS_URL:'https://results-receiver.actions.githubusercontent.com'};
 const stateRoot=join(root,'private'),journal=join(stateRoot,'choice-journal'),stateFile=join(stateRoot,'state.local.json');await mkdir(stateRoot,{mode:0o700});await mkdir(journal,{mode:0o700});const st=await stat(journal);await writeFile(stateFile,JSON.stringify({version:1,kind:'synthetic-channel-owner-state',directoryIdentity:{dev:String(st.dev),ino:String(st.ino)}}),{mode:0o600,flag:'wx'});
 const f={root,journal,stateFile,request,config,binding,run,commit,env,now:()=>now,reads:[],posts:[],diagnostics:[],uploads:[],objects:new Map(),statuses:[initial],ready:deferred(),winner:deferred(),postError:false};
 f.api=async(path,payload)=>{
  f.reads.push(path);
  if(payload){f.posts.push(structuredClone(payload));if(f.postError)throw Error('synthetic network unknown');const status={id:f.statuses.length+1,creator:{id:42},url:'https://api.github.com/'+path,...payload};f.statuses.push(status);if(payload.description.startsWith('winner:'))f.winner.resolve();return status;}
  if(path==='user')return {id:42};
  if(path.includes('/statuses?'))return structuredClone(f.statuses);
  if(path.includes('/git/commits/'))return structuredClone(commit);
  if(path.includes('/jobs?'))return {total_count:2,jobs:[{id:101,name:'Contender A',run_id:77,head_sha:revision,status:'in_progress'},{id:102,name:'Contender B',run_id:77,head_sha:revision,status:'in_progress'}]};
  if(path.includes('/artifacts?'))return {total_count:f.objects.size,artifacts:[...f.objects.values()].map(x=>structuredClone(x.metadata))};
  const m=/\/actions\/artifacts\/([0-9]+)$/.exec(path);if(m){const x=f.objects.get(Number(m[1]));if(!x)throw Error('synthetic missing artifact');return structuredClone(x.metadata);}
  if(path.endsWith('/actions/runs/77/attempts/1'))return structuredClone(run);throw Error('Unexpected synthetic API path');
 };
 f.checkout=async()=>({revision,tree,branch:BRANCH,clean:true});
 f.download=async(...args)=>{const id=args.at(-1),x=f.objects.get(id);if(!x)throw Error('missing synthetic artifact');return Buffer.from(x.raw);};
 f.add=async(contender,payload,options)=>{
  const raw=await zip(payload,options),id=contender==='a'?502:501;
  const metadata={id,name:artifactName(binding),size_in_bytes:raw.length,digest:'sha256:'+sha(raw),expired:false,created_at:new Date(now).toISOString(),expires_at:new Date(now+86400000).toISOString(),workflow_run:{id:77,head_sha:revision,head_branch:BRANCH}};
  f.objects.set(id,{raw,metadata});if(f.objects.size===2)f.ready.resolve();return {id,size:raw.length,digest:sha(raw)};
 };
 f.seed=async()=>{for(const [who,nonce] of [['a','1'.repeat(64)],['b','2'.repeat(64)]])await f.add(who,JSON.stringify({nonce,scopeHash:scopeHashFor(binding)}));};
 f.execute=(contender,overrides={})=>runChannel({config,contender,env:{...env,GITHUB_JOB:'contender_'+contender}},{api:f.api,checkout:f.checkout,artifactClient:async()=>({uploadArtifact:async(name,files,directory,opts)=>{assert.equal(name,artifactName(binding));assert.deepEqual(opts,{retentionDays:2,compressionLevel:0,skipArchive:false});const payload=await readFile(files[0],'utf8');f.uploads.push({contender,name,payload});return f.add(contender,payload);}}),recordDiagnostic:async d=>f.diagnostics.push(d),now:f.now,sleep:async()=>f.winner.promise,...overrides});
 f.choice=mode=>ownerChoice({mode,binding,stateFile},{api:f.api,download:f.download,check:()=>{},now:f.now,sleep:async()=>{}});
 f.owner=mode=>ownerStatus({mode,revision,request,...(mode.startsWith('choice')?{stateFile}:{})},{api:f.api,download:f.download,checkout:f.checkout,now:f.now,sleep:async()=>{}});
 return f;
}

test('two original processes upload same name; only durable owner-selected claim reaches simulated marker',async t=>{
 const f=await fixture(t),a=f.execute('a'),b=f.execute('b');await f.ready.promise;
 const prepared=await f.owner('choiceprepare');assert.equal(f.posts.length,0);assert.equal((await readdir(f.journal)).length,2);
 const announced=await f.owner('choicepublish');assert.equal(prepared.choiceHash,announced.choiceHash);
 const results=await Promise.all([a,b]);assert.deepEqual(results.map(r=>r.AWS_SIMULATED_MARKER),[0,1]);assert.equal(results[1].candidateHash,announced.choiceHash);assert.equal(results[0].winnerHash,announced.choiceHash);
 assert.equal(f.uploads.length,2);assert.equal(new Set(f.uploads.map(x=>x.name)).size,1);assert.notEqual(JSON.parse(f.uploads[0].payload).nonce,JSON.parse(f.uploads[1].payload).nonce);
 for(const result of [...results,...f.diagnostics]){const text=JSON.stringify(result);assert(!text.includes('nonce')&&!text.includes('artifactId')&&!text.includes('private/'));}
 assert(!Object.keys(results[0]).includes('capability'));
 const oldPosts=f.posts.length;await f.owner('choiceprepare');await f.owner('choicepublish');assert.equal(f.posts.length,oldPosts);
 for(const name of await readdir(f.journal))assert.equal((await stat(join(f.journal,name))).mode&511,0o600);
});
test('oldest timestamp precedes numeric artifact-ID tie breaker',async t=>{const f=await fixture(t);await f.seed();f.objects.get(502).metadata.created_at=new Date(f.now()-1000).toISOString();const x=await f.choice('choiceprepare');const payload=readClaimZip(f.objects.get(502).raw,f.binding);assert.equal(x.choiceHash,hash(selectionFor(f.binding,{...payload,artifactId:502,artifactDigest:sha(f.objects.get(502).raw)}).claim));});
test('choice is create-once across concurrent owner processes',async t=>{const f=await fixture(t);await f.seed();const results=await Promise.allSettled([f.choice('choiceprepare'),f.choice('choiceprepare')]);assert(results.some(x=>x.status==='fulfilled'));assert.equal((await readdir(f.journal)).filter(x=>x.endsWith('-record.json')).length,1);assert.equal(f.posts.length,0);});
test('missing initial owner announcement prevents choosing or publishing a winner',async t=>{const f=await fixture(t);await f.seed();f.statuses=[];await assert.rejects(f.owner('choiceprepare'),/SyntheticInitialBindingRequired/);assert.deepEqual(await readdir(f.journal),[]);});
test('choicepublish never creates an unprepared choice',async t=>{const f=await fixture(t);await f.seed();await assert.rejects(f.choice('choicepublish'),/SyntheticChoiceNotPrepared/);assert.equal(f.posts.length,0);assert.deepEqual(await readdir(f.journal),[]);});
test('missing whole journal cannot be recreated after a winner was announced',async t=>{const f=await fixture(t);await f.seed();await f.choice('choiceprepare');await f.choice('choicepublish');for(const name of await readdir(f.journal))await unlink(join(f.journal,name));await assert.rejects(f.choice('choiceprepare'),/SyntheticChoiceHistoryMissing/);assert.deepEqual(await readdir(f.journal),[]);assert.equal(f.posts.length,1);});
test('late/new inbox does not cause re-election',async t=>{const f=await fixture(t);await f.seed();const before=await f.choice('choiceprepare');f.objects.set(499,{...f.objects.get(502),metadata:{...f.objects.get(502).metadata,id:499,created_at:new Date(f.now()-2000).toISOString()}});const after=await f.choice('choiceprepare');assert.equal(before.choiceHash,after.choiceHash);});
for(const fault of ['missing-record','missing-start','corrupt-record','expiry-change','directory-recreated'])test('private history '+fault+' HOLDs without re-creating choice',async t=>{
 const f=await fixture(t);await f.seed();await f.choice('choiceprepare');const names=await readdir(f.journal),record=join(f.journal,names.find(n=>n.endsWith('-record.json'))),start=join(f.journal,names.find(n=>n.endsWith('-start.json')));
 if(fault==='missing-record')await unlink(record);else if(fault==='missing-start')await unlink(start);else if(fault==='corrupt-record')await writeFile(record,'{"success":true}\n');else if(fault==='expiry-change'){const x=JSON.parse(await readFile(record));x.selection.claim.expiresMs++;await writeFile(record,JSON.stringify(x));}else{await rm(f.journal,{recursive:true});await mkdir(f.journal,{mode:0o700});}
 await assert.rejects(f.choice('choiceprepare'));assert.equal(f.posts.length,0);
});
for(const fault of ['missing','permissive'])test('owner state reference '+fault+' is not initialized or repaired',async t=>{const f=await fixture(t);if(fault==='missing')await unlink(f.stateFile);else await chmod(f.stateFile,0o644);await assert.rejects(f.choice('choiceprepare'));assert.deepEqual(await readdir(f.journal),[]);});
test('selected missing/different artifact HOLDs without choosing the other inbox',async t=>{for(const change of ['missing','digest']){const f=await fixture(t);await f.seed();await f.choice('choiceprepare');if(change==='missing')f.objects.delete(501);else f.objects.get(501).metadata.digest='sha256:'+'f'.repeat(64);await assert.rejects(f.choice('choicepublish'));assert.equal(f.posts.length,0);}});
test('unknown announcements consume two durable attempts then HOLD, always same winner',async t=>{const f=await fixture(t);await f.seed();await f.choice('choiceprepare');f.postError=true;await assert.rejects(f.choice('choicepublish'));await assert.rejects(f.choice('choicepublish'));await assert.rejects(f.choice('choicepublish'),/SyntheticAnnouncementLimit/);assert.equal(f.posts.length,2);assert.deepEqual(f.posts[0],f.posts[1]);assert.equal((await readdir(f.journal)).filter(n=>n.includes('-announce-')).length,2);});
test('conflicting owner winner history cannot rebind a local choice',async t=>{const f=await fixture(t);await f.seed();await f.choice('choiceprepare');const upload={...readClaimZip(f.objects.get(502).raw,f.binding),artifactId:502,artifactDigest:sha(f.objects.get(502).raw)},wrong=selectionFor(f.binding,upload);f.statuses.push({id:2,creator:{id:42},url:'https://api.github.com/'+wrong.announcement.path,...wrong.announcement.payload});await assert.rejects(f.choice('choicepublish'),/SyntheticWinnerConflict/);assert.equal(f.posts.length,0);});
test('selection expiry is fixed, regardless of time of observation/publication',async t=>{const f=await fixture(t);await f.seed();const x=await f.choice('choiceprepare'),files=await readdir(f.journal),r=JSON.parse(await readFile(join(f.journal,files.find(n=>n.endsWith('-record.json')))));assert.equal(r.selection.claim.expiresMs,f.binding.notAfter);assert.equal(x.choiceHash,hash(r.selection.claim));});
test('winner read rejects conflicts, wrong target, unknown fields in upload formatter and incomplete pages',async t=>{
 const f=await fixture(t);await f.seed();const a=selectionFor(f.binding,{...readClaimZip(f.objects.get(501).raw,f.binding),artifactId:501,artifactDigest:sha(f.objects.get(501).raw)}),s={id:2,creator:{id:42},url:'https://api.github.com/'+a.announcement.path,...a.announcement.payload};
 await assert.rejects(readWinner(f.binding,async()=>[s,{...s,id:3,description:'winner:'+'f'.repeat(64)}],()=>{}),/SyntheticWinnerConflict/);
 await assert.rejects(readWinner(f.binding,async()=>[{...s,target_url:'https://example.com'}],()=>{}),/SyntheticWinnerStatus/);
 assert.throws(()=>selectionFor(f.binding,{...a.claim,success:true}));
 let seq=1;await assert.rejects(readWinner(f.binding,async()=>Array.from({length:100},()=>({...s,id:seq++,context:'other'})),()=>{}),/SyntheticStatusPaginationLimit/);
});
for(const change of ['wrong-scope','unknown-key','duplicate-key','extra-file','oversized','wrong-name','bad-crc'])test('single ZIP claim rejects '+change,async t=>{
 const f=await fixture(t),payload=JSON.stringify({nonce:'1'.repeat(64),scopeHash:scopeHashFor(f.binding)});let raw;
 if(change==='wrong-scope')raw=await zip(payload.replace(scopeHashFor(f.binding),'f'.repeat(64)));
 else if(change==='unknown-key')raw=await zip(payload.slice(0,-1)+',"success":true}');
 else if(change==='duplicate-key')raw=await zip(payload.slice(0,-1)+',"nonce":"'+'2'.repeat(64)+'"}');
 else if(change==='extra-file')raw=await zip(payload,{extra:true});
 else if(change==='oversized')raw=await zip('x'.repeat(2048));
 else if(change==='wrong-name')raw=await zip(payload,{name:'other.json'});
 else {raw=await zip(payload);raw=Buffer.from(raw);raw[raw.indexOf(Buffer.from('"nonce"'))+10]^=1;}
 assert.throws(()=>readClaimZip(raw,f.binding));
});
test('actual pinned SDK ZIP producer is accepted without extracting files',async t=>{
 const f=await fixture(t),file=join(f.root,'claim.json'),payload={nonce:'1'.repeat(64),scopeHash:scopeHashFor(f.binding)};await writeFile(file,JSON.stringify(payload),{mode:0o600});
 const {getUploadZipSpecification}=await import('./node_modules/@actions/artifact/lib/internal/upload/upload-zip-specification.js'),{createZipUploadStream}=await import('./node_modules/@actions/artifact/lib/internal/upload/zip.js');
 const stream=await createZipUploadStream(getUploadZipSpecification([file],f.root),0),chunks=[];for await(const chunk of stream)chunks.push(chunk);assert.deepEqual(readClaimZip(Buffer.concat(chunks),f.binding),payload);
});
test('deflated ordinary single-entry ZIP is bounded and accepted',async t=>{const f=await fixture(t),payload={nonce:'1'.repeat(64),scopeHash:scopeHashFor(f.binding)};assert.deepEqual(readClaimZip(await zip(JSON.stringify(payload),{level:6}),f.binding),payload);});
test('wrong metadata digest/expiry and identical nonces prevent local choice',async t=>{
 for(const fault of ['digest','expiry','nonce']){const f=await fixture(t);await f.seed();if(fault==='digest')f.objects.get(501).metadata.digest='sha256:'+'f'.repeat(64);else if(fault==='expiry')f.objects.get(501).metadata.expires_at=new Date(f.now()+1).toISOString();else await f.add('a',JSON.stringify({nonce:'2'.repeat(64),scopeHash:scopeHashFor(f.binding)}));await assert.rejects(f.choice('choiceprepare'));assert.deepEqual(await readdir(f.journal),[]);}
});
test('old receipt or caller nonce cannot recreate a process capability',async t=>{const f=await fixture(t);await assert.rejects(runChannel({config:f.config,contender:'a',env:{...f.env,GITHUB_JOB:'contender_a'},firstReceipt:{AWS_SIMULATED_MARKER:1}},{}));await assert.rejects(runChannel({config:{...f.config,nonce:'1'.repeat(64)},contender:'a',env:{...f.env,GITHUB_JOB:'contender_a'}},{}));});
test('an uploaded inbox without a winner status never reaches the simulated step',async t=>{const f=await fixture(t);await assert.rejects(f.execute('a',{sleep:async()=>{}}),/SyntheticAnnouncementMissing/);assert.equal(f.uploads.length,1);assert(f.diagnostics.every(d=>!Object.hasOwn(d,'AWS_SIMULATED_MARKER')));});
test('a new process with a fresh nonce cannot reuse a previously selected artifact identity',async t=>{const f=await fixture(t);await f.seed();await f.choice('choiceprepare');await f.choice('choicepublish');const result=await f.execute('b');assert.equal(result.AWS_SIMULATED_MARKER,0);assert.notEqual(result.candidateHash,result.winnerHash);});
test('wrong actor winner statuses are not accepted or used to select the owner',async t=>{const f=await fixture(t);await f.seed();const p=selectionFor(f.binding,{...readClaimZip(f.objects.get(501).raw,f.binding),artifactId:501,artifactDigest:sha(f.objects.get(501).raw)});assert.equal(await readWinner(f.binding,async()=>[{id:2,creator:{id:99},url:'https://api.github.com/'+p.announcement.path,...p.announcement.payload}],()=>{}),undefined);});
test('expired run binding stops both owner and contender without renewing expiry',async t=>{const f=await fixture(t);f.run.created_at=new Date(f.now()-LIMITS.windowMs-1).toISOString();await assert.rejects(f.execute('a'),/SyntheticDeadline/);await assert.rejects(f.owner('choiceprepare'),/SyntheticOwnerSource/);assert.equal(f.uploads.length,0);assert.equal(f.posts.length,0);assert.deepEqual(await readdir(f.journal),[]);});
test('owner must still be the actual initiating actor before creating local state',async t=>{const f=await fixture(t);const original=f.api;f.api=async(path,payload)=>path==='user'?{id:99}:original(path,payload);await assert.rejects(f.owner('choiceprepare'),/SyntheticOwnerActor/);assert.deepEqual(await readdir(f.journal),[]);});
test('owner CLI has explicit state-file only for choice modes, never token/body overrides',()=>{const base=['--repository','example/repository','--run-id','77','--run-attempt','1','--challenge','a'.repeat(64),'--revision','b'.repeat(40)];assert.equal(ownerArguments(['choiceprepare',...base,'--state-file','/private/state.local.json']).stateFile,'/private/state.local.json');assert.throws(()=>ownerArguments(['choicepublish',...base]));assert.throws(()=>ownerArguments(['publish',...base,'--state-file','/private/state.local.json']));assert.throws(()=>ownerArguments(['choicepublish',...base,'--token','secret']));});
test('workflow has parallel contenders and an explicit marker check; no cloud/write grants or static actor inputs',async()=>{
 const workflow=await readFile(new URL('../../workflows/reconcile-previews.yml',import.meta.url),'utf8'),action=await readFile(new URL('./action.yml',import.meta.url),'utf8');
 assert.match(workflow,/contender_a:/);assert.match(workflow,/contender_b:/);assert.match(workflow,/needs: \[contender_a, contender_b\]/);assert.doesNotMatch(workflow,/first_claim|duplicate_claim|id-token:|statuses: write|actions: write|configure-aws|secrets\.|GITHUB_ENV|owner_actor_id/);assert.match(action,/using: node24/);assert.doesNotMatch(action,/first-receipt:/);
});
