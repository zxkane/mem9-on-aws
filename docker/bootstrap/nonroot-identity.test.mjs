import {describe,it,expect} from 'vitest';
import {inspectGuardIdentity,parseGuardJson,resolveGuardPurpose} from './nonroot-identity.mjs';

const status=(changes={})=>Object.entries({Pid:'17',PPid:'1',Uid:'1000\t1000\t1000\t1000',Gid:'1000\t1000\t1000\t1000',
 Groups:'1000',CapInh:'0000000000000000',CapPrm:'0000000000000000',CapEff:'0000000000000000',
 CapBnd:'0000000000000000',CapAmb:'0000000000000000',NoNewPrivs:'1',...changes}).map(([k,v])=>k+':\t'+v).join('\n')+'\n';

describe('guard process identity',()=>{
 it('requires all UID/GID positions, capability sets and NNP before dispatch',()=>{
  expect(inspectGuardIdentity(status(),17)).toMatchObject({pid:17,uid:[1000,1000,1000,1000],gid:[1000,1000,1000,1000],noNewPrivs:1});
  expect(inspectGuardIdentity(status({Groups:''}),17).groups).toEqual([]);
 });
 for(const key of ['Uid','Gid'])for(let n=0;n<4;n++)it('rejects root in '+key+' position '+n,()=>{
  const ids=[1000,1000,1000,1000];ids[n]=0;expect(()=>inspectGuardIdentity(status({[key]:ids.join(' ')}),17)).toThrow('NonrootIdentity');
 });
 for(const key of ['CapInh','CapPrm','CapEff','CapBnd','CapAmb'])it('rejects '+key+' even if effective capabilities are zero',()=>{
  expect(()=>inspectGuardIdentity(status({[key]:'0000000000000001'}),17)).toThrow('NonrootIdentity');
 });
 it('rejects NNP zero, foreign groups, duplicates, mismatched PID and missing evidence',()=>{
  for(const raw of [status({NoNewPrivs:'0'}),status({Groups:'1000 0'}),status({Groups:'1000 1000'}),status()+ 'Uid:\t1000 1000 1000 1000\n',status({Pid:'18'}),status().replace(/^CapAmb:.*\n/m,'')])
   expect(()=>inspectGuardIdentity(raw,17)).toThrow('NonrootIdentity');
 });
});

describe('guard structured input',()=>{
 it('accepts exact JSON serialization and rejects duplicate or unsafe values',()=>{
  expect(parseGuardJson('{"version":1,"items":["ok"]}\n',1024)).toEqual({version:1,items:['ok']});
  for(const raw of ['{"a":1,"a":2}','{"a":1,"\\u0061":2}','{"n":9007199254740992}','{"n":1e999}','{"__proto__":{}}','{"a":1}trailing'])
   expect(()=>parseGuardJson(raw,1024)).toThrow('NonrootInput');
  expect(()=>parseGuardJson(JSON.stringify({a:'x'.repeat(1024)}),1024)).toThrow('NonrootInput');
  expect(()=>parseGuardJson('['.repeat(65)+'0'+']'.repeat(65),1024)).toThrow('NonrootInput');
 });
});

describe('fixed purpose routing',()=>{
 it('retains the exact original CLI module and operation',()=>{
  expect(resolveGuardPurpose('bootstrap-runtime-verify',{MEM9_STAGE:'prod',MEM9_BOOTSTRAP_OPERATION:'runtime-verify',MEM9_RUNTIME_BOOTSTRAP_VERSION:'1'}))
   .toMatchObject({module:'/bootstrap/operator/scripts/runtime-bootstrap.mjs'});
  expect(resolveGuardPurpose('consolidation-control',{MEM9_STAGE:'prod',MEM9_PRODUCTION_WORKER_OPERATOR:'control'}))
   .toMatchObject({module:'/bootstrap/operator/scripts/production-consolidation-operator.mjs'});
 });
 it('denies production preview/provision/transition routes before reading credential values',()=>{
  const env={MEM9_STAGE:'prod',get MEM9_DB_SECRET(){throw Error('credential accessed');}};
  for(const purpose of ['denied-provision','denied-transition','bootstrap-runtime-bootstrap','post-runtime-fixture','../arbitrary'])
   expect(()=>resolveGuardPurpose(purpose,env)).toThrow('NonrootPurpose');
 });
 it('never silently converts a wrong operation or stage',()=>{
  expect(()=>resolveGuardPurpose('bootstrap-runtime-verify',{MEM9_STAGE:'prod',MEM9_BOOTSTRAP_OPERATION:'runtime-bootstrap',MEM9_RUNTIME_BOOTSTRAP_VERSION:'1'})).toThrow('NonrootPurpose');
  expect(()=>resolveGuardPurpose('consolidation-promote',{MEM9_STAGE:'pr-1',MEM9_PRODUCTION_WORKER_OPERATOR:'promotion'})).toThrow('NonrootPurpose');
 });
 it('requires a complete stage-bound unexpired synthetic canary identity',()=>{
  const identity={stage:'pr-7',runId:'11',runAttempt:1,commit:'a'.repeat(40),sourceTree:'b'.repeat(40),coordinatorDigest:'c'.repeat(64),
   schemaDigest:'d'.repeat(64),operatorDigest:'e'.repeat(64),nonce:'f'.repeat(32),deadlineMs:Date.now()+60000};
  const env={MEM9_STAGE:'pr-7',MEM9_CANARY_FIXTURE_IDENTITY:JSON.stringify(identity)};
  expect(resolveGuardPurpose('canary-fixture',env).module).toBe('/bootstrap/operator/scripts/canary-fixture-runner.mjs');
  for(const change of [{stage:'pr-8'},{deadlineMs:1},{sourceTree:'unreviewed'},{extra:true}])
   expect(()=>resolveGuardPurpose('canary-fixture',{...env,MEM9_CANARY_FIXTURE_IDENTITY:JSON.stringify({...identity,...change})})).toThrow('NonrootPurpose');
 });
});
