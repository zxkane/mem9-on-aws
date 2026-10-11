import {test,expect} from 'vitest';
import {inspectNonrootRecord} from './lib/production-nonroot-contracts.mjs';
import {describeDataObservationSchedule,inspectDataObservationPlan,selectDataObservationLaunch} from './lib/production-nonroot-data-observer.mjs';

// Explicit synthetic contract data; no provider or native completion is mocked.
const plan=()=>({version:1,kind:'bounded-data-observation',owner:'a'.repeat(32),operation:'b'.repeat(32),
 launchNonce:'c'.repeat(32),sourceTree:'d'.repeat(40),role:'planner',
 image:{rootDigest:'sha256:'+'1'.repeat(64),arm64Digest:'sha256:'+'2'.repeat(64),configDigest:'sha256:'+'3'.repeat(64)},
 startedMs:1000,latestArmMs:1100,observationEndMs:1400,deadlineMs:1500,armingLimitMs:25,cleanupReserveMs:100,
 episodes:[{index:0,offsetMs:200,durationMs:100,sampleEveryMs:50}],
 limits:{readBytes:268435456,rawBytes:1048576,initialProcesses:128,finalProcesses:128,combinedIdentities:256}});

test('closed prospective plan and original absolute schedule',()=>{
 const p=inspectDataObservationPlan(plan());expect(Object.isFrozen(p)).toBe(true);
 expect(describeDataObservationSchedule(p)).toMatchObject({snapshotCount:3,episodes:[{startedMs:1200,completedMs:1300,samples:3}],deadlineMs:1500});
});
test('before window and at/after latest admission choose normal with no observation allocation',()=>{
 for(const nowMs of [999,1100,1400,1500,1000000])expect(selectDataObservationLaunch(plan(),{nowMs})).toMatchObject({mode:'normal',observation:null});
});
test('observed selection retains original cleanup/end clock across admitted starts',()=>{
 for(const nowMs of [1000,1050,1099])expect(selectDataObservationLaunch(plan(),{nowMs})).toMatchObject({mode:'observed',observation:{observationEndMs:1400,cleanupDeadlineMs:1500,armingDeadlineMs:nowMs+25}});
});
test('end sample retained when interval does not divide the window',()=>{
 const p=plan();p.episodes[0].sampleEveryMs=30;expect(describeDataObservationSchedule(p).snapshotCount).toBe(5);
});
test('foreign version/role and executable-source fields are not launch switches',()=>{
 for(const mutate of [p=>p.version=2,p=>p.role='debug',p=>p.source='process.exit(0)',p=>p.callback='allowed']){
  const p=plan();mutate(p);expect(()=>inspectDataObservationPlan(p)).toThrow('NonrootContractInvalid');
 }
});
test('late normal selection still validates the whole plan',()=>{
 const p=plan();p.image.rootDigest='unbound';expect(()=>selectDataObservationLaunch(p,{nowMs:99999})).toThrow('NonrootContractInvalid');
});
test('original read/output/process limits cannot be reduced or increased',()=>{
 for(const key of Object.keys(plan().limits))for(const delta of [-1,1]){
  const p=plan();p.limits[key]+=delta;expect(()=>inspectDataObservationPlan(p)).toThrow('NonrootContractInvalid');
 }
});
test('arming and cleanup time must fit before any observation work',()=>{
 for(const mutate of [p=>p.armingLimitMs=30001,p=>p.cleanupReserveMs=101,p=>p.latestArmMs=1190,p=>p.deadlineMs=1400]){
  const p=plan();mutate(p);expect(()=>inspectDataObservationPlan(p)).toThrow('NonrootContractInvalid');
 }
});
test('episode omissions, overlap, reordering and overrun reject',()=>{
 for(const mutate of [p=>p.episodes=[],p=>p.episodes[0].index=1,p=>p.episodes[0].durationMs=300,
  p=>p.episodes.push({index:1,offsetMs:250,durationMs:50,sampleEveryMs:10})]){
  const p=plan();mutate(p);expect(()=>inspectDataObservationPlan(p)).toThrow('NonrootContractInvalid');
 }
});
test('unsafe arithmetic, zero intervals and unknown clock reject',()=>{
 for(const mutate of [p=>p.startedMs=Number.MAX_SAFE_INTEGER,p=>p.episodes[0].sampleEveryMs=0]){
  const p=plan();mutate(p);expect(()=>inspectDataObservationPlan(p)).toThrow('NonrootContractInvalid');
 }
 for(const nowMs of [0,-1,NaN,Infinity,1.5])expect(()=>selectDataObservationLaunch(plan(),{nowMs})).toThrow();
 expect(()=>selectDataObservationLaunch(plan(),{nowMs:1000,callback:'allowed'})).toThrow('DataObservationClock');
});
test('getters and proxies are rejected without invoking caller code',()=>{
 let calls=0;const p=plan();Object.defineProperty(p,'role',{enumerable:true,get(){calls++;return 'planner';}});
 expect(()=>inspectDataObservationPlan(p)).toThrow();expect(calls).toBe(0);
 expect(()=>inspectDataObservationPlan(new Proxy(plan(),{get(){throw Error('trap');}}))).toThrow('NonrootContractInvalid');
 expect(()=>selectDataObservationLaunch(plan(),{get nowMs(){calls++;return 1000;}})).toThrow('NonrootContractInvalid');expect(calls).toBe(0);
});
test('new plan cannot enter legacy fixed-launch decoder',()=>{
 expect(()=>inspectNonrootRecord('FixedDataLaunchV1',plan())).toThrow('NonrootContractInvalid');
});
