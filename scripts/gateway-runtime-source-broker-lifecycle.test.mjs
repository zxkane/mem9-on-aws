import {describe,it,expect,vi} from 'vitest';
import {mkdtemp,readFile,readdir,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {expectedGatewayBoundaryPolicyDocument} from './lib/gateway-workload-boundary.mjs';
import {startSimulatedBroker} from './test-fixtures/gateway-runtime-canary/simulated-broker.mjs';

// The lifecycle is replaced here only to make it throw at a chosen point; the
// broker, adapter, session-policy wrapper and synthetic services are real.
const lifecycle=vi.hoisted(()=>({touchFirst:false}));
vi.mock('./lib/gateway-runtime-canary-lifecycle.mjs',()=>({
  async runGatewayRuntimeCanaryLifecycle({ops}){
    if(lifecycle.touchFirst)await ops.assertAbsent({signal:new AbortController().signal});
    throw Error('GatewayRuntimeCanaryPlanChanged');
  },
}));

const reviewed=expectedGatewayBoundaryPolicyDocument({partition:'aws',accountId:'123456789012',applicationRegion:'ap-northeast-1',policyRevision:'r1'});
async function start(test){
  const directory=await mkdtemp(join(tmpdir(),'gateway-broker-throw-'));test.onTestFinished(()=>rm(directory,{recursive:true,force:true}));
  const liveBoundaryPath=join(directory,'live-boundary.json');await writeFile(liveBoundaryPath,JSON.stringify(reviewed));
  let aws;const logs=[];
  const error=await startSimulatedBroker({directory,liveBoundaryPath,log:m=>logs.push(m),onFixture:f=>{aws=f.aws;}}).then(()=>null,e=>e);
  const [run]=await readdir(join(directory,'evidence'));
  const read=async name=>readFile(join(directory,'evidence',run,name),'utf8');
  return {error,aws,logs,outcome:JSON.parse(await read('canary-outcome.json')),journal:(await read('journal.jsonl')).trim().split('\n').map(l=>JSON.parse(l))};
}

describe('Gateway source broker lifecycle throws',()=>{
  it('TC-GW-BROKER-034 a lifecycle that throws before any AWS operation closes the session policy and fails, not holds',async test=>{
    lifecycle.touchFirst=false;
    const f=await start(test);
    expect(f.error.message).toBe('GatewayRuntimeCanaryPlanChanged');expect(f.error.held).toBe(false);
    expect(f.aws.state().sessionPolicies).toEqual({});
    expect(f.outcome).toMatchObject({status:'FAILED',reason:'GatewayRuntimeCanaryPlanChanged',sessionPolicy:{status:'CLOSED',cleanupComplete:true}});
    expect(f.journal.find(j=>j.event==='lifecycle-threw')).toMatchObject({reason:'GatewayRuntimeCanaryPlanChanged',touchedAws:false});
    expect(f.journal.filter(j=>j.source==='session-policy').map(j=>j.event).at(-1)).toBe('session-policy-deleted');
    expect(f.logs).toContain('lifecycle threw (GatewayRuntimeCanaryPlanChanged) before any AWS operation');
  },60_000);

  it('TC-GW-BROKER-034 a lifecycle that throws after an AWS operation holds the session policy for review',async test=>{
    lifecycle.touchFirst=true;
    const f=await start(test);
    expect(f.error.held).toBe(true);
    expect(Object.keys(f.aws.state().sessionPolicies)).toHaveLength(1);
    expect(f.outcome).toMatchObject({status:'HELD',sessionPolicy:{status:'HELD'}});
    expect(f.journal.find(j=>j.event==='lifecycle-threw')).toMatchObject({touchedAws:true});
  },60_000);
});
