import {it,expect,vi,afterEach} from 'vitest';
import {runProductionCanary} from './run-production-canary.mjs';
import * as delivery from './lib/production-canary-delivery.mjs';
import * as sampler from './lib/mcp-canary-sampler.mjs';
import * as flow from './lib/production-canary-continuation-flow.mjs';
import * as scheduling from './lib/production-scheduling.mjs';
import * as observer from './lib/production-recurring-observer.mjs';
import * as operator from './run-production-consolidation.mjs';
afterEach(()=>vi.restoreAllMocks());

it('requires independent operator controls before touching AWS',async()=>{
  const load=vi.spyOn(delivery,'loadProductionCanaryWorker');
  await expect(runProductionCanary({clients:{},region:'ap-northeast-1',persist:async()=>{},continuation:{},controls:{}})).rejects.toThrow('ContinuationOperatorControlsRequired');
  expect(load).not.toHaveBeenCalled();
});
it('wires canonical N150 sampling, journal intent, cancellable wakes and authenticated recurrence',async()=>{
  const clusterArn='arn:aws:ecs:ap-northeast-1:123456789012:cluster/mem9-on-aws-prod-Fixture';
  const backendBinding={taskArn:clusterArn.replace(':cluster/',':task/')+'/'+'a'.repeat(32),
    taskDefinitionArn:'arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-on-aws-prod-Fixture-Mem9RuntimeServer:1',
    containers:['mnemo-server','qwen3-embed','llm-proxy'].map(name=>({name,imageDigest:'sha256:'+'d'.repeat(64)}))};
  const targets=['planner','executor'].map(kind=>({kind,clusterArn,taskDefinitionArn:'definition-'+kind}));
  vi.spyOn(delivery,'loadProductionCanaryWorker').mockImplementation(async(_clients,{kind})=>targets.find(t=>t.kind===kind));
  const wake=vi.spyOn(delivery,'runProductionCanaryWake').mockResolvedValue({});
  vi.spyOn(sampler,'loadMcpCanaryConfiguration').mockResolvedValue({});
  const client={read:vi.fn(async()=>true),write:vi.fn(async()=>true)};
  vi.spyOn(sampler,'createMcpCanaryClient').mockResolvedValue(client);
  const sample=vi.spyOn(sampler,'sampleMcpCanaryCohort').mockResolvedValue({});
  const admin=vi.spyOn(operator,'runProductionConsolidationTask').mockResolvedValue({phase:'status'});
  const actualActivate=scheduling.activateProductionScheduling,setSecret=vi.fn(async()=>{});
  vi.spyOn(scheduling,'activateProductionScheduling').mockImplementation((deps,config)=>actualActivate({...deps,setSecret,currentMain:async()=>config.revision},config));
  vi.spyOn(scheduling,'enableProductionScheduling').mockResolvedValue(undefined);
  const verify=vi.spyOn(scheduling,'verifyProductionScheduling').mockImplementation(async(_clients,_targets,options)=>({enabled:options.enabled}));
  vi.spyOn(scheduling,'captureProductionBackend').mockResolvedValue(backendBinding);
  const recurring=vi.spyOn(observer,'observeProductionRecurringDeliveries').mockResolvedValue({verified:true});
  const guard=vi.fn(async()=>{}),override=vi.fn(),controls={guard,verifyQuiet:async()=>{},release:async()=>{},hold:async()=>{},calibrate:async()=>{},admin:override};
  const clients={ssm:{send:vi.fn()},ecs:{send:vi.fn()},scheduler:{send:vi.fn()},logs:{send:vi.fn()}},startedMs=Date.now();
  const continuation={original:{},attemptId:'a'.repeat(32),compatibility:{current:{backendBinding},images:{worker:{currentRoot:'sha256:'+'b'.repeat(64),currentChild:'sha256:'+'c'.repeat(64)}}}};
  vi.spyOn(flow,'runProductionContinuationFlow').mockImplementation(async deps=>{
    const intent=async()=>{};await deps.wake('executor',{wave:'apply',admission:'d'.repeat(32),onIntent:intent});
    expect(wake.mock.calls[0][2].onIntent).toBe(intent);const signal=wake.mock.calls[0][3].signal;expect(signal.aborted).toBe(false);
    let closed=false;const onWrite=async()=>{};
    await deps.sample('a'.repeat(32),'loaded',{samplesPerKind:150,onWrite,isClosing:()=>closed});
    expect(sample.mock.calls[0][1]).toMatchObject({samplesPerKind:150,onWrite});
    await sample.mock.calls[0][0].read(0);closed=true;expect(()=>sample.mock.calls[0][0].write('synthetic')).toThrow('ContinuationClosing');
    await deps.admin('status');expect(admin).toHaveBeenCalled();expect(override).not.toHaveBeenCalled();
    await deps.activateScheduling({admission:'e'.repeat(64),activationSeed:'f'.repeat(64),startedMs,backendBinding});
    expect(verify.mock.calls.some(call=>call[2].enabled===true&&call[2].backendBinding===backendBinding)).toBe(true);
    const count=setSecret.mock.calls.length;
    await expect(deps.activateScheduling({admission:'e'.repeat(64),activationSeed:'f'.repeat(64),startedMs,backendBinding:{...backendBinding,taskArn:backendBinding.taskArn.replace(/a{32}$/,'b'.repeat(32))}})).rejects.toThrow('ProductionBackendArtifactChanged');
    expect(setSecret.mock.calls.length).toBe(count);
    await deps.observeRecurring({admission:'e'.repeat(64)});
    expect(recurring.mock.calls[0][0]).toBe(clients);expect(recurring.mock.calls[0][2]).toMatchObject({afterMs:startedMs,deadlineMs:startedMs+2700000,
      artifacts:{executor:{rootDigest:'sha256:'+'b'.repeat(64),arm64Digest:'sha256:'+'c'.repeat(64)}}});
    await recurring.mock.calls[0][2].guard();expect(guard).toHaveBeenCalledWith('recurring');
    deps.abortWakes();expect(signal.aborted).toBe(true);return {phase:'adapter-tested'};
  });
  expect((await runProductionCanary({clients,region:'ap-northeast-1',persist:async()=>{},continuation,controls})).phase).toBe('adapter-tested');
});
