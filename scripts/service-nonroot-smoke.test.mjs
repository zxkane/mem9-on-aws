import {test} from 'vitest';
import assert from 'node:assert/strict';
import {parseArgs, imageReferences, verifyLoadedServiceImage, verifiedContainerImageId, verifyProcessStatus, containerLimits} from './run-service-nonroot-smoke.mjs';
import {createHash} from 'node:crypto';
import {taggedServiceDefinition} from './test-fixtures/service-nonroot-images.mjs';

test('CLI accepts only explicit private input/output paths and rejects duplicate or arbitrary options', () => {
  assert.deepEqual(parseArgs(['--baseline', '/private/input', '--evidence-root', '/private/output']), {baseline: '/private/input', evidenceRoot: '/private/output'});
  for (const args of [[], ['--baseline'], ['--image', 'arbitrary'], ['--baseline', '/a', '--baseline', '/b', '--evidence-root', '/c']])
    assert.throws(() => parseArgs(args));
});

test('baseline permits exactly the known containers and immutable digest references', () => {
  const baseline = {taskDefinition: {containerDefinitions: ['mnemo-server', 'llm-proxy', 'qwen3-embed'].map(name => ({name, image: 'example.com/synthetic@sha256:' + 'a'.repeat(64)}))}};
  assert.equal(Object.keys(imageReferences(baseline)).length, 2);
  for (const mutate of [b => b.taskDefinition.containerDefinitions.push({name: 'unknown'}),
    b => b.taskDefinition.containerDefinitions[0].image = 'example.com/synthetic:latest',
    b => b.taskDefinition.containerDefinitions[2].image = 'example.com/synthetic:latest',
    b => b.taskDefinition.containerDefinitions[0].command = ['arbitrary'],
    b => b.taskDefinition.containerDefinitions[0].linuxParameters = {capabilities: {add: ['SYS_ADMIN']}}]) {
    const copy = structuredClone(baseline); mutate(copy); assert.throws(() => imageReferences(copy));
  }
  for(const imageBindings of [null,false,0,''])assert.throws(()=>imageReferences({...baseline,imageBindings}));
});

const status = 'Name:\tmnemo-server\nUid:\t1000 1000 1000 1000\nGid:\t1000 1000 1000 1000\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n';
test('cached index identity cannot substitute a different platform or image config',()=>{
  const baseline=taggedServiceDefinition(),e=baseline.imageBindings.images['mnemo-server'];e.imageDigest=e.registryDigest;baseline.imageBindings.tasks[0].containers[0].imageDigest=e.registryDigest;
  const image={Id:JSON.parse(e.leafManifest).config.digest,RepoDigests:[imageReferences(baseline)['mnemo-server']],Os:'linux',Architecture:'arm64'};
  assert.equal(verifyLoadedServiceImage(image,'mnemo-server',baseline),image.Id);
  for(const delta of [{Architecture:'amd64'},{Os:'windows'},{Id:'sha256:'+'f'.repeat(64)}])assert.throws(()=>verifyLoadedServiceImage({...image,...delta},'mnemo-server',baseline));
  const leafDigest='sha256:'+createHash('sha256').update(e.leafManifest).digest('hex'),descriptor={digest:leafDigest,mediaType:JSON.parse(e.leafManifest).mediaType,platform:{os:'linux',architecture:'arm64'}};
  assert.equal(verifyLoadedServiceImage({...image,Id:leafDigest,Descriptor:descriptor},'mnemo-server',baseline),leafDigest);
  assert.throws(()=>verifyLoadedServiceImage({...image,Id:leafDigest},'mnemo-server',baseline));
  assert.throws(()=>verifyLoadedServiceImage({...image,Id:leafDigest,Descriptor:{...descriptor,digest:e.registryDigest}},'mnemo-server',baseline));
  assert.equal(verifiedContainerImageId({Image:e.registryDigest,ImageManifestDescriptor:descriptor},leafDigest),leafDigest);
  assert.equal(verifiedContainerImageId({Image:image.Id},image.Id),image.Id);
  assert.throws(()=>verifiedContainerImageId({Image:e.registryDigest},leafDigest));
});
test('application evidence rejects root, saved root IDs, every nonzero capability set and missing NoNewPrivs', () => {
  assert.equal(verifyProcessStatus(status).NoNewPrivs, '1');
  for (const key of ['Uid', 'Gid']) {
    for (let i = 0; i < 4; i++) {
      const ids = ['1000', '1000', '1000', '1000']; ids[i] = '0';
      assert.throws(() => verifyProcessStatus(status.replace(new RegExp(key + ':.*'), key + ': ' + ids.join(' '))));
    }
  }
  for (const key of ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'])
    assert.throws(() => verifyProcessStatus(status.replace(new RegExp(key + ':.*'), key + ': 0000000000000001')));
  assert.throws(() => verifyProcessStatus(status.replace('NoNewPrivs:\t1', 'NoNewPrivs:\t0')));
  assert.throws(() => verifyProcessStatus(status.replace(/CapBnd:.*\n/, '')));
});

test('simultaneous containers fit the aggregate resource budget with no pulls, swap or restart', () => {
  let memory = 0, cpus = 0;
  for (const kind of ['postgres', 'fixture', 'proxy', 'mnemo']) {
    const args = containerLimits(kind);
    const value = flag => args[args.indexOf(flag) + 1];
    memory += parseInt(value('--memory')); cpus += Number(value('--cpus'));
    assert.equal(value('--memory'), value('--memory-swap'));
    assert(args.includes('--pull=never')); assert(args.includes('--restart=no'));
  }
  assert(memory <= 6144); assert(cpus <= 2);
  assert.throws(() => containerLimits('unbounded'));
});
