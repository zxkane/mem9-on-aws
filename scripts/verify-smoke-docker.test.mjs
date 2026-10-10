import {it,expect} from 'vitest';
import {readFileSync} from 'node:fs';
import {parse} from 'yaml';
import {validateSmokeDockerHostConfig,validateSmokeDockerRuntime,SMOKE_DOCKER_VERSION,SMOKE_DOCKER_CONTEXT} from './verify-smoke-docker.mjs';
import {ciSmokeJobDefinition} from './lib/ci-smoke-job.mjs';

function fixture(){
 const base='/tmp/runner/mem9-smoke-docker',host='unix://'+base+'/run-1234abcd/docker.sock';
 return {env:{RUNNER_ENVIRONMENT:'github-hosted',RUNNER_TEMP:'/tmp/runner',DOCKER_CONFIG:base+'/client',DOCKER_HOST:host},version:{Client:{Version:SMOKE_DOCKER_VERSION,ApiVersion:'1.53'},Server:{Version:SMOKE_DOCKER_VERSION,ApiVersion:'1.53'}},info:{DriverStatus:[['driver-type','io.containerd.snapshotter.v1']],DockerRootDir:base+'/run-1234abcd/data'},contexts:[{Name:SMOKE_DOCKER_CONTEXT,Endpoints:{docker:{Host:host}}}]};
}
it('accepts only the selected job-local client, daemon, store and socket',()=>{const f=fixture();expect(validateSmokeDockerRuntime(f.env,f.version,f.info,f.contexts).containerd).toBe(true);});
it.each([
 f=>{f.version.Client.Version='28.0.4';},f=>{f.version.Server.ApiVersion='1.48';},f=>{f.info.DriverStatus=[];},
 f=>{f.info.DockerRootDir='/var/lib/docker';},f=>{f.env.DOCKER_HOST='unix:///var/run/docker.sock';},
 f=>{f.contexts[0].Endpoints.docker.Host='tcp://example.com:2375';},f=>{f.env.DOCKER_CONTEXT='default';},
 f=>{f.env.DOCKER_API_VERSION='1.48';},
 f=>{f.env.RUNNER_ENVIRONMENT='self-hosted';},f=>{f.env.DOCKER_CONFIG='/shared/docker';},
])('rejects an incompatible or shared daemon configuration',change=>{const f=fixture();change(f);expect(()=>validateSmokeDockerRuntime(f.env,f.version,f.info,f.contexts)).toThrow();});
it('accepts an absent/empty or inert host configuration',()=>{expect(validateSmokeDockerHostConfig({})).toEqual({});expect(()=>validateSmokeDockerHostConfig({'exec-opts':['native.cgroupdriver=systemd'],features:{buildkit:true},debug:false})).not.toThrow();});
it.each(['data-root','exec-root','pidfile','hosts','containerd','containerd-namespace','containerd-plugins-namespace','registry-mirrors','proxies','tlskey'])('rejects inherited %s before the installer reads it',key=>{expect(()=>validateSmokeDockerHostConfig({[key]:'/shared'})).toThrow('SmokeDockerSharedConfig');});
it('wires the pinned Node24 Docker setup before QEMU, credentials and acquisition',()=>{
 const job=ciSmokeJobDefinition(),actual=parse(readFileSync(new URL('../.github/workflows/infra-ci.yml',import.meta.url),'utf8')).jobs['mnemo-nonroot-smoke'];
 const index=name=>job.steps.findIndex(s=>s.name===name),setup=job.steps.find(s=>s.name==='Set up isolated smoke Docker');
 expect(setup?.uses).toBe('docker/setup-docker-action@2bf61fb9464cc67f0cbdeabed6aa0380accd1c70');
 expect(setup.with.version).toBe('v'+SMOKE_DOCKER_VERSION);expect(setup.with.context).toBe(SMOKE_DOCKER_CONTEXT);
 expect(JSON.parse(setup.with['daemon-config'])).toEqual({debug:false,'log-level':'info',features:{'containerd-snapshotter':true}});
 expect(setup.with['runtime-basedir']).toBe('${{ runner.temp }}/mem9-smoke-docker');expect(setup.with['set-host']).toBe(true);expect(setup.with).not.toHaveProperty('tcp-port');
 expect(index('Prepare isolated smoke Docker')).toBeLessThan(index('Set up isolated smoke Docker'));
 for(const name of ['Set up QEMU','Configure smoke registry credentials','Acquire exact smoke image digests'])expect(index('Verify isolated smoke Docker')).toBeLessThan(index(name));
 expect(actual).toEqual(job);
});
