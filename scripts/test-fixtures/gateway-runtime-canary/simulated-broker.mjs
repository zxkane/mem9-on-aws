// Real broker library over the synthetic AWS CLI and service simulation, for
// in-process tests and as a child process beside the shell deploy mock. Its
// receipts prove the wiring, never AWS state.
import {execFileSync,spawn} from 'node:child_process';
import {copyFileSync,existsSync,mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {mkdtemp} from 'node:fs/promises';
import {dirname,join,resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {GATEWAY_CANARY_SOURCE_PATHS,startGatewayRuntimeSourceBroker} from '../../lib/gateway-runtime-source-broker.mjs';
import {installFakeAwsCli} from './fake-aws-cli.mjs';
import {installGatewayCanaryServiceSimulation} from './native-simulation.mjs';

const repository=resolve(dirname(fileURLToPath(import.meta.url)),'../../..');
export const gitExecutable=execFileSync('/bin/sh',['-c','command -v git'],{encoding:'utf8'}).trim();

/** A clean single-commit checkout holding the reviewed canary sources and an
 * application region, so source binding does not depend on this worktree. */
export function createSyntheticBrokerCheckout(directory,{region='ap-northeast-1'}={}){
  const root=join(directory,'checkout');mkdirSync(root,{recursive:true});
  for(const path of Object.values(GATEWAY_CANARY_SOURCE_PATHS)){mkdirSync(dirname(join(root,path)),{recursive:true});copyFileSync(join(repository,path),join(root,path));}
  writeFileSync(join(root,'sst.config.ts'),`export default $config({app(){return {name:'synthetic',providers:{aws:{region:'${region}'}}};},async run(){}});\n`);
  const env={PATH:process.env.PATH,HOME:directory,GIT_CONFIG_NOSYSTEM:'1',GIT_AUTHOR_NAME:'synthetic',GIT_AUTHOR_EMAIL:'synthetic@example.com',GIT_COMMITTER_NAME:'synthetic',GIT_COMMITTER_EMAIL:'synthetic@example.com'};
  for(const args of [['init','-q','-b','main'],['add','.'],['commit','-q','-m','synthetic canary sources']])execFileSync(gitExecutable,['-C',root,...args],{env});
  const head=args=>execFileSync(gitExecutable,['-C',root,'rev-parse',args],{env,encoding:'utf8'}).trim();
  return {root,commit:head('HEAD'),tree:head('HEAD^{tree}')};
}

/** Start the real broker against synthetic services in this process. */
export async function startSimulatedBroker({directory,liveBoundaryPath,liveVersion='v1',faults={},defect,maxRequests,deadlineMs,signal,environment={},log=()=>{},onFixture=()=>{}}){
  const checkout=createSyntheticBrokerCheckout(directory);
  const aws=installFakeAwsCli({directory,liveBoundaryPath,liveVersion,faults});
  const services=installGatewayCanaryServiceSimulation({statePath:aws.statePath,configPath:aws.configPath,defect});
  // Lets a caller observe the synthetic services while the startup canary runs.
  onFixture({checkout,aws,services});
  try{
    const broker=await startGatewayRuntimeSourceBroker({repoRoot:checkout.root,awsExecutable:aws.awsExecutable,gitExecutable,
      evidenceRoot:join(directory,'evidence'),socketParent:tmpdir(),environment:{PATH:process.env.PATH,HOME:directory,GATEWAY_CANARY_ORG_POLICIES_PRINCIPAL_NEUTRAL:'true',...environment},log,
      ...(maxRequests?{maxRequests}:{}),...(deadlineMs?{deadlineMs}:{}),...(signal?{signal}:{})});
    broker.closed.finally(()=>services.restore());
    return {broker,checkout,aws,services};
  }catch(error){services.restore();throw error;}
}

/** The same broker as a child process, for callers that block their event loop. */
export async function spawnSimulatedBroker({directory,liveBoundaryPath}){
  const child=spawn(process.execPath,[fileURLToPath(import.meta.url),directory,liveBoundaryPath],{env:{PATH:process.env.PATH,HOME:directory},stdio:['ignore','pipe','inherit']});
  const exited=new Promise(resolve=>child.once('close',resolve));
  let path;
  try{path=await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(Error('simulated broker startup timeout')),90_000);let out='';
    child.once('close',()=>reject(Error('simulated broker exited')));
    child.stdout.on('data',chunk=>{out+=chunk;const m=/^source ([a-f0-9]{40}) ([a-f0-9]{40})\nexport MEM9_BOOTSTRAP_REQUEST_SOCKET=(\S+)\n/.exec(out);if(m){clearTimeout(timer);resolve({commit:m[1],tree:m[2],path:m[3]});}});
  });}catch(error){child.kill('SIGKILL');await exited;throw error;}
  const {commit,tree}=path;path=path.path;
  return {path,source:{commit,tree},async close(){
    child.kill('SIGTERM');await exited;const summary=join(directory,'broker-summary.json');
    return existsSync(summary)?JSON.parse(readFileSync(summary,'utf8')):null;
  }};
}

if(process.argv[1]===fileURLToPath(import.meta.url)){
  const [directory,liveBoundaryPath]=process.argv.slice(2);
  const {broker}=await startSimulatedBroker({directory:await mkdtemp(join(directory,'broker-')),liveBoundaryPath,log:m=>process.stderr.write(`simulated-broker: ${m}\n`)});
  for(const signal of ['SIGTERM','SIGINT'])process.once(signal,()=>broker.close({abort:true}));
  process.stdout.write(`source ${broker.source.commit} ${broker.source.tree}\nexport MEM9_BOOTSTRAP_REQUEST_SOCKET=${broker.socketPath}\n`);
  const summary=await broker.closed;writeFileSync(join(directory,'broker-summary.json'),JSON.stringify(summary));
}
