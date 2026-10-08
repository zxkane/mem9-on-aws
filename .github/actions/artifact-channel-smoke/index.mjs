import {appendFile,readFile} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {runChannel,githubReader,need,LIMITS} from './channel.mjs';

// The watchdog terminates this very process on an ambiguous SDK timeout. It
// never retries the upload or leaves a background success path to be adopted.
const watchdog=setTimeout(()=>{console.error('::error::SyntheticChannelDeadline');process.exit(1);},LIMITS.durationMs);
const exec=promisify(execFile),env=process.env;
try{
 need(process.versions.node.split('.')[0]==='24','SyntheticNodeRuntime');
 const event=JSON.parse(await readFile(env.GITHUB_EVENT_PATH,'utf8'));
 const config={repository:env.GITHUB_REPOSITORY,runId:Number(env.GITHUB_RUN_ID),runAttempt:Number(env.GITHUB_RUN_ATTEMPT),initiatingActorId:Number(env.GITHUB_ACTOR_ID),challenge:env.INPUT_CHALLENGE};
 need(event.inputs?.challenge===config.challenge,'SyntheticDispatchInputs');
 const checkout=async()=>{
  const opts={cwd:env.GITHUB_WORKSPACE,env:{PATH:'/usr/bin:/bin',GIT_CONFIG_NOSYSTEM:'1'},timeout:10000,maxBuffer:65536};
  const r=await exec('/usr/bin/git',['rev-parse','HEAD','HEAD^{tree}'],opts),status=await exec('/usr/bin/git',['status','--porcelain=v1'],opts),[revision,tree]=r.stdout.trim().split('\n');return {revision,tree,clean:status.stdout===''};
 };
 const artifactClient=async()=>{
  const pkg=JSON.parse(await readFile(new URL('./node_modules/@actions/artifact/package.json',import.meta.url),'utf8'));need(pkg.version==='6.3.1','SyntheticArtifactVersion');
  const {DefaultArtifactClient}=await import('@actions/artifact');return new DefaultArtifactClient();
 };
 const recordDiagnostic=async diagnostic=>{
  const raw=JSON.stringify(diagnostic);await appendFile(env.GITHUB_OUTPUT,'diagnostic='+raw+'\n');
  await new Promise((resolve,reject)=>process.stdout.write(raw+'\n',error=>error?reject(error):resolve()));
 };
 const result=await runChannel({config,contender:env.INPUT_CONTENDER,env},{api:githubReader(env['INPUT_GITHUB-TOKEN']),checkout,artifactClient,recordDiagnostic});
 const raw=JSON.stringify(result);await appendFile(env.GITHUB_OUTPUT,'receipt='+raw+'\nmarker='+result.AWS_SIMULATED_MARKER+'\n');console.log(raw);
 clearTimeout(watchdog);
}catch{console.error('::error::SyntheticChannelHeld');process.exit(1);}
