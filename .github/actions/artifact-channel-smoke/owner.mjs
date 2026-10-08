/** Local existing-gh owner CLI. prepare performs reads; publish performs at
 * most one fixed commit-status POST after live identity/source validation.
 * No token is accepted in argv or printed. Never invoked by the workflow. */
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';
import {BRANCH,dispatchInputs,inputs,bindingFor,statusFor,readAnnouncement,hash,need,LIMITS} from './channel.mjs';
import {ownerChoice} from './owner-choice.mjs';

export function ownerArguments(argv){
 const [mode,...args]=argv,isChoice=['choiceprepare','choicepublish'].includes(mode);need((isChoice||['prepare','publish'].includes(mode))&&args.length===(isChoice?12:10),'SyntheticOwnerArguments');const values={};
 const allowed=new Set(['repository','run-id','run-attempt','challenge','revision',...(isChoice?['state-file']:[])]);
 for(let i=0;i<args.length;i+=2){need(args[i].startsWith('--')&&allowed.delete(args[i].slice(2))&&typeof args[i+1]==='string','SyntheticOwnerArguments');values[args[i].slice(2)]=args[i+1];}
 need(allowed.size===0&&/^[a-f0-9]{40}$/.test(values.revision),'SyntheticOwnerArguments');
 return {mode,revision:values.revision,request:dispatchInputs({repository:values.repository,runId:Number(values['run-id']),runAttempt:Number(values['run-attempt']),challenge:values.challenge}),...(isChoice?{stateFile:values['state-file']}:{})};
}
export async function ownerStatus({mode,revision,request,stateFile},{api,download,checkout,now=Date.now,sleep}={}){
 const isChoice=['choiceprepare','choicepublish'].includes(mode);need(isChoice||['prepare','publish'].includes(mode),'SyntheticOwnerMode');request=dispatchInputs(request);const started=now(),deadline=started+90000;let count=0;
 const check=()=>need(now()>=started&&now()<deadline,'SyntheticOwnerDeadline');
 const call=async(path,payload)=>{check();need(++count<=64,'SyntheticOwnerReadLimit');const result=await api(path,payload);check();return result;};
 const local=await checkout();need(local.revision===revision&&local.branch===BRANCH&&local.clean===true,'SyntheticOwnerCheckout');
 const user=await call('user');
 const run=await call(`repos/${request.repository}/actions/runs/${request.runId}/attempts/${request.runAttempt}`);need(run.head_sha===revision,'SyntheticOwnerRevision');
 need(Number.isSafeInteger(user?.id)&&user.id>0&&run.actor?.id===user.id,'SyntheticOwnerActor');
 const config=inputs({...request,initiatingActorId:run.actor.id});
 const commit=await call(`repos/${config.repository}/git/commits/${revision}`),binding=bindingFor(config,run,commit);
 need(binding.tree===local.tree&&now()<binding.notAfter,'SyntheticOwnerSource');
 const payload=statusFor(binding),path=`repos/${config.repository}/statuses/${revision}`;
 const existing=await readAnnouncement(binding,p=>call(p),check);
 if(isChoice){
  need(existing&&typeof download==='function','SyntheticInitialBindingRequired');
  const current=()=>{check();need(now()<binding.notAfter,'SyntheticChoiceExpired');};
  const bytes=async id=>{current();need(++count<=64,'SyntheticOwnerReadLimit');const result=await download(config.repository,id);current();return result;};
  return ownerChoice({mode,binding,stateFile},{api:call,download:bytes,check:current,now,sleep});
 }
 if(mode==='prepare')return {kind:'synthetic-channel-status-plan',bindingHash:hash(binding),payload,path,alreadyPresent:existing};
 if(existing)return {kind:'synthetic-channel-status-existing',bindingHash:hash(binding),path};
 need(hash(await checkout())===hash(local),'SyntheticOwnerCheckoutChanged');check();
 const status=await call(path,payload);
 need(status?.creator?.id===config.initiatingActorId&&status.url==='https://api.github.com/'+path&&Object.entries(payload).every(([k,v])=>status[k]===v),'SyntheticOwnerStatusUnconfirmed');
 return {kind:'synthetic-channel-status-posted',bindingHash:hash(binding),statusId:status.id,path};
}

if(process.argv[1]&&fileURLToPath(import.meta.url)===process.argv[1]){
 const timer=setTimeout(()=>{console.error('SyntheticOwnerDeadline');process.exit(1);},90000),exec=promisify(execFile),root=fileURLToPath(new URL('../../../',import.meta.url));
 try{
  need(process.env.GITHUB_ACTIONS!=='true'&&process.versions.node.split('.')[0]==='24','SyntheticOwnerLocalOnly');
  const args=ownerArguments(process.argv.slice(2));
  const api=async(path,payload)=>{
   const command=['api','--hostname','github.com','--method',payload?'POST':'GET',path];if(payload)command.push('--input','-');
   // gh reads its existing owner credential by reference from normal config/env.
   const promise=exec('/usr/bin/gh',command,{timeout:15000,maxBuffer:LIMITS.jsonBytes,env:process.env});
   promise.child.stdin.on('error',()=>{});promise.child.stdin.end(payload?JSON.stringify(payload):undefined);
   const result=await promise;return JSON.parse(result.stdout);
  };
  const checkout=async()=>{
   const opts={cwd:root,env:{PATH:'/usr/bin:/bin',GIT_CONFIG_NOSYSTEM:'1'},timeout:10000,maxBuffer:65536};
   const result=await exec('/usr/bin/git',['rev-parse','HEAD','HEAD^{tree}','--abbrev-ref','HEAD'],opts),status=await exec('/usr/bin/git',['status','--porcelain=v1'],opts),[revision,tree,branch]=result.stdout.trim().split('\n');return {revision,tree,branch,clean:status.stdout===''};
  };
  const download=async(repository,id)=>{need(Number.isSafeInteger(id)&&id>0,'SyntheticArtifactId');const result=await exec('/usr/bin/gh',['api','--hostname','github.com','--method','GET',`repos/${repository}/actions/artifacts/${id}/zip`],{timeout:15000,maxBuffer:LIMITS.artifactBytes,encoding:'buffer',env:process.env});return result.stdout;};
  console.log(JSON.stringify(await ownerStatus(args,{api,download,checkout}),null,2));clearTimeout(timer);
 }catch{console.error('SyntheticOwnerHeld');process.exit(1);}
}
