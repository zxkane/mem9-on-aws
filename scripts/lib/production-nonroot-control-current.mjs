/** Forward the original caller's synchronous permit assertion. This helper
 * owns no authority, credit, expiry or callback result. Cleanup selects the
 * caller's already issued cleanup permit; it never revives normal work. */
import {types} from 'node:util';

export function assertNonrootControlCurrent(options,cleanup=false){
 const check=options?.assertCurrent;
 if(check===undefined)return;
 if(typeof check!=='function'||types.isAsyncFunction(check))throw Error('NonrootControlSynchronousCurrent');
 const result=check(cleanup);
 if(result&&typeof result.then==='function'){
  Promise.resolve(result).catch(()=>{});
  throw Error('NonrootControlSynchronousCurrent');
 }
 if(result!==undefined)throw Error('NonrootControlSynchronousCurrent');
}

/** Pure recorded-command framing. Kept with the existing small shared helper
 * so runtime modules do not import the host archive/source replay closure. */
export function inspectNonrootRecordedCommands(rows,stages,{startedMs,completedMs}){
 const need=(v,c)=>{if(!v)throw Error(c);};
 need(Array.isArray(rows)&&rows.length===stages.length,'RehearsalCommandCount');let after=startedMs;
 for(const [i,r]of rows.entries()){
  need(r.stage===stages[i]&&r.cleanup===['remove','inspect-removed'].includes(r.stage),'RehearsalCommandStage');
  need(Number.isSafeInteger(r.startedMs)&&Number.isSafeInteger(r.completedMs)&&r.startedMs>=after&&r.completedMs>=r.startedMs&&r.completedMs<=completedMs,'RehearsalCommandClock');after=r.completedMs;
  need(typeof r.stdout==='string'&&typeof r.stderr==='string'&&Buffer.byteLength(r.stdout)+Buffer.byteLength(r.stderr)<=1048576,'RehearsalCommandOutputBound');
  need(Array.isArray(r.args)&&r.args.every(x=>typeof x==='string')&&Buffer.byteLength(JSON.stringify(r.args))<=131072,'RehearsalCommandArguments');
 }
 return (stage,args,status=0)=>{
  const row=rows[stages.indexOf(stage)];need(row&&row.status===status,'RehearsalCommandStatus');
  need(row.args.length===args.length&&row.args.every((v,i)=>v===args[i]),'RehearsalCommandArguments');return row;
 };
}
