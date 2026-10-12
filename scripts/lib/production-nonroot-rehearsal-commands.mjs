/** Original command evidence decoding. No process, Docker, host file or
 * credential operation is available through this archive-only interface. */
import {need,exact,same} from './production-nonroot-engineering-json.mjs';

export async function readNonrootRehearsalCommands(rows,{reader,count}){
 reader.current();need(Array.isArray(rows)&&rows.length===count&&count<=35,'RehearsalCommandCount');
 reader.paid.debit(count*(32*131072+65536));
 const out=[];
 for(const row of rows){
  reader.current();exact(row,['stage','args','cleanup','status','stdout','stderr','startedMs','completedMs',...(Object.hasOwn(row,'taskKey')?['taskKey']:[])]);
  need(typeof row.stage==='string'&&typeof row.cleanup==='boolean'&&Number.isSafeInteger(row.status)&&Array.isArray(row.args)&&row.args.every(x=>typeof x==='string')&&Buffer.byteLength(JSON.stringify(row.args))<=131072,'RehearsalCommandFields');
  need(Number.isSafeInteger(row.startedMs)&&row.startedMs>0&&Number.isSafeInteger(row.completedMs)&&row.completedMs>=row.startedMs,'RehearsalCommandClock');
  need(row.stdout.bytesLength+row.stderr.bytesLength<=1048576,'RehearsalCommandOutputBound');
  const stdout=await reader.readBytes(row.stdout,1048576);reader.current();
  const stderr=await reader.readBytes(row.stderr,1048576);reader.current();
  const decode=raw=>new TextDecoder('utf-8',{fatal:true}).decode(raw);
  out.push({...row,args:[...row.args],stdout:decode(stdout),stderr:decode(stderr)});
 }
 return out;
}

export {inspectNonrootRecordedCommands as inspectNonrootRehearsalCommandSequence} from './production-nonroot-control-current.mjs';
