import {describe,it,expect} from 'vitest';
import {inspectServiceProcessOutput} from './lib/service-nonroot-runtime.mjs';
const row=`MEM9_PROCESS /proc/17\nExecutable: /usr/local/bin/node\nUid: 1000 1000 1000 1000\nGid: 1000 1000 1000 1000\nCapInh: 0000000000000000\nCapPrm: 0000000000000000\nCapEff: 0000000000000000\nCapBnd: 0000000000000000\nCapAmb: 0000000000000000\nNoNewPrivs: 1\nMEM9_PROCESS_END\n`;
describe('actual ECS application process evidence',()=>{
 it('accepts framed security attributes with session-manager framing',()=>{
  expect(inspectServiceProcessOutput('Starting session\n'+row+'Session ended')).toHaveLength(1);
 });
 it('checks every application process rather than accepting one healthy PID',()=>{
  expect(()=>inspectServiceProcessOutput(row+row.replace('Uid: 1000 1000 1000 1000','Uid: 0 0 0 0'))).toThrow();
 });
 it.each(['Executable','Uid','Gid','CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs'])('rejects missing %s evidence',key=>{
  expect(()=>inspectServiceProcessOutput(row.replace(new RegExp('^'+key+':.*\\n','m'),''))).toThrow();
 });
 it('rejects missing process output and effective capabilities',()=>{
  expect(()=>inspectServiceProcessOutput('command failed')).toThrow();
  expect(()=>inspectServiceProcessOutput(row.replace('CapEff: 0000000000000000','CapEff: 0000000000000001'))).toThrow();
 });
});
