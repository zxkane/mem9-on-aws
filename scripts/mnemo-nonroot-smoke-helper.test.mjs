import {describe,it,expect,vi,beforeEach,afterEach} from 'vitest';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {ownedInventory,cleanupOwned} from './lib/mnemo-nonroot-smoke-helper.mjs';
const state=vi.hoisted(()=>({reply:{status:0,stdout:Buffer.alloc(0),stderr:Buffer.alloc(0)},calls:[]}));
vi.mock('node:child_process',async original=>({...await original(),spawnSync:(file,args)=>{state.calls.push([file,...args]);return state.reply;}}));
let directory;
function fixture(){
 directory=mkdtempSync(join(tmpdir(),'mem9-smoke-cleanup-test-'));
 const input={invocationId:'a'.repeat(64),containers:Array.from({length:6},(_,i)=>({id:String(i+1).repeat(64),name:'owned-'+i})),network:'9'.repeat(64),workDirectory:join(directory,'mem9-ci-smoke-work')};
 const file=join(directory,'state.json');writeFileSync(file,JSON.stringify(input),{mode:0o600});return {file,input};
}
beforeEach(()=>{state.calls=[];state.reply={status:0,stdout:Buffer.alloc(0),stderr:Buffer.alloc(0)};});
afterEach(()=>{if(directory)rmSync(directory,{recursive:true,force:true});});
describe('owned Docker cleanup',()=>{
 it('requires successful complete inventories before reporting absence',()=>{
  const {file}=fixture();expect(ownedInventory(file)).toEqual({containerIds:[],networkIds:[],volumeNames:[],temporaryEntries:[]});
  expect(state.calls).toHaveLength(3);expect(state.calls.every(c=>c.includes('label=mem9-ci-smoke-invocation='+'a'.repeat(64)))).toBe(true);
 });
 it('does not interpret Docker daemon failure as an empty inventory',()=>{
  const {file}=fixture();state.reply={status:1,stdout:Buffer.alloc(0),stderr:Buffer.from('daemon unavailable')};
  expect(()=>ownedInventory(file)).toThrow('SmokeInventoryFailed');
 });
 it('refuses to remove a container with a different ownership label',()=>{
  const {file,input}=fixture();state.reply={status:0,stdout:Buffer.from(JSON.stringify([{Name:'/owned-0',Config:{Labels:{'mem9-ci-smoke-invocation':'b'.repeat(64)}}}])),stderr:Buffer.alloc(0)};
  expect(()=>cleanupOwned(file)).toThrow('SmokeOwnership');
  expect(state.calls).toEqual([['docker','inspect',input.containers[0].id]]);
 });
});
