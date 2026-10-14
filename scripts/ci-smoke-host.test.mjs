import {afterEach,it,expect} from 'vitest';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {ciSmokeHost} from './lib/ci-smoke-host.mjs';

const directories=[];
afterEach(()=>{for(const path of directories.splice(0))rmSync(path,{recursive:true,force:true});});
function fixture(){
 const directory=mkdtempSync(join(tmpdir(),'mem9-smoke-host-')),bin=join(directory,'bin');directories.push(directory);mkdirSync(bin);
 const log='2026-10-10T00:00:00Z \u001b[32m#1 pushing manifest for example.com/image@sha256:'+'a'.repeat(64)+' done\u001b[0m\n';
 writeFileSync(join(bin,'gh'),`#!/usr/bin/env node
const args=process.argv.slice(2);
if(args.at(-1)==='repos/example/repository/actions/jobs/7/logs'){
 if(!args.includes('--allow-escape-sequences')){process.stderr.write('Refusing log terminal escape sequences');process.exitCode=1;}
 else process.stdout.write(${JSON.stringify(log)});
}else if(args.at(-1)==='repos/example/repository/actions/runs/7'){
 if(args.includes('--allow-escape-sequences'))process.exitCode=2;
 else process.stdout.write('{"id":7}');
}else process.exitCode=3;
`,{mode:0o700});
 const env={PATH:bin+':'+dirname(process.execPath)+':/usr/bin:/bin',GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:'example/repository',GITHUB_SHA:'a'.repeat(40),GITHUB_RUN_ID:'7',GITHUB_RUN_ATTEMPT:'1'};
 return {host:ciSmokeHost(env,directory),log};
}

it('reads exact build-log bytes when the CLI requires explicit escape-sequence admission',async()=>{
 const {host,log}=fixture();expect(await host.readLog(7)).toBe(log);
});
it('keeps ordinary metadata requests on their unchanged JSON path',async()=>{
 const {host}=fixture();expect(await host.api('actions/runs/7')).toEqual({id:7});
});
it.each([0,-1,NaN,Infinity,'7'])('rejects invalid job identifiers before invoking the CLI: %s',async id=>{
 const {host}=fixture();await expect(host.readLog(id)).rejects.toThrow('CiSmokeHostInvalid');
});
