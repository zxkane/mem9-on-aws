import {test,expect} from 'vitest';
import {spawnSync} from 'node:child_process';
import {inspectObservationGateFiles,inspectObservationKernelStatus,nodeObservationCommonGateSource,runNodeObservationCommonGate} from './lib/production-nonroot-observation-gate.mjs';
const status=()=>['Name:\tnode','Uid:\t1000 1000 1000 1000','Gid:\t1000 1000 1000 1000','Groups:\t1000',...['Inh','Prm','Eff','Bnd','Amb'].map(k=>'Cap'+k+':\t0000000000000000'),'NoNewPrivs:\t1'].join('\n')+'\n';
const file=()=>({path:'/usr/local/bin/node',resolvedPath:'/usr/local/bin/node',sha256:'a'.repeat(64),size:1024,mode:493,uid:0,gid:0});
test('strict shared kernel gate validates all identities/capability sets',()=>expect(inspectObservationKernelStatus(status())).toEqual({uid:[1000,1000,1000,1000],gid:[1000,1000,1000,1000],groups:[1000],noNewPrivs:1}));
test('no supplementary groups remains a valid hardened identity',()=>expect(inspectObservationKernelStatus(status().replace('Groups:\t1000','Groups:\t')).groups).toEqual([]));
test('root, mixed IDs, extra groups and each residual capability reject',()=>{
 const invalid=[status().replace('1000 1000 1000 1000','1000 0 1000 1000'),status().replace('Groups:\t1000','Groups:\t1000 0'),status().replace('NoNewPrivs:\t1','NoNewPrivs:\t0')];
 for(const key of ['Inh','Prm','Eff','Bnd','Amb'])invalid.push(status().replace('Cap'+key+':\t0000000000000000','Cap'+key+':\t0000000000000001'));
 for(const raw of invalid)expect(()=>inspectObservationKernelStatus(raw)).toThrow('DataObservationSecurityGate');
});
test('missing/duplicate status cannot provide a fake NNP or capability value',()=>{
 for(const raw of [status().replace('NoNewPrivs:\t1\n',''),status()+'NoNewPrivs:\t0\n',status().replace('CapEff:\t0000000000000000','CapEff:\t0'),status().replace('1000 1000 1000 1000','1000')])expect(()=>inspectObservationKernelStatus(raw)).toThrow('DataObservationSecurityGate');
});
test('gate file rows retain exact original content metadata',()=>expect(inspectObservationGateFiles([file()])).toEqual([file()]));
test('writable/privileged files, alternate paths, owner changes and extra fields reject',()=>{
 for(const mutate of [f=>f.mode=511,f=>f.mode=0o4755,f=>f.uid=1000,f=>f.path='/tmp/../secret',f=>f.resolvedPath='relative',f=>f.sha256='wrong',f=>f.callback='read',f=>f.size=201326593]){
  const f=file();mutate(f);expect(()=>inspectObservationGateFiles([f])).toThrow();
 }
 expect(()=>inspectObservationGateFiles([file(),file()])).toThrow();
 expect(()=>runNodeObservationCommonGate([{...file(),callback:'read'}])).toThrow('DataObservationGateFiles');
});
test('fixed serialized gate source has no caller callback or environment dump',()=>{
 const source=nodeObservationCommonGateSource();expect(source).toContain("small('/proc/self/status',65536)");expect(source).not.toContain('/environ');expect(source).not.toContain('process.env');
});
test('serialized gate loads in a native Node child without test-loader bindings',()=>{
 const code=nodeObservationCommonGateSource()+"\nprocess.stdout.write(typeof fixedNodeObservationCommonGate);";
 const r=spawnSync(process.execPath,['--input-type=module','-e',code],{env:{},encoding:'utf8',timeout:5000,maxBuffer:16384});
 expect(r.error).toBeUndefined();expect(r.status).toBe(0);expect(r.stderr).toBe('');expect(r.stdout).toBe('function');
});
