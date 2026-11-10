import {describe,it,expect} from 'vitest';
import {hardenMaintenanceContainer,assertHardenedMaintenanceContainer,assertMaintenanceProcess} from './maintenance-task-nonroot.mjs';

const container=()=>({name:'Mem9ConsolidationPlanner',image:'example/worker:revision',entryPoint:['node'],
  command:['/app/scripts/consolidation-worker.mjs'],environment:[{name:'MEM9_STAGE',value:'pr-7'}],
  secrets:[{name:'MEM9_PLANNER_DB_SECRET',valueFrom:'/example/planner-credential'}],
  linuxParameters:{initProcessEnabled:true},pseudoTerminal:true});
const status=()=>['Uid:\t1000\t1000\t1000\t1000','Gid:\t1000\t1000\t1000\t1000',
  ...['CapInh','CapPrm','CapEff','CapBnd','CapAmb'].map(k=>k+':\t0000000000000000'),'NoNewPrivs:\t1'].join('\n');

describe('maintenance task privilege boundary',()=>{
  it('preserves the workload and credential references while hardening its process',()=>{
    const original=container(),before=structuredClone(original),result=hardenMaintenanceContainer(original);
    expect(result).toMatchObject({user:'1000:1000',pseudoTerminal:false,
      entryPoint:['/usr/bin/setpriv','--no-new-privs','--','/usr/local/bin/node'],
      linuxParameters:{initProcessEnabled:true,capabilities:{add:[],drop:['ALL']}}});
    for(const key of ['name','image','command','environment','secrets'])expect(result[key]).toEqual(before[key]);
    expect(original).toEqual(before);expect(hardenMaintenanceContainer(result)).toEqual(result);
    expect(()=>assertHardenedMaintenanceContainer(result)).not.toThrow();
  });
  it('rejects root, privilege escalation, extra capabilities and entrypoint drift',()=>{
    const good=hardenMaintenanceContainer(container());
    for(const mutate of [c=>{c.user='0';},c=>{delete c.user;},c=>{c.privileged=true;},
      c=>{c.entryPoint=['node'];},c=>{c.entryPoint.splice(1,1);},
      c=>{c.linuxParameters.capabilities.add=['SYS_ADMIN'];},c=>{c.linuxParameters.capabilities.drop=[];}]){
      const bad=structuredClone(good);mutate(bad);expect(()=>assertHardenedMaintenanceContainer(bad)).toThrow('MaintenanceTaskPrivileges');
    }
    expect(()=>hardenMaintenanceContainer({...container(),entryPoint:['sh','-c']})).toThrow('MaintenanceTaskPrivileges');
    expect(()=>hardenMaintenanceContainer({...container(),privileged:true})).toThrow('MaintenanceTaskPrivileges');
  });
  it('requires real and saved IDs, every capability set and no-new-privileges to agree',()=>{
    expect(()=>assertMaintenanceProcess(status(),1000,1000)).not.toThrow();
    for(const bad of [status().replace('Uid:\t1000\t1000\t1000\t1000','Uid:\t1000\t1000\t0\t1000'),
      status().replace('Gid:\t1000','Gid:\t0'),status().replace('NoNewPrivs:\t1','NoNewPrivs:\t0'),
      status().replace('CapBnd:\t0000000000000000','CapBnd:\t0000000000000001'),
      status().replace('CapEff:\t0000000000000000','CapEff:\tinvalid'),
      status().replace('CapAmb:\t0000000000000000',''),status()+'\nNoNewPrivs:\t1'])
      expect(()=>assertMaintenanceProcess(bad,1000,1000)).toThrow('MaintenanceProcessPrivileges');
    expect(()=>assertMaintenanceProcess(status(),0,1000)).toThrow('MaintenanceProcessPrivileges');
    expect(()=>assertMaintenanceProcess(status(),1000,0)).toThrow('MaintenanceProcessPrivileges');
  });
});
