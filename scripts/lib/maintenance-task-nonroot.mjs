import {isDeepStrictEqual} from 'node:util';
import {readFile} from 'node:fs/promises';

export const MAINTENANCE_NODE_ENTRYPOINT=Object.freeze(['/usr/bin/setpriv','--no-new-privs','--','/usr/local/bin/node']);
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const need=(value,code='MaintenanceTaskPrivileges')=>{if(!value)throw Error(code);};

/** Constructs process settings; it does not authorize task or database access. */
export function hardenMaintenanceContainer(original){
  need(object(original)&&typeof original.name==='string'&&original.name.length>0);
  const c=structuredClone(original);
  need(c.entrypoint===undefined);
  need(c.privileged===undefined||c.privileged===false);
  need(c.user===undefined||['','root','0','0:0','root:root','node','1000','1000:1000'].includes(c.user));
  need(isDeepStrictEqual(c.entryPoint,['node'])||isDeepStrictEqual(c.entryPoint,MAINTENANCE_NODE_ENTRYPOINT));
  need(c.linuxParameters===undefined||object(c.linuxParameters));
  const caps=c.linuxParameters?.capabilities;
  if(caps!==undefined){
    need(object(caps)&&Object.keys(caps).every(k=>['add','drop'].includes(k)));
    need(caps.add===undefined||isDeepStrictEqual(caps.add,[]));
    need(caps.drop===undefined||isDeepStrictEqual(caps.drop,['ALL']));
  }
  c.user='1000:1000';c.entryPoint=[...MAINTENANCE_NODE_ENTRYPOINT];c.pseudoTerminal=false;
  c.linuxParameters={...c.linuxParameters,capabilities:{add:[],drop:['ALL']}};
  return c;
}

export function assertHardenedMaintenanceContainer(c){
  need(object(c)&&c.user==='1000:1000'&&(c.privileged===undefined||c.privileged===false)&&c.entrypoint===undefined&&c.pseudoTerminal!==true);
  need(isDeepStrictEqual(c.entryPoint,MAINTENANCE_NODE_ENTRYPOINT));
  need(object(c.linuxParameters?.capabilities)&&isDeepStrictEqual(c.linuxParameters.capabilities.drop,['ALL'])&&
    (c.linuxParameters.capabilities.add===undefined||isDeepStrictEqual(c.linuxParameters.capabilities.add,[]))&&
    Object.keys(c.linuxParameters.capabilities).every(k=>['add','drop'].includes(k)));
}

export function assertMaintenanceProcess(status,uid,gid){
  const check=value=>need(value,'MaintenanceProcessPrivileges');
  check(typeof status==='string'&&status.length<=65536&&uid===1000&&gid===1000);
  const fields=new Map();
  for(const line of status.split('\n')){
    const match=/^(Uid|Gid|CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs):\s*(.*?)\s*$/.exec(line);
    if(match){check(!fields.has(match[1]));fields.set(match[1],match[2]);}
  }
  for(const key of ['Uid','Gid'])check(fields.get(key)?.split(/\s+/).join(' ')==='1000 1000 1000 1000');
  for(const key of ['CapInh','CapPrm','CapEff','CapBnd','CapAmb'])check(/^0{1,32}$/.test(fields.get(key)??''));
  check(fields.get('NoNewPrivs')==='1');
}

/** Called only by the deployed worker CLI, before it reads credentials or opens a connection. */
export async function requireMaintenanceProcess(){
  assertMaintenanceProcess(await readFile('/proc/self/status','utf8'),process.getuid?.(),process.getgid?.());
}
