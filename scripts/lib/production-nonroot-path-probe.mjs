// Fixed, credential-free artifact probe. The host passes only canonical paths.
import {readFileSync,lstatSync,realpathSync} from 'node:fs';
import {posix} from 'node:path';

const need=ok=>{if(!ok)throw Error('NonrootArtifactProbeRejected');};
try{
 const status=readFileSync('/proc/self/status','utf8');need(status.length<=65536);
 const fields=new Map(status.trim().split('\n').map(line=>{const at=line.indexOf(':');return [line.slice(0,at),line.slice(at+1).trim()];}));
 const ids=name=>{const values=(fields.get(name)??'').split(/\s+/).map(Number);need(values.length===4&&values.every(n=>n===1000));return values;};
 const identity={uid:ids('Uid'),gid:ids('Gid'),groups:(fields.get('Groups')??'').split(/\s+/).filter(Boolean).map(Number)};
 need(identity.groups.every(n=>n===1000));
 for(const name of ['CapInh','CapPrm','CapEff','CapBnd','CapAmb']){const value=fields.get(name);need(typeof value==='string'&&/^0{16}$/.test(value));identity[name]=value;}
 need(fields.get('NoNewPrivs')==='1');identity.noNewPrivs=1;
 need(process.argv.length===2&&process.argv[1].length<=65536);
 const paths=JSON.parse(process.argv[1]);
 need(Array.isArray(paths)&&paths.length>0&&paths.length<=512&&paths[0]==='/'&&new Set(paths).size===paths.length);
 for(const path of paths)need(typeof path==='string'&&path.length<=4096&&/^\/[A-Za-z0-9_./+-]*$/.test(path)&&posix.normalize(path)===path&&(path==='/'||!path.endsWith('/')));
 const observations=paths.map(path=>{const stat=lstatSync(path),resolvedPath=realpathSync(path);need(stat.isDirectory()||stat.isFile()||stat.isSymbolicLink());return {path,resolvedPath,type:stat.isSymbolicLink()?'symlink':stat.isDirectory()?'directory':'file',uid:stat.uid,gid:stat.gid,mode:stat.mode&0o7777};});
 const output=JSON.stringify({version:1,kind:'control-runtime-path-observation',identity,observations});need(Buffer.byteLength(output)<=262144);
 process.stdout.write(output+'\n');
}catch{process.stderr.write('NonrootArtifactProbeRejected\n');process.exitCode=1;}
