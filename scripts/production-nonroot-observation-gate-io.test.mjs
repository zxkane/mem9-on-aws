import {test,expect,vi,beforeEach,afterEach} from 'vitest';
import {createHash} from 'node:crypto';
// Raw kernel/filesystem model only. No native completion, provider response or
// high-level verification function is replaced by a success result.
const model=vi.hoisted(()=>({rows:new Map(),fds:new Map(),next:10,reads:[],opens:[],stats:new Map(),change:null,onMaps:null,calls:[],peakFds:0}));
const metadata=vi.hoisted(()=>row=>({dev:row.dev??1,ino:row.ino??20,size:row.size??row.bytes.length,mode:row.mode??493,uid:row.uid??0,gid:0,mtimeMs:1,ctimeMs:1,isFile:()=>true}));
vi.mock('node:fs',()=>({
 constants:{O_RDONLY:0,O_NONBLOCK:2048},
 openSync(path){model.calls.push('open');if(!model.rows.has(path))throw Object.assign(Error('missing'),{code:'ENOENT'});const fd=model.next++;model.fds.set(fd,{path,row:model.rows.get(path),offset:0});model.peakFds=Math.max(model.peakFds,model.fds.size);model.opens.push(path);if(path==='/proc/self/maps'&&model.onMaps)model.onMaps();return fd;},
 closeSync(fd){model.calls.push('close');if(!model.fds.delete(fd))throw Error('bad fd');},
 readSync(fd,buffer){const r=model.fds.get(fd),bytes=r.row.bytes;const n=Math.min(buffer.length,bytes.length-r.offset);bytes.copy(buffer,0,r.offset,r.offset+n);r.offset+=n;model.reads.push({path:r.path,n,requested:buffer.length});return n;},
 realpathSync(path){model.calls.push('realpath');return model.rows.get(path)?.resolvedPath??path;},
 fstatSync(fd,options){model.calls.push('fstat');if(options?.bigint!==true)throw Error('precise stat required');const {path,row}=model.fds.get(fd);const ordinal=(model.stats.get(path)??0)+1;model.stats.set(path,ordinal);const stat=metadata(row);if(model.change)model.change(path,ordinal,stat);return stat;},
 statSync(path,options){model.calls.push('stat');if(options?.bigint!==true)throw Error('precise stat required');return metadata(model.rows.get(path));},
}));
import {runNodeObservationCommonGate} from './lib/production-nonroot-observation-gate.mjs';
const kernel=['Uid:\t1000 1000 1000 1000','Gid:\t1000 1000 1000 1000','Groups:\t1000',...['Inh','Prm','Eff','Bnd','Amb'].map(k=>'Cap'+k+':\t0000000000000000'),'NoNewPrivs:\t1'].join('\n')+'\n';
const node='/usr/local/bin/node',lib='/lib/aarch64-linux-gnu/libc.so.6';
const sha=b=>createHash('sha256').update(b).digest('hex');
let arch,version;
beforeEach(()=>{
 model.rows.clear();model.fds.clear();model.stats.clear();model.reads=[];model.opens=[];model.change=null;model.onMaps=null;model.calls=[];model.peakFds=0;
 model.rows.set('/proc/self/status',{bytes:Buffer.from(kernel)});
 model.rows.set('/proc/self/maps',{bytes:Buffer.from('1000-2000 r-xp 0 00:01 20 '+node+'\n2000-3000 r-xp 0 00:01 21 '+lib+'\n')});
 model.rows.set(node,{bytes:Buffer.from('synthetic-node-file'),ino:20});model.rows.set(lib,{bytes:Buffer.from('synthetic-library-file'),ino:21});
 model.rows.set('/proc/self/exe',{...model.rows.get(node),resolvedPath:node});
 arch=Object.getOwnPropertyDescriptor(process,'arch');version=Object.getOwnPropertyDescriptor(process,'version');
 Object.defineProperty(process,'arch',{...arch,value:'arm64'});Object.defineProperty(process,'version',{...version,value:'v24.0.0'});
});
afterEach(()=>{Object.defineProperty(process,'arch',arch);Object.defineProperty(process,'version',version);});
const files=()=>[node,lib].map(path=>({path,resolvedPath:path,sha256:sha(model.rows.get(path).bytes),size:model.rows.get(path).bytes.length,mode:493,uid:0,gid:0}));
test('reads and hashes each supplied original file and both kernel statuses, then closes every FD',async()=>{
 const result=await runNodeObservationCommonGate(files());expect(result.files).toHaveLength(2);
 expect(result.readBytes).toBe(model.reads.reduce((n,r)=>n+r.n,0));expect(model.fds.size).toBe(0);
 expect(model.opens.filter(p=>p==='/proc/self/status')).toHaveLength(2);expect(model.opens).toContain('/proc/self/maps');
});
test('an omitted mapped library rejects after complete maps read',async()=>{
 await expect(runNodeObservationCommonGate(files().slice(0,1))).rejects.toThrow('DataObservationSecurityGate');expect(model.fds.size).toBe(0);
});
test('wrong original content hash rejects and closes its FD',async()=>{
 const f=files();f[0].sha256='f'.repeat(64);await expect(runNodeObservationCommonGate(f)).rejects.toThrow('DataObservationSecurityGate');expect(model.fds.size).toBe(0);
});
test('changed inode between pre/post hash metadata rejects',async()=>{
 model.change=(path,n,s)=>{if(path===node&&n===2)s.ino++;};
 await expect(runNodeObservationCommonGate(files())).rejects.toThrow('DataObservationSecurityGate');expect(model.fds.size).toBe(0);
});
test('unexpected symlink resolution rejects before reading the file',async()=>{
 model.rows.get(node).resolvedPath='/tmp/foreign';await expect(runNodeObservationCommonGate(files())).rejects.toThrow('DataObservationSecurityGate');expect(model.opens).not.toContain(node);expect(model.fds.size).toBe(0);
});
test('file growth is bounded by the declared size plus one and rejects',async()=>{
 const f=files(),row=model.rows.get(node);row.size=row.bytes.length;row.bytes=Buffer.concat([row.bytes,Buffer.from('extra')]);
 await expect(runNodeObservationCommonGate(f)).rejects.toThrow('DataObservationSecurityGate');expect(model.fds.size).toBe(0);
 expect(model.reads.filter(r=>r.path===node).reduce((n,r)=>n+r.n,0)).toBe(f[0].size+1);
});
test('security failure precedes all image file IO',async()=>{
 model.rows.get('/proc/self/status').bytes=Buffer.from(kernel.replace('NoNewPrivs:\t1','NoNewPrivs:\t0'));
 await expect(runNodeObservationCommonGate(files())).rejects.toThrow('DataObservationSecurityGate');expect(model.opens).toEqual(['/proc/self/status']);expect(model.fds.size).toBe(0);
});
test('invalid input representation invokes no filesystem API',()=>{
 let called=false;const input=[{get path(){called=true;return node;}}];
 expect(()=>runNodeObservationCommonGate(input)).toThrow();expect(called).toBe(false);expect(model.opens).toEqual([]);
});
test('matching path with a different mapped inode rejects',async()=>{
 const r=model.rows.get('/proc/self/maps');r.bytes=Buffer.from(r.bytes.toString().replace('00:01 20','00:01 999'));
 await expect(runNodeObservationCommonGate(files())).rejects.toThrow('DataObservationSecurityGate');expect(model.fds.size).toBe(0);
});
test('matching inode with a different mapped device rejects',async()=>{
 const r=model.rows.get('/proc/self/maps');r.bytes=Buffer.from(r.bytes.toString().replace('00:01 20','00:02 20'));
 await expect(runNodeObservationCommonGate(files())).rejects.toThrow('DataObservationSecurityGate');expect(model.fds.size).toBe(0);
});
test('empty maps cannot establish required interpreter coverage',async()=>{
 model.rows.get('/proc/self/maps').bytes=Buffer.alloc(0);
 await expect(runNodeObservationCommonGate(files())).rejects.toThrow('DataObservationSecurityGate');expect(model.fds.size).toBe(0);
});
test('anonymous-only or library-only maps cannot substitute for the interpreter',async()=>{
 for(const maps of ['1000-2000 rw-p 0 00:00 0 [heap]\n','1000-2000 r-xp 0 00:01 21 '+lib+'\n']){
  model.rows.get('/proc/self/maps').bytes=Buffer.from(maps);await expect(runNodeObservationCommonGate(files())).rejects.toThrow('DataObservationSecurityGate');expect(model.fds.size).toBe(0);
 }
});
test('malformed map rows cannot be ignored',async()=>{
 model.rows.get('/proc/self/maps').bytes=Buffer.from('not a maps record\n');
 await expect(runNodeObservationCommonGate(files())).rejects.toThrow('DataObservationSecurityGate');expect(model.fds.size).toBe(0);
});
test('current executable must be the verified mapped interpreter instance',async()=>{
 model.rows.get('/proc/self/exe').ino=999;
 await expect(runNodeObservationCommonGate(files())).rejects.toThrow('DataObservationSecurityGate');expect(model.fds.size).toBe(0);
});
test('same-name path replacement after hashing cannot pass using the old mapped FD',async()=>{
 model.onMaps=()=>model.rows.set(node,{...model.rows.get(node),ino:999});
 await expect(runNodeObservationCommonGate(files())).rejects.toThrow('DataObservationSecurityGate');expect(model.fds.size).toBe(0);
});
test('ordinary anonymous/JIT and kernel mappings remain allowed beside verified files',async()=>{
 const r=model.rows.get('/proc/self/maps');r.bytes=Buffer.concat([r.bytes,Buffer.from('3000-4000 rw-p 0 00:00 0\n4000-5000 rwxp 0 00:00 0 [anon:V8]\n5000-6000 r-xp 0 00:00 0 [vdso]\n')]);
 await expect(runNodeObservationCommonGate(files())).resolves.toHaveProperty('files');expect(model.fds.size).toBe(0);
});
test('every named alias is rechecked after maps even when another alias shares its inode',async()=>{
 const alias='/usr/bin/node',f=files();
 model.rows.set(alias,{...model.rows.get(node),resolvedPath:node});f.push({...f[0],path:alias});
 model.onMaps=()=>model.rows.set(node,{...model.rows.get(node),ino:999});
 await expect(runNodeObservationCommonGate(f)).rejects.toThrow('DataObservationSecurityGate');expect(model.fds.size).toBe(0);
});
test('stable aliases keep separate opened-file and named-path rechecks',async()=>{
 const alias='/usr/bin/node',f=files();model.rows.set(alias,{...model.rows.get(node),resolvedPath:node});f.push({...f[0],path:alias});
 await expect(runNodeObservationCommonGate(f)).resolves.toHaveProperty('files');
 expect(model.stats.get(node)).toBe(3);expect(model.stats.get(alias)).toBe(3);expect(model.fds.size).toBe(0);
});
test('64-bit inode and high device fields retain exact identity',async()=>{
 const inode=(1n<<60n)+1n,device=0xfedcb123456789abn;
 Object.assign(model.rows.get(node),{ino:inode,dev:device});Object.assign(model.rows.get('/proc/self/exe'),{ino:inode,dev:device});
 const maps=model.rows.get('/proc/self/maps');
 maps.bytes=Buffer.from('1000-2000 r-xp 0 fedcb789:123456ab '+inode+' '+node+'\n2000-3000 r-xp 0 00:01 21 '+lib+'\n');
 await expect(runNodeObservationCommonGate(files())).resolves.toHaveProperty('files');expect(model.fds.size).toBe(0);
 maps.bytes=Buffer.from(maps.bytes.toString().replace(String(inode),String(inode+1n)));
 await expect(runNodeObservationCommonGate(files())).rejects.toThrow('DataObservationSecurityGate');expect(model.fds.size).toBe(0);
});
test('metadata and retained descriptor work is bounded per complete original file row',async()=>{
 const f=files();await runNodeObservationCommonGate(f);
 const count=kind=>model.calls.filter(k=>k===kind).length;
 expect({open:count('open'),close:count('close'),fstat:count('fstat'),stat:count('stat'),realpath:count('realpath')})
  .toEqual({open:f.length+4,close:f.length+4,fstat:3*f.length+2,stat:2*f.length,realpath:3*f.length+2});
 expect(model.peakFds).toBe(f.length+2);expect(model.fds.size).toBe(0);
});
test('the approved exact io_uring mapping retains all raw read accounting',async()=>{
 const r=model.rows.get('/proc/self/maps');r.bytes=Buffer.concat([r.bytes,Buffer.from('3000-4000 rw-s 0 00:11 123 anon_inode:[io_uring]\n')]);
 const result=await runNodeObservationCommonGate(files());expect(result.files).toHaveLength(2);
 expect(model.reads.filter(r=>r.path==='/proc/self/maps').reduce((n,r)=>n+r.n,0)).toBe(r.bytes.length);
 expect(result.readBytes).toBe(model.reads.reduce((n,r)=>n+r.n,0));expect(model.fds.size).toBe(0);
});
test.each([
 ['executable','rwxs','00:11','123','anon_inode:[io_uring]'],
 ['read-only','r--s','00:11','123','anon_inode:[io_uring]'],
 ['private','rw-p','00:11','123','anon_inode:[io_uring]'],
 ['nonzero major','rw-s','01:11','123','anon_inode:[io_uring]'],
 ['zero inode','rw-s','00:11','0','anon_inode:[io_uring]'],
 ['foreign kernel name','rw-s','00:11','123','anon_inode:[foreign]'],
 ['name suffix','rw-s','00:11','123','anon_inode:[io_uring]-extra'],
 ['trailing name text','rw-s','00:11','123','anon_inode:[io_uring] extra'],
])('io_uring exception denies %s variant',async(_name,permissions,device,inode,path)=>{
 const r=model.rows.get('/proc/self/maps');r.bytes=Buffer.concat([r.bytes,Buffer.from(`3000-4000 ${permissions} 0 ${device} ${inode} ${path}\n`)]);
 await expect(runNodeObservationCommonGate(files())).rejects.toThrow('DataObservationSecurityGate');expect(model.fds.size).toBe(0);
});
test('io_uring cannot substitute for the verified executable mapping',async()=>{
 model.rows.get('/proc/self/maps').bytes=Buffer.from('3000-4000 rw-s 0 00:11 123 anon_inode:[io_uring]\n');
 await expect(runNodeObservationCommonGate(files())).rejects.toThrow('DataObservationSecurityGate');expect(model.fds.size).toBe(0);
});
test('io_uring does not bypass ordinary mapped-file instance validation',async()=>{
 model.rows.get('/proc/self/maps').bytes=Buffer.from('1000-2000 r-xp 0 00:01 999 '+node+'\n3000-4000 rw-s 0 00:11 123 anon_inode:[io_uring]\n');
 await expect(runNodeObservationCommonGate(files())).rejects.toThrow('DataObservationSecurityGate');expect(model.fds.size).toBe(0);
});
