import {it,expect} from 'vitest';
import {mkdtempSync,writeFileSync,readFileSync,rmSync,statSync,utimesSync,renameSync,symlinkSync,chmodSync,unlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {createCiRootReplaySnapshot} from './lib/ci-smoke-root-replay.mjs';
import {calculateCiRootRequestCost} from './lib/ci-smoke-root-request-cost.mjs';
import {futureRootScope} from './lib/ci-smoke-owner-delivery.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
function fixture(checkpoint='deploy-prod/17',test={}){
 const directory=mkdtempSync(join(tmpdir(),'ci-root-snapshot-')),prefix='target-'+'a'.repeat(64),scope=futureRootScope(checkpoint),events=[],charges=[];
 const raw=Buffer.from(JSON.stringify({payload:'x'.repeat(140000)})),path=join(directory,prefix+'-root-request.json');writeFileSync(path,raw,{mode:0o600});
 const ref={path,sha256:sha(raw)},q=calculateCiRootRequestCost({checkpoint});let used=0;
 const snapshot=createCiRootReplaySnapshot({directory,prefix,scope,consume:n=>{used+=n;charges.push(n);expect(used).toBeLessThanOrEqual(q.work.replay);}},{afterRead:info=>{events.push(info);test.afterRead?.(info);}});
 return {directory,prefix,scope,events,charges,raw,ref,snapshot,close(){snapshot.close();rmSync(directory,{recursive:true,force:true});}};
}

it.each(['deploy-prod/17','deploy-prod/19'])('%s keeps authenticated bytes between exactly two full content scans',checkpoint=>{
 const f=fixture(checkpoint);try{
  const retained=f.snapshot.read(f.ref);expect(retained).toEqual(f.raw);const entryReads=f.events.length;
  // Intermediate callers use the retained verified result; their other guard
  // and budget checks do not call this private snapshot's read method again.
  for(let i=0;i<50000;i++)expect(retained.length).toBe(f.raw.length);
  expect(f.events.length).toBe(entryReads);expect(f.charges).toHaveLength(1);
  const result=f.snapshot.finish();expect(result).toEqual({entryBytes:f.raw.length+1,finishBytes:f.raw.length+1,contentScans:2});
  expect(f.events.filter(e=>e.phase==='entry')).toHaveLength(entryReads);expect(f.events.filter(e=>e.phase==='finish')).toHaveLength(entryReads);
  expect(f.charges).toEqual([8*(f.raw.length+1),f.raw.length+1]);expect(()=>f.snapshot.finish()).toThrow();
 }finally{f.close();}
});

it.each(['overwrite-restored-mtime','replace-identical','symlink','delete','permissions','directory-permissions'])('finish rejects %s before success',defect=>{
 const f=fixture();try{
  f.snapshot.read(f.ref);const before=statSync(f.ref.path);
  if(defect==='overwrite-restored-mtime'){const raw=Buffer.from(f.raw);raw[20]=raw[20]===120?121:120;writeFileSync(f.ref.path,raw);utimesSync(f.ref.path,before.atime,before.mtime);}
  if(defect==='replace-identical'){renameSync(f.ref.path,f.ref.path+'.old');writeFileSync(f.ref.path,f.raw,{mode:0o600});utimesSync(f.ref.path,before.atime,before.mtime);}
  if(defect==='symlink'){renameSync(f.ref.path,f.ref.path+'.old');symlinkSync(f.ref.path+'.old',f.ref.path);}
  if(defect==='delete')unlinkSync(f.ref.path);
  if(defect==='permissions')chmodSync(f.ref.path,0o644);
  if(defect==='directory-permissions')chmodSync(f.directory,0o755);
  expect(()=>f.snapshot.finish()).toThrow();expect(()=>f.snapshot.read(f.ref)).toThrow();
 }finally{f.close();}
});

it.each(['entry','finish'])('rejects a mutation during the %s content scan',phase=>{
 let f,changed=false;f=fixture('deploy-prod/17',{afterRead:info=>{
  if(info.phase===phase&&!changed){changed=true;const raw=readFileSync(info.path);raw[raw.length-20]=121;writeFileSync(info.path,raw);}
 }});
 try{if(phase==='entry')expect(()=>f.snapshot.read(f.ref)).toThrow();else{f.snapshot.read(f.ref);expect(()=>f.snapshot.finish()).toThrow();}expect(changed).toBe(true);}finally{f.close();}
});

it('rejects a wrong full SHA even when all file metadata is valid',()=>{
 const f=fixture();try{expect(()=>f.snapshot.read({...f.ref,sha256:'0'.repeat(64)})).toThrow('CiRootReplayHash');}finally{f.close();}
});

it('exhausted prepaid credits stop before acquiring content',()=>{
 const f=fixture();let reads=0;
 try{const snapshot=createCiRootReplaySnapshot({directory:f.directory,prefix:f.prefix,scope:f.scope,consume(){throw Error('Unpaid');}},{afterRead(){reads++;}});
  expect(()=>snapshot.read(f.ref)).toThrow('Unpaid');expect(reads).toBe(0);
 }finally{f.close();}
});

it.each(['deploy-prod/9','deploy-prod/21','deploy-prod/23'])('%s cannot open a LOCAL replay snapshot',checkpoint=>{
 const f=fixture();try{expect(()=>createCiRootReplaySnapshot({directory:f.directory,prefix:f.prefix,scope:futureRootScope(checkpoint),consume(){}})).toThrow('CiRootReplayScope');}finally{f.close();}
});

it('rejects sibling paths, duplicate acquisition and over-bound files',()=>{
 const f=fixture();try{
  expect(()=>f.snapshot.read({path:join(f.directory,'unowned.json'),sha256:'0'.repeat(64)})).toThrow('CiRootReplayPath');
 }finally{f.close();}
 const g=fixture();try{g.snapshot.read(g.ref);expect(()=>g.snapshot.read(g.ref)).toThrow('CiRootReplayDuplicate');}finally{g.close();}
 const h=fixture();try{writeFileSync(h.ref.path,Buffer.alloc(1048577));expect(()=>h.snapshot.read(h.ref)).toThrow('CiRootReplayIdentity');expect(h.charges).toHaveLength(0);}finally{h.close();}
});
