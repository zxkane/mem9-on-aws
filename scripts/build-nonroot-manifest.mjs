import {readdirSync,lstatSync,writeFileSync} from 'node:fs';
import {readGuardArtifact} from '/bootstrap/nonroot-files.mjs';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';

const fail=()=>{throw Error('NonrootBuildManifest');};

/** Invoked inside the CONTROL image while files are still root-owned. The
 * whole application/package tree is retained, not a guessed import subset. */
export function buildNonrootManifest(){
 if(process.getuid()!==0)fail();
 const rows=[];let total=0;
 const file=path=>{
  const {realPath,sha256,size}=readGuardArtifact(path,134217728);
  if(!(realPath.startsWith('/bootstrap/')||realPath==='/usr/local/bin/node'))fail();
  total+=size;if(total>2147483648)fail();return {path,realPath,sha256,size};
 };
 const walk=directory=>{
  const stat=lstatSync(directory);if(!stat.isDirectory()||stat.uid!==0||stat.gid!==0||(stat.mode&0o7022)!==0||(stat.mode&0o005)!==0o005)fail();
  for(const name of readdirSync(directory).sort()){
   const path=join(directory,name);if(path==='/bootstrap/nonroot-manifest.json')continue;
   const entry=lstatSync(path);
   if(entry.isDirectory())walk(path);
   else if(entry.isFile()||entry.isSymbolicLink()){rows.push(file(path));if(rows.length>20000)fail();}
   else fail();
  }
 };
 walk('/bootstrap');rows.sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
 const result={version:1,kind:'guarded-control-files',files:rows,node:file('/usr/local/bin/node')};
 if(!['nonroot-dispatch.mjs','nonroot-identity.mjs','nonroot-files.mjs'].every(name=>rows.some(row=>row.path==='/bootstrap/'+name)))fail();
 writeFileSync('/bootstrap/nonroot-manifest.json',JSON.stringify(result)+'\n',{mode:0o644,flag:'wx'});
 return {files:rows.length,bytes:total};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 if(process.argv.length!==2)fail();console.log(JSON.stringify(buildNonrootManifest()));
}
