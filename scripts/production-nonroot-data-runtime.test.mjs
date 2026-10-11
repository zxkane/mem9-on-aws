import {test,expect} from 'vitest';
import {describeGoDataPathEvidence,verifyDataRuntimePathEvidence} from './lib/production-nonroot-launch.mjs';
const image={rootDigest:'sha256:'+'1'.repeat(64),arm64Digest:'sha256:'+'2'.repeat(64),configDigest:'sha256:'+'3'.repeat(64)};
const path='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
const file=(name,digest,size)=>({path:name,type:'file',mode:0o755,uid:0,gid:0,pax:{},content:{sha256:digest.repeat(64),size}});
function fixture(){
 const entrypoint=file('usr/local/bin/entrypoint.sh','4',80),executable=file('usr/local/bin/mnemo-server','5',1024),sourceFile={path:'docker/mnemo-server/entrypoint.sh',sha256:entrypoint.content.sha256,bytes:80};
 const args={component:'mnemo-server',image,path,entrypoint,executable,sourceFile},context={component:'mnemo-server',key:'mnemo-server',contractVersion:2,image,config:{Env:['PATH='+path],Entrypoint:['/usr/local/bin/entrypoint.sh']},entries:[entrypoint,executable],sourceFile};
 return {args,context};
}
test('fresh Go evidence binds two fixed files and carries no fictional Node location',()=>{
 const f=fixture(),value=describeGoDataPathEvidence(f.args);expect(value.nodePath).toBe('not-applicable');expect(value).not.toHaveProperty('resolvedNode');
 expect(()=>verifyDataRuntimePathEvidence(value,f.context)).not.toThrow();
 for(const change of [v=>v.executable.sha256='6'.repeat(64),v=>v.entrypoint.path='/other',v=>v.nodePath='/usr/local/bin/node',v=>v.extra=true]){
  const bad=structuredClone(value);change(bad);expect(()=>verifyDataRuntimePathEvidence(bad,f.context)).toThrow();
 }
});
test('v1 Go decoding remains compatible; v2 requires the honest Go variant',()=>{
 const f=fixture(),old={image,path,resolvedNode:'/usr/local/bin/node'};
 expect(()=>verifyDataRuntimePathEvidence(old,{...f.context,contractVersion:1})).not.toThrow();expect(()=>verifyDataRuntimePathEvidence(old,f.context)).toThrow();
 expect(()=>verifyDataRuntimePathEvidence(old,{...f.context,contractVersion:3})).toThrow();
});
test.each(['qwen3-embed','llm-proxy','planner','executor'])('Node PATH and shadowing remain checked for %s',key=>{
 const component=['planner','executor'].includes(key)?'llm-proxy':key,node=file('usr/local/bin/node','7',1024),config={Env:['PATH='+path]},context={component,key,contractVersion:2,image,config,entries:[node]},value={image,path,resolvedNode:'/usr/local/bin/node'};
 expect(()=>verifyDataRuntimePathEvidence(value,context)).not.toThrow();
 expect(()=>verifyDataRuntimePathEvidence(value,{...context,entries:[file('usr/local/sbin/node','8',1024),node]})).toThrow(/NonrootDataNodeShadow/);
 expect(()=>verifyDataRuntimePathEvidence(value,{...context,entries:[]})).toThrow(/NonrootDataNodeShadow/);
 const go=fixture();expect(()=>verifyDataRuntimePathEvidence(describeGoDataPathEvidence(go.args),context)).toThrow();
});
test('Go file and source bindings reject a foreign component, mutable owner, privilege bits and script change',()=>{
 for(const change of [f=>f.args.component='llm-proxy',f=>f.args.executable.mode=0o4755,f=>f.args.executable.uid=1000,f=>f.args.executable.type='symlink',f=>f.args.sourceFile.sha256='0'.repeat(64)]){
  const f=fixture();change(f);expect(()=>describeGoDataPathEvidence(f.args)).toThrow();
 }
});
