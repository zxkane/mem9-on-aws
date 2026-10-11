import {test} from 'vitest';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {rolldown} from 'rolldown';
import {minifySync} from 'rolldown/utils';
import {OBSERVATION_FRAME_LIMITS,encodeObservationFrames,createObservationFrameDecoder,describeObservationFrameGeometry,observationFrameEncoderSource} from './lib/production-nonroot-observation-frames.mjs';
const binding='a'.repeat(64),capture='b'.repeat(32),sha=b=>createHash('sha256').update(b).digest('hex');
const scope={binding,capture},raw=Buffer.alloc(8193,123);
// Independent encoding of the reviewed prototype wire, not runtime authority.
function fixtureFrames(bytes,ids=scope){
 const parts=Math.ceil(bytes.length/2048),whole=sha(bytes),out=[];
 for(let part=0;part<parts+2;part++){
  const kind=part===0?'B':part===parts+1?'E':'D',body=kind==='D'?bytes.subarray((part-1)*2048,part*2048):Buffer.alloc(0);
  out.push(Buffer.from('\nMEM9-OBS2|'+[ids.binding,ids.capture,kind,part,parts,bytes.length,whole,sha(body),body.toString('base64')].join('|')+'\n'));
 }
 return out;
}
const wire=fixtureFrames(raw);
const decoder=(options={})=>createObservationFrameDecoder({bindings:[binding],maxCaptures:1,maxInputBytes:3000000,...options});
function read(parts,options){const d=decoder(options);for(const p of parts)d.push(p);return d.finish();}
function change(frame,index,value){const x=frame.toString().slice(1,-1).split('|');x[index]=value;return Buffer.from('\n'+x.join('|')+'\n');}

test('canonical encoder matches independent fixture wire for one/partial/full pieces',()=>{
 for(const length of [1,2047,2048,2049,8193]){const bytes=Buffer.alloc(length,237);assert.deepEqual(encodeObservationFrames({...scope,bytes}),fixtureFrames(bytes));}
});
test('strict immutable limits and closed geometry retain1MiB and514frames',()=>{
 assert(Object.isFrozen(OBSERVATION_FRAME_LIMITS));assert.deepEqual(OBSERVATION_FRAME_LIMITS,{frameBytes:4096,partRawBytes:2048,rawBytes:1048576});
 assert.deepEqual(describeObservationFrameGeometry({rawBytes:1048576}),{rawBytes:1048576,parts:512,frameCount:514,maxWireBytes:2105344});
 for(const rawBytes of [0,-1,1048577,Infinity,1.5])assert.throws(()=>describeObservationFrameGeometry({rawBytes}),/RawBound/);
 assert.throws(()=>describeObservationFrameGeometry({rawBytes:1,authority:true}),/Fields/);
});
test('complete record returns exact raw bytes and total wire/non-frame counts',()=>{
 const r=read(wire);assert.deepEqual(r.captures,[{...scope,bytes:raw,sha256:sha(raw),frameCount:wire.length}]);
 assert.equal(r.wireBytes,wire.reduce((n,b)=>n+b.length,0));assert.equal(r.nonFrameBytes,0);assert.equal(r.nonFrameSha256,sha(Buffer.alloc(0)));
 assert.deepEqual(Object.keys(r).sort(),['captures','nonFrameBytes','nonFrameSha256','wireBytes']);
});
test('complete1MiB payload has514bounded frames and no truncation',()=>{
 const bytes=Buffer.alloc(1048576,237),f=encodeObservationFrames({...scope,bytes});assert.equal(f.length,514);assert(f.every(b=>b.length<=4096));assert.deepEqual(read(f).captures[0].bytes,bytes);
});
test('every-byte segments and empty segments are not EOF',()=>{
 const bytes=Buffer.concat(fixtureFrames(Buffer.from('split sample'))),parts=[];for(const byte of bytes)parts.push(Buffer.alloc(0),Buffer.from([byte]));
 assert.deepEqual(read(parts).captures[0].bytes,Buffer.from('split sample'));
});
test('all offsets through a complete frame split correctly across chunks',()=>{
 const small=fixtureFrames(Buffer.from('sample'));
 for(let at=0;at<small[1].length;at++)assert.deepEqual(read([small[0],small[1].subarray(0,at),small[1].subarray(at),small[2]]).captures[0].bytes,Buffer.from('sample'));
});
test('complete frames reorder by index, with END arriving before BEGIN',()=>assert.deepEqual(read([...wire].reverse()).captures[0].bytes,raw));
test('multiple interleaved captures return deterministic binding/capture order',()=>{
 const ids=[{binding:'d'.repeat(64),capture:'1'.repeat(32)},{binding,capture:'c'.repeat(32)},{binding,capture:'0'.repeat(32)}];
 const sets=ids.map((s,i)=>fixtureFrames(Buffer.alloc(2049+i,i+1),s)),parts=[];for(let j=3;j>=0;j--)for(let i=2;i>=0;i--)parts.push(sets[i][j]);
 const r=read(parts,{bindings:[ids[0].binding,binding],maxCaptures:3});assert.deepEqual(r.captures.map(r=>({binding:r.binding,capture:r.capture})),[ids[2],ids[1],ids[0]]);
 assert.deepEqual(r.captures.map(r=>r.bytes.length),[2051,2050,2049]);
});
test('ordinary app bytes, split UTF8 and final LF are counted/hashed without returning content',()=>{
 const app=Buffer.from('partial 漢字\nno final token\n'),r=read([app.subarray(0,10),wire[0],app.subarray(10,12),...wire.slice(1),app.subarray(12)]);
 assert.equal(r.nonFrameBytes,app.length);assert.equal(r.nonFrameSha256,sha(app));assert(!Object.hasOwn(r,'application'));
});
test('large bounded noise is streamed without changing payload reconstruction',()=>{
 const app=Buffer.alloc(1200000,120),r=read([app,...wire]);assert.equal(r.nonFrameBytes,app.length);assert.equal(r.nonFrameSha256,sha(app));
});
test('mismatched partial markers are ordinary bytes; unfinished magic remains ambiguous',()=>{
 const app=Buffer.from('\nMEMORY\nM-noise\n\n'),r=read([...wire,app]);assert.equal(r.nonFrameBytes,app.length);assert.equal(r.nonFrameSha256,sha(app));
 assert.throws(()=>read([...wire,Buffer.from('\nMEM9-OB')]),/Truncated/);
});
test('missing BEGIN/DATA/END and duplicate logical frames reject, including identical duplicates',()=>{
 for(const parts of [wire.slice(1),wire.slice(0,-1),wire.filter((_,i)=>i!==2),[...wire,wire[1]]])assert.throws(()=>read(parts),/Incomplete|Duplicate/);
});
test('foreign bindings and capture-capacity overflow reject before acceptance',()=>{
 assert.throws(()=>read([change(wire[0],1,'f'.repeat(64))]),/Binding/);
 assert.throws(()=>read([...wire,...fixtureFrames(Buffer.from('other'),{binding,capture:'c'.repeat(32)})]),/CaptureBound/);
 assert.throws(()=>read([change(wire[0],2,'BAD')]),/Binding/);
});
test('ASCII, exact field shape, safe integers, indices and stable manifests are strict',()=>{
 const bad=[change(wire[0],4,'00'),change(wire[0],4,'99'),change(wire[0],5,'9'.repeat(100)),change(wire[0],6,'1048577'),change(wire[0],3,'BEGIN'),
  change(wire[0],7,'F'.repeat(64)),Buffer.from(wire[0].toString().replace('|B|','|\x7f|')),Buffer.from(wire[0].toString().replace(/\n$/,'|sensitive-text\n'))];
 for(const part of bad)assert.throws(()=>read([part]),e=>/^NonrootObservation[A-Za-z]+$/.test(e.message));
 assert.throws(()=>read([wire[0],change(wire[1],6,'8194')]),/ManifestChanged/);
});
test('base64 canonical padding bits and decoded piece length reject permissive decoder tricks',()=>{
 const f=fixtureFrames(Buffer.from('a'));for(const value of ['YR==','YQ=','YQ===','Y Q=='])assert.throws(()=>read([f[0],change(f[1],9,value),f[2]]),/Encoding/);
 assert.throws(()=>read([f[0],change(f[1],9,''),f[2]]),/Piece/);
});
test('BEGIN/END payloads and altered binary pieces cannot pass',()=>{
 const f=fixtureFrames(Buffer.from('a'));assert.throws(()=>read([change(f[0],9,'YQ=='),...f.slice(1)]),/Piece/);
 assert.throws(()=>read([f[0],change(f[1],9,'Yg=='),f[2]]),/Piece/);assert.throws(()=>read([...f.slice(0,-1),change(f[2],9,'YQ==')]),/Piece/);
});
test('whole hash is independently checked after all valid individual pieces',()=>assert.throws(()=>read(wire.map(b=>change(b,7,'f'.repeat(64)))),/WholeHash/));
test('oversized/truncated frames and intra-frame app bytes are never repaired',()=>{
 assert.throws(()=>read([Buffer.from('\nMEM9-OBS2|'+'x'.repeat(4096))]),/FrameBound/);
 assert.throws(()=>read([...wire.slice(0,-1),wire.at(-1).subarray(0,-1)]),/Truncated/);
 assert.throws(()=>read([wire[0],Buffer.concat([wire[1].subarray(0,100),Buffer.from('APP'),wire[1].subarray(100)]),...wire.slice(2)]));
});
test('input bound rejects before processing even a malformed over-limit chunk and stays held',()=>{
 const d=decoder({maxInputBytes:10});assert.throws(()=>d.push(Buffer.from('\nMEM9-OBS2|invalid')),/InputBound/);
 assert.throws(()=>d.push(Buffer.alloc(0)),/Held/);assert.throws(()=>d.finish(),/Held/);
});
test('caller buffer mutation cannot rewrite stored pieces and completion is one-shot',()=>{
 const d=decoder(),copies=wire.map(b=>Buffer.from(b));for(const b of copies){d.push(b);b.fill(0);}assert.deepEqual(d.finish().captures[0].bytes,raw);
 assert.throws(()=>d.finish(),/Finished/);assert.throws(()=>d.push(Buffer.alloc(0)),/Finished/);
});
test('declaration/callback/authority extensions and invalid encodes reject',()=>{
 const valid={bindings:[binding],maxCaptures:1,maxInputBytes:100};
 for(const k of ['authority','onApplication','reserveLocal','check'])assert.throws(()=>createObservationFrameDecoder({...valid,[k]:()=>{}}),/Fields/);
 for(const maxCaptures of [0,1.5,Infinity])assert.throws(()=>createObservationFrameDecoder({...valid,maxCaptures}),/InputBound/);
 assert.throws(()=>createObservationFrameDecoder({...valid,bindings:[binding,binding]}),/Binding/);
 for(const bytes of [Buffer.alloc(0),Buffer.alloc(1048577),'raw'])assert.throws(()=>encodeObservationFrames({...scope,bytes}));
 assert.throws(()=>encodeObservationFrames({...scope,bytes:Buffer.from('a'),complete:true}),/Fields/);
 assert.throws(()=>read([Buffer.from('ordinary only')]),/Incomplete/);
});

function nativeSource(source){
 const r=spawnSync(process.execPath,['--input-type=module','-e',source],{env:{},encoding:'utf8',timeout:10000,maxBuffer:131072});
 assert.ifError(r.error);assert.equal(r.status,0,r.stderr);assert.equal(r.stderr,'');return r.stdout;
}
function verifyGeneratedEncoder(source){
 assert(!/__vite_ssr_|__require|__name\(/.test(source));
 const result=JSON.parse(nativeSource(source+`
import {createHash as testDigest} from 'node:crypto';
const ids={binding:'a'.repeat(64),capture:'b'.repeat(32)};
const cases=[1,2048,2049,1048576].map(size=>{
 const frames=encodeObservationFrames({...ids,bytes:Buffer.alloc(size,237)});
 if(frames.some(b=>b.length>4096))throw Error('FrameTooLarge');
 return {size,count:frames.length,wireHash:testDigest('sha256').update(Buffer.concat(frames)).digest('hex')};
});
let rejected=0;
for(const input of [{...ids,bytes:Buffer.alloc(0)},{...ids,bytes:Buffer.alloc(1048577)},
 {...ids,binding:'foreign',bytes:Buffer.from('a')},{...ids,bytes:'not-buffer'},
 {...ids,bytes:Buffer.from('a'),callback:'untrusted'}]){
 try{encodeObservationFrames(input);}catch(e){if(!/^NonrootObservation[A-Za-z]+$/.test(e.message))throw e;rejected++;}
}
if(rejected!==5)throw Error('MissingRejection');
process.stdout.write(JSON.stringify({cases,rejected}));`));
 assert.equal(result.rejected,5);
 for(const c of result.cases){const frames=encodeObservationFrames({...scope,bytes:Buffer.alloc(c.size,237)});assert.equal(c.count,frames.length);assert.equal(c.wireHash,sha(Buffer.concat(frames)));}
}
test('generated encoder source executes in native Node with exact wire at1/2048/2049/1MiB and invalid inputs',()=>{
 verifyGeneratedEncoder(observationFrameEncoderSource());
});
test('encoder source generator accepts no parameters or replacement helpers',()=>{
 for(const args of [[undefined],[{}],[()=>{}]])assert.throws(()=>observationFrameEncoderSource(...args),/NonrootObservationSourceArguments/);
 const source=observationFrameEncoderSource();assert.equal(source,observationFrameEncoderSource());
 assert(source.includes("from 'node:crypto'"));assert(source.includes('const encodeObservationFrames='));
});
test('actual Rolldown bundle plus current compact options preserve self-contained native generated source',async t=>{
 const directory=await mkdtemp(join(tmpdir(),'observation-encoder-source-'));t.onTestFinished(()=>rm(directory,{recursive:true,force:true}));
 const input=fileURLToPath(new URL('./lib/production-nonroot-observation-frames.mjs',import.meta.url));
 const bundle=await rolldown({input,platform:'node',onwarn:warning=>{throw Error(warning.message);}});
 let generated;try{generated=await bundle.generate({format:'esm',codeSplitting:false});}finally{await bundle.close();}
 const chunks=generated.output.filter(x=>x.type==='chunk');assert.equal(chunks.length,1);
 const compact=minifySync('index.mjs',chunks[0].code,{module:true,compress:false,mangle:false,format:{asciiOnly:false,legalComments:'none'}});
 const path=join(directory,'bundle.mjs');await writeFile(path,compact.code,{mode:0o600});
 const source=nativeSource('import {observationFrameEncoderSource} from '+JSON.stringify(pathToFileURL(path).href)+';process.stdout.write(observationFrameEncoderSource());');
 verifyGeneratedEncoder(source);
});
