/** Pure framing DATA. Caller owns original prepayment, source/task/stream
 * authentication, charged event deduplication, secret screening and closure.
 * END and successful reassembly never authorize a workload or certify exit. */
import {createHash} from 'node:crypto';

// Keep the encoder, geometry and their primitive bindings in one fixed
// factory. The inline form serializes this same complete implementation.
function nonrootObservationFrameEncoderFactory(frameCreateHash){
const OBSERVATION_FRAME_LIMITS=Object.freeze({frameBytes:4096,partRawBytes:2048,rawBytes:1048576});
const {frameBytes:FRAME,partRawBytes:PIECE,rawBytes:RAW}=OBSERVATION_FRAME_LIMITS;
const MAGIC=Buffer.from('\nMEM9-OBS2|');
const EMPTY_HASH='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const need=(v,c)=>{if(!v)throw Error('NonrootObservation'+c);};
const positive=v=>Number.isSafeInteger(v)&&v>0;
const hex=(v,n)=>typeof v==='string'&&v.length===n&&/^[a-f0-9]+$/.test(v);
const sha=b=>frameCreateHash('sha256').update(b).digest('hex');
function exact(value,keys){
 need(value&&typeof value==='object'&&!Array.isArray(value),'Fields');
 const actual=Object.keys(value);need(actual.length===keys.length&&actual.every(k=>keys.includes(k)),'Fields');
}

function describeObservationFrameGeometry(value){
 exact(value,['rawBytes']);const {rawBytes}=value;need(positive(rawBytes)&&rawBytes<=RAW,'RawBound');
 const parts=Math.ceil(rawBytes/PIECE),frameCount=parts+2;
 return Object.freeze({rawBytes,parts,frameCount,maxWireBytes:FRAME*frameCount});
}

function encodeObservationFrames(value){
 exact(value,['binding','capture','bytes']);const {binding,capture,bytes}=value;
 need(hex(binding,64)&&hex(capture,32),'Binding');need(Buffer.isBuffer(bytes),'Bytes');
 const {parts}=describeObservationFrameGeometry({rawBytes:bytes.length}),whole=sha(bytes),out=[];
 for(let part=0;part<parts+2;part++){
  const kind=part===0?'B':part===parts+1?'E':'D';
  const body=kind==='D'?bytes.subarray((part-1)*PIECE,part*PIECE):Buffer.alloc(0);
  const frame=Buffer.from('\nMEM9-OBS2|'+[binding,capture,kind,part,parts,bytes.length,whole,
   body.length?sha(body):EMPTY_HASH,body.toString('base64')].join('|')+'\n');
  need(frame.length<=FRAME,'FrameBound');out.push(frame);
 }
 return out;
}

 return Object.freeze({OBSERVATION_FRAME_LIMITS,describeObservationFrameGeometry,encodeObservationFrames,
  primitives:Object.freeze({FRAME,PIECE,RAW,MAGIC,EMPTY_HASH,need,positive,hex,sha,exact})});
}
const observationEncoder=nonrootObservationFrameEncoderFactory(createHash);
export const OBSERVATION_FRAME_LIMITS=observationEncoder.OBSERVATION_FRAME_LIMITS;
export const describeObservationFrameGeometry=observationEncoder.describeObservationFrameGeometry;
export const encodeObservationFrames=observationEncoder.encodeObservationFrames;
const {FRAME,PIECE,RAW,MAGIC,EMPTY_HASH,need,positive,hex,sha,exact}=observationEncoder.primitives;

/** Fixed ESM source for the coordinator; no caller code or helper injection. */
export function observationFrameEncoderSource(){
 if(arguments.length!==0)throw Error('NonrootObservationSourceArguments');
 return `import {createHash as nonrootObservationInlineCreateHash} from 'node:crypto';
const encodeObservationFrames=(${Function.prototype.toString.call(nonrootObservationFrameEncoderFactory)})(nonrootObservationInlineCreateHash).encodeObservationFrames;`;
}

/** Accept ordered original byte segments. Complete frames can occur in any
 * index order; byte fragments cannot be reordered or repaired by this parser.
 * Duplicated provider events must be handled by the authenticated caller;
 * duplicated logical frames (even identical ones) always reject here. */
export function createObservationFrameDecoder(options){
 exact(options,['bindings','maxCaptures','maxInputBytes']);
 const {bindings,maxCaptures,maxInputBytes}=options;
 need(Array.isArray(bindings)&&bindings.length>0&&bindings.every(b=>hex(b,64)),'Binding');
 const allowed=new Set(bindings);need(allowed.size===bindings.length,'Binding');
 need(positive(maxCaptures)&&positive(maxInputBytes),'InputBound');
 const frame=Buffer.alloc(FRAME),noise=Buffer.alloc(FRAME),noiseHash=createHash('sha256'),captures=new Map();
 let matched=0,frameLength=0,inFrame=false,wireBytes=0,nonFrameBytes=0,noiseLength=0,held=false,finished=false;
 function operate(fn){
  need(!finished,'Finished');need(!held,'Held');
  try{return fn();}catch(error){held=true;throw error;}
 }
 function flushNoise(){if(noiseLength){noiseHash.update(noise.subarray(0,noiseLength));noiseLength=0;}}
 function noiseByte(byte){nonFrameBytes++;noise[noiseLength++]=byte;if(noiseLength===FRAME)flushNoise();}
 function consumeFrame(){
  const bytes=frame.subarray(MAGIC.length,frameLength-1);
  need(bytes.every(byte=>byte>=32&&byte<=126),'FrameAscii');
  const fields=bytes.toString('ascii').split('|');need(fields.length===9,'FrameShape');
  const [binding,capture,kind,partText,partsText,lengthText,whole,pieceHash,base64]=fields;
  need(allowed.has(binding)&&hex(capture,32),'Binding');
  need([partText,partsText,lengthText].every(s=>/^(0|[1-9][0-9]*)$/.test(s)),'FrameInteger');
  const part=Number(partText),parts=Number(partsText),length=Number(lengthText);
  need(Number.isSafeInteger(part)&&positive(parts)&&positive(length)&&length<=RAW&&parts===Math.ceil(length/PIECE),'ManifestBound');
  need(part<=parts+1&&kind===(part===0?'B':part===parts+1?'E':'D'),'FrameIndex');
  need(hex(whole,64)&&hex(pieceHash,64),'FrameEncoding');
  const key=binding+'|'+capture,known=captures.get(key);
  if(known){need(known.parts===parts&&known.length===length&&known.whole===whole,'ManifestChanged');need(!known.frames.has(part),'DuplicateFrame');}
  else need(captures.size<maxCaptures,'CaptureBound');
  need(base64.length<=4*Math.ceil(PIECE/3)&&/^[A-Za-z0-9+/]*={0,2}$/.test(base64),'FrameEncoding');
  const decoded=Buffer.from(base64,'base64');need(decoded.toString('base64')===base64,'FrameEncoding');
  const expectedLength=kind==='D'?Math.min(PIECE,length-(part-1)*PIECE):0;
  need(decoded.length===expectedLength,'PieceLength');
  need((decoded.length?sha(decoded):EMPTY_HASH)===pieceHash,'PieceHash');
  const entry=known??{binding,capture,parts,length,whole,frames:new Map()};
  entry.frames.set(part,decoded);if(!known)captures.set(key,entry);
 }
 function accept(byte){
  if(inFrame){
   need(frameLength<FRAME,'FrameBound');frame[frameLength++]=byte;
   if(byte===10){consumeFrame();inFrame=false;frameLength=0;}
   else need(frameLength<FRAME,'FrameBound');
   return;
  }
  if(byte===MAGIC[matched]){
   frame[matched++]=byte;
   if(matched===MAGIC.length){inFrame=true;frameLength=matched;matched=0;}
   return;
  }
  // MAGIC has no interior LF; only this byte's LF can restart a prefix.
  for(let i=0;i<matched;i++)noiseByte(frame[i]);matched=0;
  if(byte===MAGIC[0]){frame[0]=byte;matched=1;}else noiseByte(byte);
 }
 return Object.freeze({
  push(bytes){return operate(()=>{
   need(Buffer.isBuffer(bytes),'Bytes');need(bytes.length<=maxInputBytes-wireBytes,'InputBound');
   // Advance the complete input counter before copying, scanning or hashing.
   // This is a local bound, never a substitute for the caller's original payer.
   wireBytes+=bytes.length;
   for(let offset=0;offset<bytes.length;offset+=FRAME){const copy=Buffer.from(bytes.subarray(offset,offset+FRAME));for(const byte of copy)accept(byte);}
  });},
  finish(){return operate(()=>{
   need(!inFrame&&matched<=1,'TruncatedFrame');need(captures.size>0,'Incomplete');
   // Preserve an ordinary final LF. A longer unfinished magic prefix is
   // ambiguous and rejects above; no missing frame delimiter is invented.
   if(matched)noiseByte(MAGIC[0]);matched=0;flushNoise();
   const ordered=[...captures.values()].sort((a,b)=>a.binding<b.binding?-1:a.binding>b.binding?1:a.capture<b.capture?-1:a.capture>b.capture?1:0);
   const output=[];
   for(const entry of ordered){
    need(entry.frames.size===entry.parts+2,'Incomplete');const pieces=[];
    for(let part=0;part<entry.parts+2;part++){need(entry.frames.has(part),'Incomplete');if(part>0&&part<=entry.parts)pieces.push(entry.frames.get(part));}
    const bytes=Buffer.concat(pieces,entry.length);need(sha(bytes)===entry.whole,'WholeHash');
    output.push({binding:entry.binding,capture:entry.capture,bytes,sha256:entry.whole,frameCount:entry.parts+2});
   }
   const nonFrameSha256=noiseHash.digest('hex');finished=true;captures.clear();
   return {captures:output,wireBytes,nonFrameBytes,nonFrameSha256};
  });}
 });
}
