/** Pure full-log DATA validation. No IO, source/owner handle, clock or grant.
 * The caller retains original bytes and owns all existing processing charges. */
const need=(ok,code)=>{if(!ok)throw Error(code);};
export function verifyNonrootControlBuildLog(bytes,image){
 need(bytes instanceof Uint8Array&&bytes.length>0&&bytes.length<=16777216,'NonrootControlBuildLog');
 const rows=new TextDecoder('utf-8',{fatal:true}).decode(bytes).split('\n');
 const events=rows.flatMap((line,index)=>{
  const m=/(?:^|\s)#([0-9]+) exporting (manifest list|manifest|config) (sha256:[a-f0-9]{64})(.*)$/.exec(line);
  return m?[{vertex:m[1],kind:m[2],digest:m[3],suffix:m[4].trim(),index}]:[];
 });
 const kinds=[['manifest list',image.rootDigest],['config',image.configDigest],...(image.arm64Digest===undefined?[]:[['manifest',image.arm64Digest]])];
 let vertex,last=-1;
 for(const[kind,digest]of kinds){
  need(/^sha256:[a-f0-9]{64}$/.test(digest??''),'NonrootControlBuildLog');
  const matches=events.filter(e=>e.kind===kind&&e.digest===digest);
  need(matches.length>=1&&matches.length<=2,'NonrootControlBuildLog');
  vertex??=matches[0].vertex;
  need(matches.every(e=>e.vertex===vertex&&(e.suffix===''||/^(?:[0-9]+(?:\.[0-9]+)?s )?done$/.test(e.suffix))),'NonrootControlBuildLog');
  // BuildKit may report a start line and a separate completion for the same
  // export. They are one event, not two competing image identities.
  if(matches.length===2)need(matches[0].suffix===''&&matches[1].suffix.endsWith('done'),'NonrootControlBuildLog');
  need(events.filter(e=>e.vertex===vertex&&e.kind===kind).every(e=>e.digest===digest),'NonrootControlBuildLog');
  last=Math.max(last,...matches.map(e=>e.index));
 }
 // Export and registry push can complete in separate progress phases. An
 // earlier DONE cannot complete later resumed work from this same vertex.
 const progress=new RegExp('(?:^|\\s)#'+vertex+' (.*)$');
 let lastProgress=-1,lastDone=-1,failed=false;
 for(const [index,line]of rows.entries()){
  const event=progress.exec(line);if(!event)continue;lastProgress=index;
  if(/^DONE(?:\s|$)/.test(event[1]))lastDone=index;
  if(/^(?:ERROR(?::|\s|$)|CACHED(?:\s|$))/.test(event[1]))failed=true;
 }
 need(lastDone>last&&lastDone===lastProgress&&!failed,'NonrootControlBuildLog');
 return {vertex};
}
