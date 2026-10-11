/** Complete COPY expansion against the original native Git tree and the
 * authenticated image filesystem. No image execution or guessed members. */
import {posix} from 'node:path';
import {nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {controlSourcePaths,readControlSourceFile,describeControlCopyClosure} from './production-control-source.mjs';
import {inspectImageFilesystemEntries,inspectImageFilesystemEvidence,imageFilesystemVerificationKind} from './production-image-filesystem.mjs';
import {compositionNeed as need,inspectProductionControlCopyRows} from './production-control-composition.mjs';

export async function describeProductionControlCopyManifest({sourceContext,baseFilesystem,charge=()=>{}}){
 need(imageFilesystemVerificationKind(baseFilesystem)==='live-filesystem-evidence','ControlCompositionLiveFilesystem');
 const fs=inspectImageFilesystemEvidence(baseFilesystem),entries=inspectImageFilesystemEntries(baseFilesystem);
 need(hash(entries)===fs.entriesHash,'ControlCompositionFilesystemChanged');
 const byPath=new Map(entries.map(e=>[e.path,e])),paths=controlSourcePaths(sourceContext);
 // This original reader authenticates complete tree membership and the exact
 // Dockerfile COPY closure. It rejects unsupported ADD/flags/source syntax.
 const closure=await describeControlCopyClosure(sourceContext);
 const dockerfile=await readControlSourceFile(sourceContext,'docker/bootstrap/Dockerfile');
 const text=new TextDecoder('utf-8',{fatal:true}).decode(dockerfile.bytes),pairs=[];
 for(const raw of text.split(/\r?\n/)){
  const line=raw.trim();if(!/^COPY\b/.test(line))continue;
  need(line.startsWith('COPY ')&&!/[\[\]"'$\\]/.test(line)&&!line.includes(String.fromCharCode(96)),'ControlCompositionCopyInstruction');
  const words=line.split(/\s+/).slice(1),destination=words.pop();
  need(words.length>0&&destination.startsWith('/')&&posix.normalize(destination).replace(/\/$/,'')===destination.replace(/\/$/,'')&&
   !words.some(word=>word.startsWith('--')),'ControlCompositionCopyInstruction');
  for(const pattern of words){
   const directory=pattern.endsWith('/'),regex=new RegExp('^'+pattern.split('*').map(RegExp.escape).join('[^/]*')+'$');
   const matches=paths.filter(path=>directory?path.startsWith(pattern):regex.test(path));
   need(matches.length>0&&(words.length===1&&matches.length===1||destination.endsWith('/')),'ControlCompositionCopyDestination');
   for(const path of matches){
    const suffix=directory?path.slice(pattern.length):posix.basename(path);
    const target=directory||destination.endsWith('/')?destination.replace(/\/$/,'')+'/'+suffix:destination;
    pairs.push({sourcePath:path,path:target.slice(1)});
   }
  }
 }
 const bySource=new Map(closure.files.map(f=>[f.path,f])),rows=new Map(),copied=new Set();
 const metadata=e=>{
  need(e&&!e.implicit&&Number.isSafeInteger(e.mode)&&Number.isSafeInteger(e.uid)&&Number.isSafeInteger(e.gid),'ControlCompositionMetadataMissing');
  need(!Object.keys(e.pax??{}).some(k=>k.startsWith('SCHILY.xattr.')||['uid','gid','size','path','linkpath'].includes(k)),'ControlCompositionExtendedMetadata');
  return {mode:e.mode,uid:e.uid,gid:e.gid};
 };
 for(const pair of pairs){
  const file=bySource.get(pair.sourcePath),entry=byPath.get(pair.path);
  need(file&&entry?.type==='file'&&entry.content?.sha256===file.sha256&&entry.content.size===file.bytes,'ControlCompositionSourceEquivalent');
  const row={path:pair.path,type:'file',...metadata(entry),sourcePath:pair.sourcePath,sha256:file.sha256,bytesLength:file.bytes};
  const prior=rows.get(row.path);need(!prior||hash(prior)===hash(row),'ControlCompositionCopyCollision');rows.set(row.path,row);copied.add(file.path);
  let parent=posix.dirname(row.path);
  while(parent!=='.'){
   const found=byPath.get(parent);need(found?.type==='directory','ControlCompositionParentEquivalent');
   const directory={path:parent,type:'directory',...metadata(found)};
   need(!rows.has(parent)||hash(rows.get(parent))===hash(directory),'ControlCompositionCopyCollision');rows.set(parent,directory);parent=posix.dirname(parent);
  }
 }
 need(copied.size===closure.files.length&&closure.files.every(f=>copied.has(f.path)),'ControlCompositionIncompleteSource');
 charge(closure.files.reduce((n,f)=>n+f.bytes,0)+dockerfile.bytes.length);
 return inspectProductionControlCopyRows([...rows.values()].sort((a,b)=>Buffer.compare(Buffer.from(a.path),Buffer.from(b.path))));
}
