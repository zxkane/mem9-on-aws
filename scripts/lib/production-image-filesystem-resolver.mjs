/** Pure final-overlay resolution shared with the genuine native accessor.
 * DATA rows never create a filesystem verification context. */
import {posix} from 'node:path';
import {IMAGE_TRANSITION_LIMITS as L} from './production-image-transition.mjs';
import {imageFailure} from './production-image-graph.mjs';
const need=(v,code='ImageFilesystemInvalid')=>{if(!v)imageFailure(code);};
const freeze=v=>{if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;};
export function normalize(path,{link=false,base=''}={}){
 need(typeof path==='string'&&Buffer.byteLength(path)<=L.maxPathBytes&&!path.includes('\0')&&!path.includes('\\'),'ImageTarPath');
 need(link||!path.startsWith('/'),'ImageTarAbsolutePath');
 const parts=link&&!path.startsWith('/')?base.split('/').filter(Boolean):[];
 for(const part of path.split('/')){if(!part||part==='.')continue;if(part==='..'){need(link&&parts.length>0,'ImageTarEscape');parts.pop();}else parts.push(part);}
 return parts.join('/');
}
export function resolved(nodes,path,{parent=false,missing=true,onLink}={}){
 let rest=normalize(path).split('/').filter(Boolean),prefix=[],hops=0;
 while(rest.length){const part=rest.shift();prefix.push(part);const name=prefix.join('/'),node=nodes.get(name);
  if(node?.type==='symlink'&&(!parent||rest.length)){need(++hops<=L.maxVirtualLinkHops,'ImageVirtualLinkLoop');onLink?.(name,node);rest=[...normalize(node.link,{link:true,base:prefix.slice(0,-1).join('/')}).split('/').filter(Boolean),...rest];prefix=[];continue;}
  if(rest.length&&node)need(node.type==='directory','ImageVirtualParent');
  if(!node&&!missing)imageFailure('ImageVirtualLinkMissing');
 }return prefix.join('/');
}
export function resolveImageFilesystemFile(entries,path,{onRead}={}){
 need(typeof path==='string'&&path.startsWith('/')&&path!=='/'&&posix.normalize(path)===path&&!path.endsWith('/'),'ImageRuntimeFilePath');
 const all=new Map(entries.map(({path,...node})=>[path,node])),links=[];
 const nodes=onRead?{get(name){const node=all.get(name);if(node)onRead(name,node);return node;}}:all;
 const effectiveId=(node,key)=>{
  const raw=node.pax?.[key];if(raw===undefined)return node[key];
  need(typeof raw==='string'&&/^(?:0|[1-9][0-9]*)$/.test(raw)&&Number.isSafeInteger(Number(raw)),'ImageRuntimeFileOwner');return Number(raw);
 };
 const metadata=(name,node)=>({path:'/'+name,type:node.type,...(node.implicit?{implicit:true}:{}),
  ...(node.mode===undefined?{}:{mode:node.mode}),...(effectiveId(node,'uid')===undefined?{}:{uid:effectiveId(node,'uid')}),
  ...(effectiveId(node,'gid')===undefined?{}:{gid:effectiveId(node,'gid')}),
  privilegeAttributes:Object.keys(node.pax??{}).filter(key=>key==='SCHILY.xattr.security.capability').sort(),
  ...(node.type==='symlink'?{link:node.link}:{})});
 const name=resolved(nodes,normalize(path,{link:true}),{missing:false,onLink:(name,node)=>links.push(metadata(name,node))}),node=nodes.get(name);
 // Runtime executable/CA proofs reject hardlink inode-metadata ambiguity.
 need(node?.type==='file'&&node.content,'ImageRuntimeFileRequired');
 const parentRecords=new Map();
 for(const start of [normalize(path,{link:true}),name,...links.map(link=>link.path.slice(1))]){
  let parent=posix.dirname(start);
  while(parent!=='.'&&parent!=='/'){
   const original=nodes.get(parent);
   if(original){need(['directory','symlink'].includes(original.type),'ImageVirtualParent');parentRecords.set(parent,metadata(parent,original));}
   else{const actual=resolved(nodes,parent,{missing:false}),entry=nodes.get(actual);need(entry?.type==='directory','ImageVirtualParent');parentRecords.set(actual,metadata(actual,entry));}
   parent=posix.dirname(parent);
  }
 }
 return freeze({...metadata(name,node),path,resolvedPath:'/'+name,sha256:node.content.sha256,size:node.content.size,
  layerDigest:node.content.layerDigest,symlinkChain:links,parents:[...parentRecords.values()].sort((a,b)=>a.path.localeCompare(b.path)),rootMetadata:'not-recorded'});
}
