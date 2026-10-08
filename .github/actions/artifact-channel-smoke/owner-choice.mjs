/** Synthetic PRIVATE LOCAL conditional-choice surrogate. This is not S3,
 * prepaid funding, a production owner claim, or a transferable capability. */
import {open,lstat,realpath,readdir} from 'node:fs/promises';
import {constants} from 'node:fs';
import {dirname,join,resolve} from 'node:path';
import {crc32,inflateRawSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {artifactName,selectionFor,scopeHashFor,winnerContext,verifyArtifact,readWinner,hash,need,LIMITS,CHANNEL_SCOPE} from './channel.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join(),'SyntheticChoiceFields');
const identity=s=>({dev:String(s.dev),ino:String(s.ino)});

/** One ordinary claim.json ZIP entry, read in memory only. Verify central and
 * local headers, sizes, CRC and optional data descriptor; reject ZIP64,
 * encryption, extra files, links, traversal, trailing data and ZIP bombs. */
export function readClaimZip(raw,binding){
 need(raw instanceof Uint8Array&&raw.length>=98&&raw.length<=LIMITS.artifactBytes,'SyntheticZipSize');const b=Buffer.from(raw),end=b.length-22;
 need(b.readUInt32LE(end)===0x06054b50&&b.readUInt16LE(end+20)===0&&b.readUInt16LE(end+4)===0&&b.readUInt16LE(end+6)===0&&b.readUInt16LE(end+8)===1&&b.readUInt16LE(end+10)===1,'SyntheticZipDirectory');
 const cdSize=b.readUInt32LE(end+12),cd=b.readUInt32LE(end+16);need(cd>=30&&cd+cdSize===end&&cdSize>=46&&b.readUInt32LE(cd)===0x02014b50,'SyntheticZipDirectory');
 const flags=b.readUInt16LE(cd+8),method=b.readUInt16LE(cd+10),crc=b.readUInt32LE(cd+16),compressed=b.readUInt32LE(cd+20),size=b.readUInt32LE(cd+24),nameLen=b.readUInt16LE(cd+28),extraLen=b.readUInt16LE(cd+30),commentLen=b.readUInt16LE(cd+32);
 need((flags&~0x808)===0&&[0,8].includes(method)&&size>0&&size<=1024&&compressed>0&&46+nameLen+extraLen+commentLen===cdSize&&b.readUInt16LE(cd+34)===0&&b.readUInt32LE(cd+42)===0,'SyntheticZipEntry');
 const mode=(b.readUInt32LE(cd+38)>>>16)&0xf000;need([0,0x8000].includes(mode)&&(b.readUInt32LE(cd+38)&16)===0,'SyntheticZipFile');
 need(b.subarray(cd+46,cd+46+nameLen).toString()==='claim.json'&&b.readUInt32LE(0)===0x04034b50&&b.readUInt16LE(6)===flags&&b.readUInt16LE(8)===method,'SyntheticZipEntry');
 const localName=b.readUInt16LE(26),localExtra=b.readUInt16LE(28),start=30+localName+localExtra,finish=start+compressed;
 need(localName===nameLen&&b.subarray(30,30+localName).equals(b.subarray(cd+46,cd+46+nameLen))&&finish<=cd,'SyntheticZipEntry');
 for(const [from,length] of [[30+localName,localExtra],[cd+46+nameLen,extraLen]]){let p=from;while(p<from+length){need(p+4<=from+length,'SyntheticZipExtra');const id=b.readUInt16LE(p),n=b.readUInt16LE(p+2);need(id!==1&&p+4+n<=from+length,'SyntheticZipExtra');p+=4+n;}}
 if(flags&8){need([0,crc].includes(b.readUInt32LE(14))&&[0,compressed].includes(b.readUInt32LE(18))&&[0,size].includes(b.readUInt32LE(22)),'SyntheticZipDescriptor');let p=finish;if(cd-p===16){need(b.readUInt32LE(p)===0x08074b50,'SyntheticZipDescriptor');p+=4;}need(cd-p===12&&b.readUInt32LE(p)===crc&&b.readUInt32LE(p+4)===compressed&&b.readUInt32LE(p+8)===size,'SyntheticZipDescriptor');}
 else need(finish===cd&&b.readUInt32LE(14)===crc&&b.readUInt32LE(18)===compressed&&b.readUInt32LE(22)===size,'SyntheticZipEntry');
 const payload=method===0?b.subarray(start,finish):inflateRawSync(b.subarray(start,finish),{maxOutputLength:1024});need(payload.length===size&&crc32(payload)===crc,'SyntheticZipIntegrity');
 const text=new TextDecoder('utf-8',{fatal:true}).decode(payload),m=/^\{"nonce":"([a-f0-9]{64})","scopeHash":"([a-f0-9]{64})"\}$/.exec(text);
 need(m&&m[2]===scopeHashFor(binding),'SyntheticZipClaim');return {nonce:m[1],scopeHash:m[2]};
}

function normalizeArtifact(binding,raw,now){
 need(typeof raw?.digest==='string'&&/^sha256:[a-f0-9]{64}$/.test(raw.digest),'SyntheticArtifactDigest');
 const artifact=verifyArtifact(binding,raw,{id:raw.id,size:raw.size_in_bytes,digest:raw.digest.slice(7)},now);
 need(artifact.createdMs>=binding.notAfter-LIMITS.windowMs,'SyntheticArtifactTime');return artifact;
}
function validateCandidate(binding,candidate){
 exact(candidate,['artifact','zipBase64']);const a=candidate.artifact;
 exact(a,['id','name','digest','size','createdMs','expiresMs']);need(typeof candidate.zipBase64==='string'&&candidate.zipBase64.length<=4*Math.ceil(LIMITS.artifactBytes/3),'SyntheticChoiceZip');
 const raw=Buffer.from(candidate.zipBase64,'base64');need(raw.toString('base64')===candidate.zipBase64&&raw.length===a.size&&sha(raw)===a.digest&&a.name===artifactName(binding),'SyntheticChoiceZip');
 return {artifact:a,upload:{...readClaimZip(raw,binding),artifactId:a.id,artifactDigest:a.digest}};
}
function choiceRecord(binding,configHash,candidates){
 need(Array.isArray(candidates)&&candidates.length===2,'SyntheticTwoContenders');const decoded=candidates.map(c=>validateCandidate(binding,c));
 need(new Set(decoded.map(x=>x.artifact.id)).size===2&&new Set(decoded.map(x=>x.upload.nonce)).size===2,'SyntheticDistinctContenders');
 const order=decoded.map((x,index)=>({...x,index})).sort((a,b)=>a.artifact.createdMs-b.artifact.createdMs||a.artifact.id-b.artifact.id),selection=selectionFor(binding,order[0].upload);
 return {version:1,kind:'synthetic-local-choice-record',bindingHash:hash(binding),configHash,candidates:order.map(x=>candidates[x.index]),selection};
}

async function privateRaw(path,max=262144){
 need(resolve(path)===path&&await realpath(path)===path,'SyntheticPrivatePath');const f=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{const s=await f.stat();need(s.isFile()&&s.uid===process.getuid()&&s.nlink===1&&(s.mode&511)===0o600&&s.size>0&&s.size<=max,'SyntheticPrivateFile');const raw=await f.readFile(),after=await f.stat();for(const k of ['dev','ino','size','mtimeMs','ctimeMs'])need(s[k]===after[k],'SyntheticPrivateChanged');return raw;}finally{await f.close();}
}
async function directory(path){need(await realpath(path)===path,'SyntheticPrivateDirectory');const s=await lstat(path);need(s.isDirectory()&&s.uid===process.getuid()&&(s.mode&511)===0o700,'SyntheticPrivateDirectory');return s;}
async function stateAt(stateFile,binding){
 const raw=await privateRaw(stateFile,4096),config=JSON.parse(raw);exact(config,['version','kind','directoryIdentity']);need(config.version===1&&config.kind==='synthetic-channel-owner-state','SyntheticOwnerState');exact(config.directoryIdentity,['dev','ino']);
 const parent=dirname(stateFile),dir=join(parent,'choice-journal');await directory(parent);need(hash(identity(await directory(dir)))===hash(config.directoryIdentity),'SyntheticDirectoryRecreated');
 let inGit=false;try{await promisify(execFile)('/usr/bin/git',['-C',parent,'rev-parse','--show-toplevel'],{env:{PATH:'/usr/bin:/bin',GIT_CONFIG_NOSYSTEM:'1'},timeout:5000,maxBuffer:4096});inGit=true;}catch(error){need(error.code===128,'SyntheticPrivateGitCheck');}need(!inGit,'SyntheticStateMustBeOutsideGit');
 const configHash=sha(raw),key=hash({challenge:binding.challenge,checkpoint:CHANNEL_SCOPE.checkpoint}),prefix='choice-'+key;
 const check=async()=>{need(sha(await privateRaw(stateFile,4096))===configHash,'SyntheticOwnerStateChanged');need(hash(identity(await directory(dir)))===hash(config.directoryIdentity),'SyntheticDirectoryRecreated');};
 return {dir,configHash,prefix,check};
}
async function once(state,suffix,value){
 await state.check();const raw=JSON.stringify(value)+'\n';need(Buffer.byteLength(raw)<=262144,'SyntheticChoiceRecordSize');const f=await open(join(state.dir,state.prefix+'-'+suffix+'.json'),constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
 try{await f.writeFile(raw);await f.sync();}finally{await f.close();}const d=await open(state.dir,constants.O_RDONLY|constants.O_DIRECTORY);try{await d.sync();}finally{await d.close();}
}
async function existingChoice(state,binding){
 const names=(await readdir(state.dir)).filter(n=>n.startsWith(state.prefix+'-'));if(names.length===0)return undefined;
 need(names.includes(state.prefix+'-start.json')&&names.includes(state.prefix+'-record.json'),'SyntheticChoiceHistoryMissing');
 need(names.every(n=>new RegExp('^'+state.prefix+'-(start|record|announce-[12]|confirmed)\\.json$').test(n)),'SyntheticChoiceHistory');
 const start=JSON.parse(await privateRaw(join(state.dir,state.prefix+'-start.json'))),record=JSON.parse(await privateRaw(join(state.dir,state.prefix+'-record.json')));
 exact(start,['version','kind','bindingHash','configHash','recordHash']);exact(record,['version','kind','bindingHash','configHash','candidates','selection']);
 const rebuilt=choiceRecord(binding,state.configHash,record.candidates);need(hash(rebuilt)===hash(record),'SyntheticChoiceChanged');
 need(hash(start)===hash({version:1,kind:'synthetic-local-choice-start',bindingHash:hash(binding),configHash:state.configHash,recordHash:hash(record)}),'SyntheticChoiceHistory');
 const marker={version:1,kind:'synthetic-choice-announcement-attempt',recordHash:hash(record),payloadHash:hash(record.selection.announcement.payload)};
 for(const n of [1,2])if(names.includes(state.prefix+'-announce-'+n+'.json')){if(n===2)need(names.includes(state.prefix+'-announce-1.json'),'SyntheticAnnouncementHistory');need(hash(JSON.parse(await privateRaw(join(state.dir,state.prefix+'-announce-'+n+'.json'))))===hash(marker),'SyntheticAnnouncementHistory');}
 if(names.includes(state.prefix+'-confirmed.json')){need(names.includes(state.prefix+'-announce-1.json'),'SyntheticAnnouncementHistory');need(hash(JSON.parse(await privateRaw(join(state.dir,state.prefix+'-confirmed.json'))))===hash({version:1,kind:'synthetic-choice-announcement-confirmed',recordHash:hash(record),choiceHash:hash(record.selection.claim)}),'SyntheticAnnouncementHistory');}
 return record;
}

/** No local directory is initialized here. The operator supplies an existing
 * 0600 state reference whose fixed 0700 journal inode was pinned beforehand. */
export async function ownerChoice({mode,binding,stateFile},{api,download,check,now=Date.now,sleep=ms=>new Promise(r=>setTimeout(r,ms))}){
 need(['choiceprepare','choicepublish'].includes(mode),'SyntheticChoiceMode');const state=await stateAt(stateFile,binding);check();
 let record=await existingChoice(state,binding);
 const fetchCandidate=async id=>{
  check();const raw=await api(`repos/${binding.repository}/actions/artifacts/${id}`),artifact=normalizeArtifact(binding,raw,now());
  const zip=await download(id);check();need(zip instanceof Uint8Array&&zip.length===artifact.size&&sha(zip)===artifact.digest,'SyntheticArtifactBytes');
  const candidate={artifact,zipBase64:Buffer.from(zip).toString('base64')};validateCandidate(binding,candidate);return candidate;
 };
 if(!record){
  need(mode==='choiceprepare','SyntheticChoiceNotPrepared');
  need(await readWinner(binding,api,check)===undefined,'SyntheticChoiceHistoryMissing');let listed;
  for(let i=0;i<LIMITS.polls;i++){
   check();listed=await api(`repos/${binding.repository}/actions/runs/${binding.runId}/artifacts?name=${encodeURIComponent(artifactName(binding))}&per_page=100&page=1`);
   need(Number.isSafeInteger(listed?.total_count)&&listed.total_count>=0&&listed.total_count<=2&&listed.artifacts?.length===listed.total_count,'SyntheticInboxInventory');if(listed.total_count===2)break;
   need(i+1<LIMITS.polls,'SyntheticInboxMissing');await sleep(LIMITS.pollMs);check();
  }
  const candidates=[];for(const item of listed.artifacts){need(Number.isSafeInteger(item.id)&&item.id>0,'SyntheticArtifactId');candidates.push(await fetchCandidate(item.id));}
  record=choiceRecord(binding,state.configHash,candidates);await once(state,'start',{version:1,kind:'synthetic-local-choice-start',bindingHash:hash(binding),configHash:state.configHash,recordHash:hash(record)});await once(state,'record',record);
 }else{
  // Revalidate the selected artifact; never list again or elect a replacement.
  const selected=record.candidates[0],live=await fetchCandidate(selected.artifact.id);need(hash(live)===hash(selected),'SyntheticSelectedArtifactChanged');
 }
 await state.check();check();const choiceHash=hash(record.selection.claim),summary={kind:'synthetic-local-choice-surrogate',bindingHash:hash(binding),choiceHash};
 if(mode==='choiceprepare')return {...summary,phase:'prepared'};
 const published=await readWinner(binding,api,check);need(published===undefined||published===choiceHash,'SyntheticWinnerConflict');
 if(published===choiceHash)return {...summary,phase:'already-announced'};
 const history=await readdir(state.dir);need(!history.includes(state.prefix+'-confirmed.json'),'SyntheticAnnouncementHistoryMissing');
 let attempt=1;if(history.includes(state.prefix+'-announce-1.json'))attempt=2;need(!history.includes(state.prefix+'-announce-2.json'),'SyntheticAnnouncementLimit');
 const marker={version:1,kind:'synthetic-choice-announcement-attempt',recordHash:hash(record),payloadHash:hash(record.selection.announcement.payload)};
 if(attempt===2)need(hash(JSON.parse(await privateRaw(join(state.dir,state.prefix+'-announce-1.json'))))===hash(marker),'SyntheticAnnouncementHistory');
 await once(state,'announce-'+attempt,marker);await state.check();check();
 const {path,payload}=record.selection.announcement,response=await api(path,payload);
 need(Number.isSafeInteger(response?.id)&&response.id>0&&response.creator?.id===binding.initiatingActorId&&response.url==='https://api.github.com/'+path&&Object.entries(payload).every(([k,v])=>response[k]===v),'SyntheticWinnerUnconfirmed');
 await once(state,'confirmed',{version:1,kind:'synthetic-choice-announcement-confirmed',recordHash:hash(record),choiceHash});return {...summary,phase:'announced'};
}
