import {inflateRawSync,gunzipSync,crc32} from 'node:zlib';
import {createHash} from 'node:crypto';
import {verifyNonrootControlBuildLog} from './production-nonroot-build-log-progress.mjs';

export const MATERIAL_LIMITS=Object.freeze({zipBytes:33554432,dockerbuildBytes:33554432,
 tarBytes:134217728,entries:256,memberBytes:67108864,logBytes:16777216,jsonBytes:4194304});
export const hashBytes=b=>createHash('sha256').update(b).digest('hex');
const need=(v,c)=>{if(!v)throw Object.assign(Error(c),{code:c});};
const text=b=>new TextDecoder('utf-8',{fatal:true}).decode(b);
export function jsonBytes(b){need(b.length<=MATERIAL_LIMITS.jsonBytes,'BaseJsonBound');try{return JSON.parse(text(b));}catch{throw Error('BaseJson');}}
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
export function materialBudget(limits){
 need(limits&&Object.keys(limits).sort().join()==='dockerbuildBytes,entries,localBytes,tarBytes,zipBytes','BaseLimits');
 for(const k of ['zipBytes','dockerbuildBytes','tarBytes','entries'])need(Number.isSafeInteger(limits[k])&&limits[k]>0&&limits[k]<=MATERIAL_LIMITS[k],'BaseLimits');
 need(Number.isSafeInteger(limits.localBytes)&&limits.localBytes>0&&limits.localBytes<=1073741824,'BaseLimits');
 const value={localBytes:0,unpackedBytes:0,entries:0};
 return {limits,value,charge(n){need(Number.isSafeInteger(n)&&n>=0,'BaseLocalBudget');value.localBytes+=n;need(value.localBytes<=limits.localBytes,'BaseLocalBudget');},
  unpack(n,cap){need(n<=cap,'BaseUnpackBound');value.unpackedBytes+=n;need(value.unpackedBytes<=limits.dockerbuildBytes+limits.tarBytes,'BaseUnpackBound');},
  entry(){need(++value.entries<=limits.entries,'BaseEntryBound');}};
}

// Constrained adaptation of the existing single-member carrier ZIP parser:
// Buffer-only deflate + CRC, no filesystem extraction, ZIP64 or path aliases.
export function unpackDockerBuildZip(b,budget){
 const L=budget.limits;need(Buffer.isBuffer(b)&&b.length>=98&&b.length<=L.zipBytes,'BaseZipBound');budget.charge(b.length);
 const end=b.length-22;need(b.readUInt32LE(end)===0x06054b50&&b.readUInt16LE(end+4)===0&&b.readUInt16LE(end+6)===0&&
  b.readUInt16LE(end+8)===1&&b.readUInt16LE(end+10)===1&&b.readUInt16LE(end+20)===0,'BaseZipDirectory');
 const at=b.readUInt32LE(end+16),length=b.readUInt32LE(end+12);
 need(at>=30&&at+length===end&&at+46<=end&&b.readUInt32LE(at)===0x02014b50,'BaseZipDirectory');
 const flags=b.readUInt16LE(at+8),method=b.readUInt16LE(at+10),crc=b.readUInt32LE(at+16),packed=b.readUInt32LE(at+20),size=b.readUInt32LE(at+24),
  nameBytes=b.readUInt16LE(at+28),extra=b.readUInt16LE(at+30),comment=b.readUInt16LE(at+32),mode=b.readUInt32LE(at+38)>>>16;
 need([0,8,0x800,0x808].includes(flags)&&[0,8].includes(method)&&size>0&&size<=L.dockerbuildBytes&&packed<=L.zipBytes&&
  b.readUInt16LE(at+34)===0&&b.readUInt32LE(at+42)===0&&comment===0&&extra===0&&nameBytes>0&&nameBytes<=200&&at+46+nameBytes===end,'BaseZipFields');
 need((mode&0xf000)===0||(mode&0xf000)===0x8000,'BaseZipType');
 const name=text(b.subarray(at+46,at+46+nameBytes));need(/^[A-Za-z0-9_.~-]+\.dockerbuild$/.test(name),'BaseZipName');
 need(b.readUInt32LE(0)===0x04034b50&&b.readUInt16LE(6)===flags&&b.readUInt16LE(8)===method&&b.readUInt16LE(26)===nameBytes&&
  b.readUInt16LE(28)===0&&b.subarray(30,30+nameBytes).equals(b.subarray(at+46,at+46+nameBytes)),'BaseZipLocal');
 const dataStart=30+nameBytes,dataEnd=dataStart+packed;need(dataEnd<=at,'BaseZipLocal');
 if(flags&8)need(at-dataEnd===16&&b.readUInt32LE(dataEnd)===0x08074b50&&b.readUInt32LE(dataEnd+4)===crc&&
  b.readUInt32LE(dataEnd+8)===packed&&b.readUInt32LE(dataEnd+12)===size&&b.readUInt32LE(14)===0&&b.readUInt32LE(18)===0&&b.readUInt32LE(22)===0,'BaseZipDescriptor');
 else need(dataEnd===at&&b.readUInt32LE(14)===crc&&b.readUInt32LE(18)===packed&&b.readUInt32LE(22)===size,'BaseZipLocal');
 need(size<=L.localBytes-budget.value.localBytes,'BaseLocalBudget');
 budget.charge(size);
 let raw;try{raw=method===0?Buffer.from(b.subarray(dataStart,dataEnd)):inflateRawSync(b.subarray(dataStart,dataEnd),{maxOutputLength:size});}catch{throw Error('BaseZipInflate');}
 budget.unpack(raw.length,L.dockerbuildBytes);need(raw.length===size&&crc32(raw)===crc,'BaseZipIntegrity');return {name,raw};
}
export function unpackCapturedBuildArtifact(raw,budget){
 need(Buffer.isBuffer(raw)&&raw.length<=budget.limits.zipBytes,'BaseZipBound');
 if(raw[0]===0x1f&&raw[1]===0x8b){need(raw.length<=budget.limits.dockerbuildBytes,'BaseDockerBuild');
  budget.charge(raw.length);return {format:'dockerbuild',name:null,raw};}
 return {format:'zip',...unpackDockerBuildZip(raw,budget)};
}
function field(block,start,length){const b=block.subarray(start,start+length),nul=b.indexOf(0);
 if(nul>=0)need(b.subarray(nul).every(v=>v===0),'BaseTarField');return text(nul<0?b:b.subarray(0,nul));}
function octal(block,start,length){const s=text(block.subarray(start,start+length));need(/^ *[0-7]+[\0 ]*$/.test(s),'BaseTarNumber');const n=parseInt(s,8);need(Number.isSafeInteger(n),'BaseTarNumber');return n;}
export function inspectDockerBuildArchive(gzip,budget){
 need(Buffer.isBuffer(gzip)&&gzip.length>0&&gzip.length<=budget.limits.dockerbuildBytes&&gzip[0]===0x1f&&gzip[1]===0x8b,'BaseDockerBuild');
 need(gzip.length>=18,'BaseDockerBuild');const declared=gzip.readUInt32LE(gzip.length-4);
 need(declared>0&&declared<=budget.limits.tarBytes,'BaseTarInflate');budget.charge(declared);
 let tar;try{tar=gunzipSync(gzip,{maxOutputLength:declared});}catch{throw Error('BaseTarInflate');}
 need(tar.length===declared,'BaseTarInflate');budget.unpack(tar.length,budget.limits.tarBytes);
 need(tar.length%512===0,'BaseTarAlignment');const members=new Map(),seen=new Set(),descriptors=[];let offset=0,ended=false;
 while(offset+512<=tar.length){const block=tar.subarray(offset,offset+512);offset+=512;
  if(block.every(v=>v===0)){need(tar.length-offset>=512&&tar.subarray(offset).every(v=>v===0),'BaseTarTrailing');ended=true;break;}
  budget.entry();const checksum=octal(block,148,8);let sum=0;for(let i=0;i<512;i++)sum+=i>=148&&i<156?32:block[i];need(sum===checksum,'BaseTarChecksum');
  const name=field(block,0,100),prefix=field(block,345,155),link=field(block,157,100),type=block[156],size=octal(block,124,12);
  need(!prefix&&!link&&/^(?:blobs\/?|blobs\/sha256\/?|index\.json|oci-layout|blobs\/sha256\/[a-f0-9]{64})$/.test(name),'BaseTarPath');
  const canonical=name.replace(/\/$/,'');need(!seen.has(canonical),'BaseTarDuplicate');seen.add(canonical);
  need(size<=MATERIAL_LIMITS.memberBytes&&offset+Math.ceil(size/512)*512<=tar.length,'BaseTarMemberBound');
  const directory=type===53;need(directory||type===0||type===48,'BaseTarType');
  if(directory)need(['blobs','blobs/sha256'].includes(canonical)&&size===0,'BaseTarDirectory');
  else{need(name==='index.json'||name==='oci-layout'||/^blobs\/sha256\/[a-f0-9]{64}$/.test(name),'BaseTarFile');
   budget.charge(size);const raw=Buffer.from(tar.subarray(offset,offset+size)),digest=hashBytes(raw);
   if(name.startsWith('blobs/'))need(name==='blobs/sha256/'+digest,'BaseTarMemberHash');
   members.set(name,raw);descriptors.push({name,sha256:digest,bytesLength:size});}
  const end=offset+size,next=offset+Math.ceil(size/512)*512;need(tar.subarray(end,next).every(v=>v===0),'BaseTarPadding');offset=next;
 }
 need(ended&&members.has('index.json')&&members.has('oci-layout'),'BaseTarComplete');
 const get=d=>{need(d&&/^sha256:[a-f0-9]{64}$/.test(d.digest)&&Number.isSafeInteger(d.size)&&d.size>=0,'BaseArchiveDescriptor');
  const b=members.get('blobs/sha256/'+d.digest.slice(7));need(b&&b.length===d.size,'BaseArchiveMembership');return b;};
 const index=jsonBytes(members.get('index.json'));need(jsonBytes(members.get('oci-layout')).imageLayoutVersion==='1.0.0'&&
  index.schemaVersion===2&&index.mediaType==='application/vnd.oci.image.index.v1+json'&&index.manifests?.length===1,'BaseArchiveIndex');
 const manifest=jsonBytes(get(index.manifests[0]));need(manifest.schemaVersion===2&&manifest.mediaType==='application/vnd.oci.image.manifest.v1+json'&&
  manifest.config?.mediaType==='application/vnd.buildkit.historyrecord.v0'&&Array.isArray(manifest.layers),'BaseArchiveManifest');
 const recordBytes=get(manifest.config),record=jsonBytes(recordBytes);const referenced=new Set([index.manifests[0].digest,manifest.config.digest]);
 for(const d of manifest.layers){get(d);need(!referenced.has(d.digest),'BaseArchiveDuplicateDescriptor');referenced.add(d.digest);}
 need([...members.keys()].filter(k=>k.startsWith('blobs/')).every(k=>referenced.has('sha256:'+k.slice(13))),'BaseArchiveUnreferenced');
 return {gzip,members,descriptors,decodedTarBytes:tar.length,manifest,recordBytes,record,get};
}

function logRows(raw){need(Buffer.isBuffer(raw)&&raw.length>0&&raw.length<=MATERIAL_LIMITS.logBytes,'BaseLogBound');text(raw);
 const rows=[];let start=0;while(start<raw.length){let end=raw.indexOf(10,start);end=end<0?raw.length:end+1;
  const line=text(raw.subarray(start,end)).replace(/\r?\n$/,''),m=/^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z) (.*)$/.exec(line);
  need((!m||Number.isSafeInteger(Date.parse(m[1])))&&end-start<=1048576,'BaseLogTimestamp');
  // Other steps can contain unprefixed CLI help continuation lines. Retain
  // those bytes as inert rows; selected bootstrap evidence must be timed.
  rows.push({start,end,time:m?Date.parse(m[1]):null,line:m?m[2]:line});start=end;need(rows.length<=200000,'BaseLogLines');}
 return rows;
}
export function extractBootstrapMaterial({buildLog,job,expectedSource,scope,buildRevision,runId,runAttempt,archive},budget){
 budget.charge(buildLog.length);const rows=logRows(buildLog),steps=job.steps?.filter(s=>s.name==='Build & push bootstrap (arm64)');
 need(steps?.length===1&&steps[0].status==='completed'&&steps[0].conclusion==='success','BaseBootstrapStep');
 const step=steps[0],stepStart=Date.parse(step.started_at),stepEnd=Date.parse(step.completed_at);
 need(Number.isSafeInteger(stepStart)&&Number.isSafeInteger(stepEnd)&&stepStart<=stepEnd,'BaseBootstrapTime');
 const commands=rows.map((r,i)=>({r,i})).filter(({r})=>r.time!==null&&r.line.startsWith('[command]/usr/bin/docker buildx build ')&&
  /(?:^|\s)--file docker\/bootstrap\/Dockerfile(?:\s|$)/.test(r.line));
 need(commands.length===1,'BaseBootstrapCommand');const {r:command,i:first}=commands[0];
 need(command.time>=stepStart&&command.time<stepEnd+1000,'BaseBootstrapTime');
 const tag=`${scope.account}.dkr.ecr.${scope.region}.amazonaws.com/mem9-on-aws/preview/bootstrap:pr-${buildRevision.slice(0,7)}`;
 const masked=tag.replace(scope.account+'.','***.'),args=command.line.split(/\s+/),values=flag=>args.flatMap((v,i)=>v===flag?[args[i+1]]:[]);
 need(same(values('--file'),['docker/bootstrap/Dockerfile'])&&same(values('--platform'),['linux/arm64'])&&
  values('--tag').length===1&&[tag,masked].includes(values('--tag')[0])&&args.includes('--push')&&
  values('--metadata-file').length===1,'BaseBootstrapCommand');
 const next=rows.findIndex((r,i)=>i>first&&r.time!==null&&(r.line.startsWith('##[group]Run ')||r.line.startsWith('[command]/usr/bin/docker buildx build ')));
 const boundary=next<0?rows.length:next,groups=rows.flatMap((r,i)=>i>first&&i<boundary&&r.line==='##[group]Metadata'?[i]:[]);
 need(groups.length===1,'BaseBootstrapMetadata');const metaStart=groups[0],metaEnd=rows.findIndex((r,i)=>i>metaStart&&i<boundary&&r.line==='##[endgroup]');
 need(metaEnd>metaStart&&rows.slice(first,metaEnd+1).every(r=>r.time!==null&&r.time>=stepStart&&r.time<stepEnd+1000),'BaseBootstrapTime');
 const payload=rows.slice(metaStart+1,metaEnd).map(r=>r.line);let stopToken=null;
 if(payload[0]?.startsWith('::stop-commands::')){stopToken=payload.shift().slice('::stop-commands::'.length);need(stopToken.length>0&&payload.pop()==='::'+stopToken+'::','BaseMetadataCommands');}
 const metadataBytes=Buffer.from(payload.join('\n')+'\n'),metadata=jsonBytes(metadataBytes);budget.charge(metadataBytes.length);
 const rootDescriptor=metadata['containerimage.descriptor'];need(rootDescriptor?.digest===metadata['containerimage.digest']&&
  rootDescriptor.mediaType==='application/vnd.oci.image.index.v1+json'&&[tag,masked].includes(metadata['image.name']),'BaseMetadataRoot');
 const provenance=metadata['buildx.build.provenance'],vcs=provenance?.invocation?.parameters?.root?.request?.args;
 need(provenance?.builder?.id===`https://github.com/${expectedSource.repository}/actions/runs/${runId}/attempts/${runAttempt}`&&
  vcs?.['vcs:revision']===buildRevision&&vcs['vcs:source']==='https://github.com/'+expectedSource.repository&&
  vcs['vcs:localdir:dockerfile']==='docker/bootstrap','BaseMetadataSource');
 const r=archive.record;need(typeof r.Ref==='string'&&metadata['buildx.build.ref']?.split('/').at(-1)===r.Ref&&
  r.FrontendAttrs?.['vcs:revision']===buildRevision&&r.FrontendAttrs['vcs:source']==='https://github.com/'+expectedSource.repository&&
  r.FrontendAttrs['vcs:localdir:dockerfile']==='docker/bootstrap'&&r.FrontendAttrs.filename==='Dockerfile'&&
  r.FrontendAttrs.platform==='linux/arm64','BaseRecordSource');
 need(r.Exporters?.length===1&&r.Exporters[0].Type==='image'&&r.Exporters[0].Attrs?.name===tag&&r.Exporters[0].Attrs.push==='true','BaseRecordExporter');
 const time=v=>v?.seconds*1000+Math.floor((v?.nanos??0)/1000000),created=time(r.CreatedAt),completed=time(r.CompletedAt);
 need(Number.isSafeInteger(created)&&Number.isSafeInteger(completed)&&stepStart<=created&&created<=completed&&completed<stepEnd+1000,'BaseRecordTime');
 const results=[...Object.values(r.Result?.Results??{}),...(r.Result?.ResultDeprecated?[r.Result.ResultDeprecated]:[])];
 need(results.length>0&&results.every(d=>d.digest===rootDescriptor.digest&&d.size===rootDescriptor.size&&d.media_type===rootDescriptor.mediaType),'BaseRecordRoot');
 need(archive.manifest.layers.some(d=>d.digest===rootDescriptor.digest&&d.size===rootDescriptor.size),'BaseRootMembership');
 const rootBytes=archive.get(rootDescriptor),root=jsonBytes(rootBytes),arms=root.manifests?.filter(d=>d.platform?.os==='linux'&&d.platform.architecture==='arm64');
 need(root.schemaVersion===2&&root.mediaType===rootDescriptor.mediaType&&arms?.length===1,'BaseRuntimeDescriptor');
 const fragment=Buffer.from(buildLog.subarray(rows[first].start,rows[metaEnd].end));budget.charge(fragment.length);
 const rootEvents=[...text(fragment).matchAll(/(?:^|\s)#([0-9]+) exporting manifest list (sha256:[a-f0-9]{64})/g)].filter(m=>m[2]===rootDescriptor.digest);
 const vertices=new Set(rootEvents.map(m=>m[1]));need(vertices.size===1,'BaseExportVertex');const vertex=[...vertices][0];
 const configs=new Set([...text(fragment).matchAll(new RegExp('(?:^|\\s)#'+vertex+' exporting config (sha256:[a-f0-9]{64})(?:\\s|$)','g'))].map(m=>m[1]));
 need(configs.size===1,'BaseExportConfig');
 const image={account:scope.account,region:scope.region,repositoryName:'mem9-on-aws/preview/bootstrap',
  rootDigest:rootDescriptor.digest,arm64Digest:arms[0].digest,configDigest:[...configs][0]};
 verifyNonrootControlBuildLog(fragment,image);
 return {image,rootDescriptor,rootBytes,runtimeDescriptor:arms[0],metadataBytes,fragment,
  extraction:{lineIndexBase:0,firstLine:first,endLineExclusive:metaEnd+1,startByte:rows[first].start,endByte:rows[metaEnd].end,
   rawBuildLogHash:hashBytes(buildLog),exportVertex:vertex,stepNumber:step.number,maskedRegistry:values('--tag')[0]===masked}};
}

/** Recompute the masked-account binding from independently captured artifact
 * metadata and exact archive members. No log replacement or scope-only proof. */
export async function verifyMaskedBootstrapArtifact({selected,binding,identity,scope,expectedSource,io,chargeLocal,assertCurrent}){
 const resume=value=>{if(assertCurrent!==undefined){need(typeof assertCurrent==='function','ControlCensusSynchronousCurrent');const checked=assertCurrent();if(checked&&typeof checked.then==='function'){Promise.resolve(checked).catch(()=>{});need(false,'ControlCensusSynchronousCurrent');}need(checked===undefined,'ControlCensusSynchronousCurrent');}return value;};resume();
 need(typeof chargeLocal==='function','ControlCensusPreviewArtifactMeter');
 const read=async ref=>{need(ref&&typeof ref.path==='string'&&/^[a-f0-9]{64}$/.test(ref.sha256),'ControlCensusPreviewArtifactBinding');
  const raw=Buffer.from(resume(await io.readBytes(ref)));need(raw.length<=33554432&&hashBytes(raw)===ref.sha256,'ControlCensusPreviewArtifactPin');return raw;};
 const json=async ref=>jsonBytes(resume(await read(ref))),a=resume(await json(selected.artifactEvidenceRef));
 need(a.kind==='existing-build-artifact-evidence'&&same(a.baseBindingRef,selected.bindingRef)&&a.artifactMetadataRef,'ControlCensusPreviewArtifactBinding');
 const record=resume(await json(a.artifactMetadataRef));let metadata;
 if(Array.isArray(record.artifacts)){
  need(record.total_count===record.artifacts.length&&record.artifacts.length<=100&&new Set(record.artifacts.map(r=>r.id)).size===record.artifacts.length,'ControlCensusPreviewArtifactInventory');
  const rows=record.artifacts.filter(r=>r.id===a.artifactId);need(rows.length===1,'ControlCensusPreviewArtifactBinding');metadata=rows[0];
 }else metadata=record;
 const capturedRef=a.zipRef??a.archiveRef,captured=resume(await read(capturedRef)),gzip=resume(await read(a.archiveRef)),run=resume(await json(binding.evidence.run));
 need(metadata.id===a.artifactId&&/^[A-Za-z0-9_.~-]+\.dockerbuild$/.test(metadata.name??'')&&metadata.expired===false&&
  metadata.workflow_run?.id===identity.ci.runId&&metadata.workflow_run.head_sha===identity.source.runHeadRevision&&
  metadata.digest==='sha256:'+hashBytes(captured)&&metadata.size_in_bytes===captured.length,'ControlCensusPreviewArtifactIdentity');
 const start=Date.parse(run.run_started_at),end=Date.parse(run.updated_at),created=Date.parse(metadata.created_at);
 need([start,end,created].every(Number.isSafeInteger)&&start<=created&&created<=end,'ControlCensusPreviewArtifactTime');
 if(a.zipRef){
  need(a.captureOutcomeRef&&a.captureConfigRef,'ControlCensusPreviewArtifactCapture');
  const outcome=resume(await json(a.captureOutcomeRef)),config=resume(await json(a.captureConfigRef));
  need(outcome.kind==='preview-ci-evidence-capture-result'&&outcome.native===true&&outcome.status==='COMPLETE'&&outcome.cleanupComplete===true&&
   outcome.unknown===false&&outcome.code===null&&outcome.providerCommands===3&&outcome.configHash===a.captureConfigRef.sha256&&
   config.captureId===outcome.captureId&&config.owner===outcome.owner&&config.runId===identity.ci.runId&&config.runAttempt===identity.ci.runAttempt&&
   config.repository===identity.source.repository&&config.candidateRevision===identity.source.runHeadRevision&&config.artifact?.id===metadata.id&&
   config.artifact.sha256===hashBytes(captured)&&config.artifact.sizeInBytes===captured.length&&config.artifact.name===metadata.name,'ControlCensusPreviewArtifactCapture');
  for(const [key,ref]of [['run',binding.evidence.run],['artifact',a.artifactMetadataRef],['archive',a.zipRef]])
   need(outcome.refs?.[key]?.path===ref.path&&outcome.refs[key].sha256===ref.sha256,'ControlCensusPreviewArtifactCapture');
 }
 // The caller's original 128MiB census-input lane also receives every decode,
 // member-copy and log-processing charge before allocation. Its cap is unchanged.
 const budget=materialBudget({zipBytes:33554432,dockerbuildBytes:33554432,tarBytes:134217728,entries:256,localBytes:134217728});
 const local=budget.charge.bind(budget);budget.charge=n=>{chargeLocal(n);local(n);};
 const decoded=unpackCapturedBuildArtifact(captured,budget);need(decoded.raw.equals(gzip),'ControlCensusPreviewArtifactArchive');
 const archive=inspectDockerBuildArchive(gzip,budget),buildRecord=resume(await read(selected.buildRecordRef)),root=resume(await read(a.rootIndexRef));
 need(archive.recordBytes.equals(buildRecord),'ControlCensusPreviewArtifactRecord');
 const rawLog=resume(await read(binding.evidence.rawBuildLog)),job=resume(await json(binding.evidence.job));
 const actual=extractBootstrapMaterial({buildLog:rawLog,job,expectedSource,scope,buildRevision:identity.source.buildRevision,
  runId:identity.ci.runId,runAttempt:identity.ci.runAttempt,archive},budget);
 need(actual.fragment.equals(resume(await read(binding.evidence.bootstrapLog)))&&actual.rootBytes.equals(root)&&
  same(actual.image,identity.image)&&same(actual.rootDescriptor,binding.rootDescriptor)&&
  same(actual.runtimeDescriptor,a.runtimeDescriptor),'ControlCensusPreviewArtifactRoot');
 const metadataBytes=resume(await read(binding.evidence.metadata));
 need(same(jsonBytes(metadataBytes),jsonBytes(actual.metadataBytes)),'ControlCensusPreviewArtifactMetadata');
 return {authority:false,artifactRef:selected.artifactEvidenceRef,metadataRef:a.artifactMetadataRef,localBytes:budget.value.localBytes};
}
