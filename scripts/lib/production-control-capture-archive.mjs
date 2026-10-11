/** Private cross-job observations, never runtime proof or authorization.
 * The consumer must replay its authenticated source contract and obtain the
 * actual completed GitHub job/log before admitting a deployed CONTROL build. */
import {createHash} from 'node:crypto';
import {types} from 'node:util';
import {copyNonrootJson,parseNonrootJson,inspectNonrootRecord,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {controlCaptureArchiveLocation,putControlCaptureBytes,getControlCaptureBytes} from './ci-smoke-private-archive.mjs';

export const CONTROL_BUILD_CAPTURE_LIMITS=Object.freeze({envelopeBytes:4194304,metadataBytes:1048576,prepareWindowMs:1800000,putResponseBytes:65536});
const SHA=/^[a-f0-9]{64}$/,GIT=/^[a-f0-9]{40}$/,DIGEST=/^sha256:[a-f0-9]{64}$/;
const need=(ok,code='ControlBuildCaptureInvalid')=>{if(!ok)throw Error(code);};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const integer=(v,min=1,max=Number.MAX_SAFE_INTEGER)=>need(Number.isSafeInteger(v)&&v>=min&&v<=max);
const same=(a,b)=>need(hash(a)===hash(b),'ControlBuildCaptureBinding');
function exact(value,keys){
 need(value&&typeof value==='object'&&!types.isProxy(value)&&!Array.isArray(value)&&[Object.prototype,null].includes(Object.getPrototypeOf(value)),'ControlBuildCaptureFields');
 const ds=Object.getOwnPropertyDescriptors(value),actual=Reflect.ownKeys(ds);
 need(actual.every(k=>typeof k==='string'&&ds[k].enumerable&&Object.hasOwn(ds[k],'value'))&&actual.sort().join()===keys.slice().sort().join(),'ControlBuildCaptureFields');
}
function parse(raw){
 need(raw instanceof Uint8Array&&!types.isProxy(raw)&&raw.byteLength>0&&raw.byteLength<=CONTROL_BUILD_CAPTURE_LIMITS.envelopeBytes,'ControlBuildCaptureLimit');
 return parseNonrootJson(new TextDecoder('utf-8',{fatal:true}).decode(raw));
}
function recordBytes(value){
 if(value instanceof Uint8Array){parse(value);return Buffer.from(value);}
 return Buffer.from(JSON.stringify(copyNonrootJson(value)));
}
function time(value){const n=Date.parse(value);need(typeof value==='string'&&Number.isSafeInteger(n)&&n>0,'ControlBuildCaptureTime');return n;}
function fingerprint(value){
 exact(value,['tree','copyClosureHash','dockerfileHash','ignoreHash']);need(GIT.test(value.tree));for(const k of ['copyClosureHash','dockerfileHash','ignoreHash'])need(SHA.test(value[k]));
}

// Only internal consistency is established here. Raw GitHub fields retain
// their provider shape; the capsule and recorder-owned shapes stay closed.
function inspectRecords(prepared,capture){
 const p=copyNonrootJson(prepared),c=copyNonrootJson(capture);
 exact(p,['version','kind','identity','bundleHash','contractHash','fingerprint','preparedMs']);
 need(p.version===1&&p.kind==='control-build-prepared'&&SHA.test(p.bundleHash)&&SHA.test(p.contractHash));integer(p.preparedMs);fingerprint(p.fingerprint);
 exact(p.identity,['repository','revision','runId','attempt']);
 exact(c,['version','kind','contractHash','source','actualMain','run','job','action','metadata','outputDigest','observedMs']);
 need(c.version===1&&c.kind==='nonroot-control-build-action-capture'&&c.contractHash===p.contractHash);integer(c.observedMs);
 const main=inspectNonrootRecord('ActualMainV1',c.actualMain),s=c.source;
 exact(s,['repository','event','ref','checkout','main','run','pullRequest']);
 exact(s.checkout,['sha','tree','parents','clean']);exact(s.main,['sha','tree']);
 exact(s.run,['id','attempt','event','headSha','repository','path','workflowSha']);
 exact(s.pullRequest,['number','state','merged','headSha','headRepository','baseRef','mergeCommitSha']);
 const sourceBytes=Buffer.from(JSON.stringify(s));
 same(main.authenticatedSource,{bytesHash:sha(sourceBytes),bytesLength:sourceBytes.length,canonicalHash:hash(s)});
 need(s.repository===main.repository&&s.event==='push'&&s.ref==='refs/heads/main'&&s.checkout.clean===true,'ControlBuildCaptureSource');
 need(s.checkout.sha===main.mainRevision&&s.checkout.tree===main.mainTree&&s.main.sha===main.mainRevision&&s.main.tree===main.mainTree,'ControlBuildCaptureSource');same(s.checkout.parents,main.parents);
 const pr=s.pullRequest,run=s.run;
 need(pr.number===main.prNumber&&pr.state==='closed'&&pr.merged===true&&pr.headSha===main.candidateRevision&&pr.headRepository===main.repository&&pr.baseRef==='main'&&pr.mergeCommitSha===main.mainRevision,'ControlBuildCaptureSource');
 need(run.id===main.workflowRun&&run.attempt===main.workflowAttempt&&run.event==='push'&&run.headSha===main.mainRevision&&run.workflowSha===main.workflowSha&&run.repository===main.repository&&run.path===main.workflowPath,'ControlBuildCaptureSource');
 same(p.identity,{repository:s.repository,revision:s.checkout.sha,runId:run.id,attempt:run.attempt});need(p.fingerprint.tree===s.checkout.tree,'ControlBuildCaptureFingerprint');
 const j=c.job,r=c.run,a=c.action;integer(j.id);
 need(j.run_id===run.id&&j.run_attempt===run.attempt&&j.head_sha===s.checkout.sha&&typeof j.name==='string'&&j.name.length>0&&j.name.length<=512,'ControlBuildCaptureJob');
 need(j.status==='in_progress'&&j.conclusion===null&&j.completed_at===null,'ControlBuildCaptureJob');
 need(r.id===run.id&&r.run_attempt===run.attempt&&r.event==='push'&&r.head_sha===s.checkout.sha&&r.head_branch==='main'&&r.path===run.path&&r.repository?.full_name===s.repository,'ControlBuildCaptureRun');
 need(Array.isArray(j.steps)&&j.steps.length<=100&&typeof a.name==='string'&&a.name.length>0,'ControlBuildCaptureAction');
 const matching=j.steps.filter(step=>step.name===a.name);need(matching.length===1,'ControlBuildCaptureAction');same(matching[0],a);
 const start=time(a.started_at),end=time(a.completed_at);
 need(a.status==='completed'&&a.conclusion==='success'&&time(j.started_at)<=start&&start<=end&&end<=c.observedMs,'ControlBuildCaptureTime');
 need(p.preparedMs<=start&&c.observedMs-p.preparedMs<=CONTROL_BUILD_CAPTURE_LIMITS.prepareWindowMs,'ControlBuildCaptureTime');
 need(typeof c.metadata==='string'&&Buffer.byteLength(c.metadata)<=CONTROL_BUILD_CAPTURE_LIMITS.metadataBytes,'ControlBuildCaptureMetadata');
 const metadata=parseNonrootJson(c.metadata,{maxBytes:CONTROL_BUILD_CAPTURE_LIMITS.metadataBytes});
 need(DIGEST.test(c.outputDigest)&&metadata['containerimage.digest']===c.outputDigest,'ControlBuildCaptureOutput');
 if(metadata['containerimage.descriptor']!==undefined)need(metadata['containerimage.descriptor']?.digest===c.outputDigest,'ControlBuildCaptureOutput');
 return {prepared:p,capture:c};
}
const commitmentKeys=['version','kind','runId','runAttempt','sourceRevision','sourceTree','buildJobId','outputDigest','envelopeSha256','bytesLength'];
export function inspectControlBuildCommitment(value){
 const c=copyNonrootJson(value);exact(c,commitmentKeys);need(c.version===1&&c.kind==='control-build-private-commitment');
 for(const k of ['runId','runAttempt','buildJobId'])integer(c[k]);for(const k of ['sourceRevision','sourceTree'])need(GIT.test(c[k]));
 need(DIGEST.test(c.outputDigest)&&SHA.test(c.envelopeSha256));integer(c.bytesLength,1,CONTROL_BUILD_CAPTURE_LIMITS.envelopeBytes);return c;
}
function commitmentFor(capture,bytes){
 return inspectControlBuildCommitment({version:1,kind:'control-build-private-commitment',runId:capture.source.run.id,runAttempt:capture.source.run.attempt,sourceRevision:capture.source.checkout.sha,sourceTree:capture.source.checkout.tree,buildJobId:capture.job.id,outputDigest:capture.outputDigest,envelopeSha256:sha(bytes),bytesLength:bytes.length});
}
const encodedRecord=bytes=>({sha256:sha(bytes),bytesLength:bytes.length,base64:bytes.toString('base64')});
function decodedRecord(row){
 exact(row,['sha256','bytesLength','base64']);integer(row.bytesLength,1,CONTROL_BUILD_CAPTURE_LIMITS.envelopeBytes);
 need(SHA.test(row.sha256)&&typeof row.base64==='string'&&row.base64.length===4*Math.ceil(row.bytesLength/3),'ControlBuildCaptureEncoding');
 const bytes=Buffer.from(row.base64,'base64');need(bytes.length===row.bytesLength&&bytes.toString('base64')===row.base64&&sha(bytes)===row.sha256,'ControlBuildCaptureEncoding');return bytes;
}
export function encodeControlBuildCapture(input){
 exact(input,['prepared','capture']);const preparedBytes=recordBytes(input.prepared),captureBytes=recordBytes(input.capture);
 need(4*Math.ceil(preparedBytes.length/3)+4*Math.ceil(captureBytes.length/3)+512<=CONTROL_BUILD_CAPTURE_LIMITS.envelopeBytes,'ControlBuildCaptureLimit');
 const {capture}=inspectRecords(parse(preparedBytes),parse(captureBytes));
 const bytes=Buffer.from(JSON.stringify({version:1,kind:'control-build-private-envelope',prepared:encodedRecord(preparedBytes),capture:encodedRecord(captureBytes)}));
 need(bytes.length<=CONTROL_BUILD_CAPTURE_LIMITS.envelopeBytes,'ControlBuildCaptureLimit');return {bytes,commitment:commitmentFor(capture,bytes)};
}
export function decodeControlBuildCapture(raw,commitment){
 const c=inspectControlBuildCommitment(commitment);need(raw instanceof Uint8Array&&!types.isProxy(raw)&&raw.byteLength===c.bytesLength,'ControlBuildCaptureCommitment');
 const envelopeBytes=Buffer.from(raw);need(sha(envelopeBytes)===c.envelopeSha256,'ControlBuildCaptureCommitment');const e=parse(envelopeBytes);
 exact(e,['version','kind','prepared','capture']);need(e.version===1&&e.kind==='control-build-private-envelope');
 const preparedBytes=decodedRecord(e.prepared),captureBytes=decodedRecord(e.capture),records=inspectRecords(parse(preparedBytes),parse(captureBytes));same(commitmentFor(records.capture,envelopeBytes),c);
 return Object.freeze({...records,preparedBytes,captureBytes,envelopeBytes,commitment:c});
}
export function controlBuildArchiveKey(stage,commitment){
 const c=inspectControlBuildCommitment(commitment);need(stage==='prod','ControlBuildCaptureStage');return `decisions/prod/control-build/${c.runId}/${c.runAttempt}/${c.envelopeSha256}.json`;
}
const selector=c=>({runId:c.runId,runAttempt:c.runAttempt,envelopeSha256:c.envelopeSha256,bytesLength:c.bytesLength});
export function controlBuildArchiveLocation(config,commitment){return controlCaptureArchiveLocation(config,selector(inspectControlBuildCommitment(commitment)));}

// Optional independently replayed expectations are an extra consistency check,
// never a replacement for the parent's full source-contract/completion replay.
function expectedBindings(decoded,expected){
 if(expected===undefined)return;const e=copyNonrootJson(expected);exact(e,['contractHash','source','fingerprint']);
 need(SHA.test(e.contractHash)&&decoded.capture.contractHash===e.contractHash,'ControlBuildCaptureExpected');fingerprint(e.fingerprint);same(decoded.capture.source,e.source);same(decoded.prepared.fingerprint,e.fingerprint);
}
export function inspectControlBuildTransferReceipt(value){
 const r=copyNonrootJson(value);exact(r,['version','kind','operation','accounting','envelopeSha256','bytesLength','requests','requestBodyBytes','responseBodyBytes','requestBodyBound','responseBodyBound','startedMs','completedMs','complete']);
 need(r.version===1&&r.kind==='control-build-capture-transfer'&&['PutObject','GetObject'].includes(r.operation)&&['owned-http','parent-client'].includes(r.accounting)&&SHA.test(r.envelopeSha256));
 integer(r.bytesLength,1,CONTROL_BUILD_CAPTURE_LIMITS.envelopeBytes);integer(r.requests,0,1);integer(r.requestBodyBytes,0);integer(r.responseBodyBytes,0);integer(r.startedMs);
 need(r.requestBodyBound===(r.operation==='PutObject'?r.bytesLength:0)&&r.responseBodyBound===(r.operation==='GetObject'?r.bytesLength:CONTROL_BUILD_CAPTURE_LIMITS.putResponseBytes));
 need(r.operation==='GetObject'||r.accounting==='owned-http');need(typeof r.complete==='boolean');if(r.completedMs!==null)integer(r.completedMs,r.startedMs);
 if(r.complete){need(r.completedMs!==null&&r.requests===1&&r.requestBodyBytes===r.requestBodyBound&&r.responseBodyBytes<=r.responseBodyBound);if(r.operation==='GetObject')need(r.responseBodyBytes===r.bytesLength);}
 return r;
}
export async function putControlBuildCapture(encoded,options){
 exact(encoded,['bytes','commitment']);const d=decodeControlBuildCapture(encoded.bytes,encoded.commitment);expectedBindings(d,options.expected);
 const out=await putControlCaptureBytes(d.envelopeBytes,selector(d.commitment),options);return Object.freeze({...out,commitment:d.commitment});
}
export async function getControlBuildCapture(commitment,options){
 const c=inspectControlBuildCommitment(commitment),out=await getControlCaptureBytes(selector(c),options);
 try{const d=decodeControlBuildCapture(out.bytes,c);expectedBindings(d,options.expected);return Object.freeze({...d,transferReceipt:out.transferReceipt});}
 catch{throw Object.assign(Error('ControlBuildCaptureReplayHeld'),{transferReceipt:out.transferReceipt});}
}
