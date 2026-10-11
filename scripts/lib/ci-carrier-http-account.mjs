import {createHash} from 'node:crypto';
import {carrierHttpCatalog,carrierHttpLocalAdmission,inspectCarrierHttpEvidence,inspectCarrierHttpPolicy} from './ci-carrier-http-policy.mjs';
const need=(v,c)=>{if(!v)throw Error(c);},sha=b=>createHash('sha256').update(b).digest('hex');
/** Constructed by the original CI counter or native owner funding accessor. It creates no parent credit. */
export function createCarrierHttpAccount({template,actor,binding,check,local,reserveRecords,hold}){
 need(binding&&Object.keys(binding).sort().join()==='grantHash,planHash'&&Object.values(binding).every(v=>/^[a-f0-9]{64}$/.test(v)),'CarrierHttpOriginalBinding');binding=Object.freeze({...binding});
 const policy=inspectCarrierHttpPolicy(template.httpPolicy),catalog=carrierHttpCatalog(template,actor),rows=catalog.map(r=>({id:r.id,calls:0,requestBytes:0,responseBytes:0,unknown:0}));
 let active,admitting=false,held=false,closed=false,sequence=0;
 const guard=()=>{check();need(!held&&!closed,'CarrierHttpHeld');};
 function before(id,{method,urlHash,requestBytes}){
  guard();need(!active&&!admitting,'CarrierHttpConcurrent');const i=catalog.findIndex(r=>r.id===id),p=catalog[i],used=rows[i];need(p&&used.calls<p.count,'CarrierHttpCalls');
  need(Number.isSafeInteger(requestBytes)&&requestBytes>=0&&requestBytes<=p.requestBytes,'CarrierHttpRequestLimit');
  need(used.requestBytes+used.responseBytes+requestBytes+p.responseBytes<=p.aggregateBytes,'CarrierHttpAggregate');
  const ordinal=++sequence;let intent,record;
  try{
   local(carrierHttpLocalAdmission(p,requestBytes,actor));record=reserveRecords();
   intent={version:1,kind:'carrier-http-intent',binding,actor,id,ordinal,method,urlHash,requestBytes,responseBytes:p.responseBytes};
  }catch(e){held=true;hold();throw e;}
  const slot={id,ordinal,done:false,sent:0,sentOnce:false,received:0,bodyPaid:false,requestHash:null,responseHash:null};admitting=true;
  const ready=Promise.resolve().then(()=>record('capture',{http:intent})).then(()=>{admitting=false;used.calls++;active=slot;},async error=>{admitting=false;held=true;await hold();throw error;});
  return {
   ready,
   caps:{requestBytes:p.requestBytes,responseBytes:p.responseBytes},finalGuard(){guard();need(active===slot&&!slot.done,'CarrierHttpSlot');},
   sent(bytes){this.finalGuard();need(bytes instanceof Uint8Array&&!slot.sentOnce&&bytes.length===requestBytes,'CarrierHttpRequest');slot.sentOnce=true;slot.sent=bytes.length;slot.requestHash=sha(bytes);used.requestBytes+=bytes.length;},
   observe(bytes){need(active===slot&&!slot.done&&!held&&!closed&&bytes instanceof Uint8Array&&!slot.bodyPaid,'CarrierHttpBytes');slot.received+=bytes.length;used.responseBytes+=bytes.length;need(slot.received<=p.responseBytes&&used.requestBytes+used.responseBytes<=p.aggregateBytes,'CarrierHttpResponseLimit');},
   received(bytes){this.finalGuard();need(bytes instanceof Uint8Array&&bytes.length<=policy.streamFrameBytes&&!slot.bodyPaid,'CarrierHttpFrame');},
   finishBody(){this.finalGuard();need(!slot.bodyPaid,'CarrierHttpBodyPaid');local(8*slot.received);slot.bodyPaid=true;},
   async complete({status,responseHash}){this.finalGuard();need(slot.bodyPaid&&Number.isInteger(status)&&/^[a-f0-9]{64}$/.test(responseHash),'CarrierHttpResponse');slot.responseHash=responseHash;await record('captured',{http:{...intent,status,requestHash:slot.requestHash,responseHash,observedRequestBytes:slot.sent,observedResponseBytes:slot.received,outcome:'complete'}});slot.done=true;active=undefined;},
   async unknown(partial={responseHash:null,hashedResponseBytes:0}){if(slot.done)return;slot.done=true;active=undefined;held=true;used.unknown++;try{await record('capture-failed',{http:{...intent,requestHash:slot.requestHash,observedRequestBytes:slot.sent,observedResponseBytes:slot.received,chargedUnknownBytes:requestBytes+p.responseBytes+policy.unknownBytes,partialResponseHash:partial.responseHash,hashedResponseBytes:partial.hashedResponseBytes,outcome:'unknown'}});}finally{await hold();}},
   async abandon(){if(slot.done)return;slot.done=true;active=undefined;held=true;try{await record('capture-failed',{http:{...intent,observedRequestBytes:0,observedResponseBytes:0,chargedUnknownBytes:0,outcome:'not-dispatched'}});}finally{await hold();}},
  };
 }
 return Object.freeze({before,check:guard,hold(){held=true;return hold();},evidence(){return inspectCarrierHttpEvidence({version:1,kind:'carrier-raw-http-evidence',binding,actor,rows:rows.map(r=>({...r})),held,closed},template,actor);},close(){need(!active&&!admitting,'CarrierHttpActiveCleanup');closed=true;},policy});
}
