import {carrierHash,carrierLedgerScope} from './ci-carrier-before-copy.mjs';
import {carrierLocalState} from './ci-carrier-local-counter.mjs';
import {createCarrierRawHttp} from './ci-carrier-http-transport.mjs';
import {createCarrierGithubRaw} from './ci-carrier-github-raw.mjs';
import {uploadCarrierStartupArtifact} from './ci-carrier-artifact-raw.mjs';
const need=(v,c)=>{if(!v)throw Error(c);},zero=()=>({ecrRequests:0,logicalBytes:0,httpBodyBytes:0,uncompressedBytes:0,processedEntries:0});
export function createCarrierNativeHttp(counter,env,{request}={}){
 const s=carrierLocalState(counter);need(s.http&&s.env===env,'CarrierHttpOriginalCounter');s.checkNormal();
 // Bound initial credential/runtime metadata work in the same original LOCAL pool.
 s.reserveLocal({...zero(),logicalBytes:8*65536});
 const http=createCarrierRawHttp({account:s.http,deadlineMs:s.plan.deadlineMs-s.policy.cleanupMs,...(request?{request}:{})}),github=createCarrierGithubRaw({http,env,repository:s.plan.template.source.repository,actor:'ci'});
 const run=fn=>s.capture(async signal=>{const abort=()=>http.abort();signal.addEventListener('abort',abort,{once:true});try{signal.throwIfAborted();return await fn();}catch(error){s.hold();throw error;}finally{signal.removeEventListener('abort',abort);}});
 return Object.freeze({api:path=>run(()=>github.api({path:'repos/'+s.plan.template.source.repository+'/'+path})),uploadArtifact(name,files,directory,options){need(name==='mem9-carrier-start-'+carrierHash(carrierLedgerScope(s.plan.template))&&files.length===1&&files[0]===directory+'/claim.json'&&options.retentionDays===2&&options.compressionLevel===0&&options.skipArchive===false,'CarrierHttpArtifactInput');return run(()=>uploadCarrierStartupArtifact({http,env,name,file:files[0],directory,check:s.checkNormal,local:n=>s.reserveLocal({...zero(),logicalBytes:n})}));},async close(){try{return await http.close();}finally{github.close();}}});
}
