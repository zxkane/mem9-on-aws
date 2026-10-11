/** Verify an owner response after a fixed HTTPS reader acquired its bytes.
 * This returns data only; it cannot recreate the original startup capability. */
import {copyNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {verifyFutureGrantSet} from './ci-smoke-grants.mjs';
import {inspectFutureAcquisitionConfig,futureAcquisitionScope,futureGrantExpectations} from './ci-smoke-future-config.mjs';

const need=(ok,code='CiFutureAllowanceInvalid')=>{if(!ok)throw Error(code);};
const exact=(value,keys)=>need(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===keys.slice().sort().join());
const positive=n=>Number.isSafeInteger(n)&&n>0;
const hex=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);

export function verifyFutureAllowance(input,expected){
 const response=copyNonrootJson(input);
 exact(response,['version','kind','runBinding','scope','nonce','artifactId','requestHash','grantSet','expiresMs']);
 exact(expected,['config','scope','startupReceipt','binding','requestHash','maximumExpiresMs','now']);
 const config=inspectFutureAcquisitionConfig(expected.config),selected=futureAcquisitionScope(config,expected.scope),receipt=copyNonrootJson(expected.startupReceipt);
 need(response.version===1&&response.kind==='owner-ci-allowance-response','CiFutureAllowanceKind');
 const bindingHash=hash(expected.binding);
 need(hex(receipt.bindingHash)&&receipt.bindingHash===bindingHash&&hash(response.runBinding)===bindingHash,'CiFutureAllowanceRun');
 need(hash(response.scope)===hash(selected.scope)&&hash(receipt.scope)===hash(selected.scope),'CiFutureAllowanceScope');
 need(hex(receipt.nonce)&&response.nonce===receipt.nonce&&positive(receipt.artifactId)&&response.artifactId===receipt.artifactId,'CiFutureAllowanceNonce');
 need(receipt.scopeHash===hash({bindingHash,scope:selected.scope}),'CiFutureAllowanceScopeHash');
 need(hex(expected.requestHash)&&response.requestHash===expected.requestHash,'CiFutureAllowanceRequest');
 const roots=futureGrantExpectations(config);
 const funded=verifyFutureGrantSet({grantSet:response.grantSet,expected:roots});
 need(hash(funded.source)===hash(config.startup.source)&&funded.anchors.authorizationId===config.ownerRoot.authorizationId&&funded.anchors.nextParameterVersion===config.target.parameterVersion,'CiFutureAllowanceFundingScope');
 const consumers=funded.consumers.filter(row=>hash(row.scope)===hash(selected.scope));need(consumers.length===1,'CiFutureAllowanceConsumer');
 const consumer=consumers[0],responseBytes=consumer.scope.kind==='source'?consumer.reader?.terminalResponseBytes:consumer.handshake?.terminalResponseBytes;
 need(responseBytes===selected.responseBytes,'CiFutureAllowanceBootstrapBudget');
 // The fixed readers also bound the ORIGINAL HTTP body. This lower bound
 // rejects a response whose contents cannot fit the declared envelope at all.
 need(Buffer.byteLength(JSON.stringify(response))<=responseBytes,'CiFutureAllowanceEnvelope');
 const at=expected.now;
 need(positive(at)&&positive(expected.maximumExpiresMs)&&positive(response.expiresMs)&&at>=funded.issuedMs&&at<response.expiresMs,'CiFutureAllowanceExpired');
 need(response.expiresMs<=Math.min(expected.maximumExpiresMs,config.startup.notAfter,funded.notAfter,receipt.notAfter)&&config.startup.notAfter<=funded.notAfter,'CiFutureAllowanceWindow');
 return Object.freeze({authority:false,funded,consumer,scope:selected.scope,binding:copyNonrootJson(response.runBinding),bindingHash,
  nonce:response.nonce,artifactId:response.artifactId,requestHash:response.requestHash,expiresMs:response.expiresMs});
}
