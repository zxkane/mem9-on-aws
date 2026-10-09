/** Protected owner configuration supplies bootstrap limits before the first
 * allowance read. The returned data is not a paid grant or business authority. */
import {copyNonrootJson,inspectNonrootDescriptor,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {inspectCiStartupConfig} from './ci-smoke-startup.mjs';
import {nonrootAccountingPolicy} from './production-nonroot-budget-revision.mjs';

const need=(ok,code='CiFutureConfigInvalid')=>{if(!ok)throw Error(code);};
const exact=(value,keys)=>need(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===keys.slice().sort().join());
const positive=n=>Number.isSafeInteger(n)&&n>0;
export const CI_FUTURE_RESPONSE_LIMIT=1048576;

export function inspectFutureAcquisitionConfig(input){
 const c=copyNonrootJson(input);
 exact(c,['version','kind','startup','target','account','region','ownerRoot','storage','bootstrap',...(c.version===3?['budgetRevision','compiledCeiling']:[])]);
 need([2,3].includes(c.version)&&c.kind==='owner-ci-acquisition-config','CiFutureConfigVersion');
 if(c.version===3)nonrootAccountingPolicy(c.budgetRevision,c.budgetRevision,c.compiledCeiling);
 const startup=inspectCiStartupConfig(c.startup);exact(c.target,['kind','descriptor','parameterVersion']);
 need(c.target.kind==='production-data-release'&&positive(c.target.parameterVersion),'CiFutureConfigTarget');
 const d=inspectNonrootDescriptor(c.target.descriptor);
 need(hash(d)===startup.descriptorHash&&d.transition.proofHash===startup.proofHash&&d.controlSourceTree===startup.source.candidateTree,'CiFutureConfigDescriptor');
 need(d.account===c.account&&d.region===c.region&&startup.notAfter<=d.expiresMs&&startup.notAfter>d.issuedMs,'CiFutureConfigScope');
 exact(c.ownerRoot,['runtimeNonce','authorizationId']);
 need(c.ownerRoot.runtimeNonce===d.runtimeNonce&&c.ownerRoot.authorizationId===d.authorizationId,'CiFutureConfigOwner');
 const s=c.storage;exact(s,['bucket','kmsKeyArn','bucketKeyEnabled']);
 need(typeof s.bucket==='string'&&/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(s.bucket)&&!s.bucket.includes('..')&&s.bucketKeyEnabled===true,'CiFutureConfigStorage');
 need(new RegExp('^arn:aws:kms:'+c.region+':'+c.account+':key/(?:[a-f0-9-]{36}|mrk-[a-f0-9]{32})$').test(s.kmsKeyArn),'CiFutureConfigKms');
 need(Array.isArray(c.bootstrap)&&c.bootstrap.length===startup.consumers.length,'CiFutureConfigBootstrap');
 const names=new Set();
 for(const entry of c.bootstrap){
  exact(entry,['checkpoint','responseBytes']);
  need(startup.consumers.some(scope=>scope.checkpoint===entry.checkpoint)&&!names.has(entry.checkpoint)&&positive(entry.responseBytes)&&entry.responseBytes<=CI_FUTURE_RESPONSE_LIMIT,'CiFutureConfigBootstrap');
  names.add(entry.checkpoint);
 }
 need(Buffer.byteLength(JSON.stringify(c))<=65536,'CiFutureConfigSize');return c;
}

/** Roots and revision arrive together in the protected owner configuration.
 * Never construct the revision expectation from a downloaded allowance. */
export function futureGrantExpectations(config){
 const c=inspectFutureAcquisitionConfig(config);
 return {...Object.fromEntries(['grantSetId','grantHash','ledgerStartHash','catalogHash'].map(k=>[k,c.startup[k]])),...(c.version===3?{budgetRevision:c.budgetRevision,compiledCeiling:c.compiledCeiling}:{})};
}

export function futureAcquisitionScope(input,requested){
 const config=inspectFutureAcquisitionConfig(input),scope=copyNonrootJson(requested);
 const found=config.startup.consumers.filter(value=>hash(value)===hash(scope));need(found.length===1,'CiFutureConsumer');
 const grant=config.startup.grantSetId,checkpointHash=hash(scope.checkpoint),owner=config.ownerRoot;
 const base=`data-authorizations/${owner.runtimeNonce}/${owner.authorizationId}/ci-grants/${grant}`;
 return Object.freeze({scope,bucket:config.storage.bucket,expectedBucketOwner:config.account,region:config.region,kmsKeyArn:config.storage.kmsKeyArn,bucketKeyEnabled:true,
  bindingKey:base+'/run-binding.json',requestKey:`decisions/prod/ci-grants/${grant}/${checkpointHash}/request.json`,responseKey:base+'/'+checkpointHash+'/response.json',
  requestBytes:16384,responseBytes:config.bootstrap.find(entry=>entry.checkpoint===scope.checkpoint).responseBytes});
}
