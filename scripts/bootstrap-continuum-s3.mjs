#!/usr/bin/env node
// Operator bootstrap after reviewing and deploying continuum-s3.json. Existing
// source/scan bindings are never silently adopted or overwritten.
import { parseArgs } from 'node:util';
import { readPrivate, writePrivate } from './deploy-continuum.mjs';
import { createClients } from './continuum/s3-client.mjs';
import { AdmissionError, ensure, sha, git, sha256, snapshotConfiguration } from './lib/continuum-s3.mjs';
import { github } from './continuum-s3-cycle.mjs';
const {values}=parseArgs({options:{binding:{type:'string'},state:{type:'string'}}});
let api;
try {
  ensure(values.binding?.endsWith('.local.json') && values.state?.endsWith('.local.json') && values.binding!==values.state,'Private binding and state files required');
  const binding=await readPrivate(values.binding);
  const {account,region,bucket,roleArn,externalId,repository}=binding;
  ensure(/^\d{12}$/u.test(account??'') && region==='us-east-1' && /^[\w.-]+\/[\w.-]+$/u.test(repository??'') && roleArn?.startsWith(`arn:aws:iam::${account}:role/continuum/integrations/`) && /^[a-z0-9-]{3,63}$/u.test(bucket??'') && /^[A-Za-z0-9-]{32,64}$/u.test(externalId??''),'Invalid bootstrap binding');
  const main=(await github(`repos/${repository}/git/ref/heads/main`)).object.sha;ensure(sha(main),'Invalid main revision');
  await git(process.cwd(),['fetch','--no-tags','origin',main]);
  api=createClients(region,bucket,account);ensure((await api.identity()).Account===account,'Wrong AWS account');await api.bucketSafe();
  let state=await readPrivate(values.state,true);
  if(!state){state={binding,revision:main,integrationToken:sha256(`${bucket}:${externalId}`),phase:'integration'};await writePrivate(values.state,state);}
  ensure(JSON.stringify(state.binding)===JSON.stringify(binding),'Bootstrap binding changed');
  if(!state.integrationId){
    ensure(state.phase==='integration','Ambiguous integration journal');
    const result=await api.call('CreateIntegration',{name:'mem9S3Source',clientToken:state.integrationToken,providerConfiguration:{s3:{bucket,roleArn,externalId}}});
    state.integrationId=result.integrationId;state.phase='source';await writePrivate(values.state,state);
  }
  const revision=state.revision,key=`code/${revision}/source-${revision}.zip`;
  const archive=await git(process.cwd(),['archive','--format=zip',revision],{binary:true});
  try{await api.put(key,archive,{IfNoneMatch:'*',Metadata:{revision,sha256:sha256(archive)}});}catch(error){if(error.$metadata?.httpStatusCode!==412)throw error;const existing=await api.get(key,undefined,100*1024*1024);ensure(existing && sha256(existing.bytes)===sha256(archive),'Archive mismatch');}
  if(!state.environmentId){
    ensure(state.phase==='source','Ambiguous environment create; reconcile AWS before retrying');
    const environments=await api.list('ListEnvironments',{});
    ensure(!environments.some(e=>e.name==='mem9S3Security'),'Named environment already exists; reconcile ownership');
    state.phase='creating';await writePrivate(values.state,state);
    const result=await api.call('CreateEnvironment',{name:'mem9S3Security',configuration:snapshotConfiguration(state.integrationId,revision)});
    state.environmentId=result.environmentId;state.phase='bound';await writePrivate(values.state,state);
  }
  const scans=await api.list('ListCodeScans',{environmentId:state.environmentId});
  ensure(scans.length>0,'Initial scan is not visible yet; retry bootstrap to finish binding');
  const receipt={version:2,repository,integrationId:state.integrationId,environmentId:state.environmentId,bucket,source:revision,lastScanAt:Date.now(),scans:Object.fromEntries(scans.map(scan=>[scan.scanRunId,revision])),patches:[]};
  const existing=await api.get('control/state.json');
  if(!existing)await api.put('control/state.json',JSON.stringify(receipt),{IfNoneMatch:'*'});
  else{const saved=JSON.parse(existing.bytes);ensure(saved.environmentId===state.environmentId && saved.integrationId===state.integrationId,'Existing controller state differs');}
  console.log(JSON.stringify({integrationId:state.integrationId,environmentId:state.environmentId,source:revision,scanStatus:scans[0].status}));
} catch(error){console.error(JSON.stringify({error:error.$metadata?error.name:error instanceof AdmissionError?error.message:'bootstrap transport failure',status:error.$metadata?.httpStatusCode}));process.exitCode=1;}finally{api?.destroy();}
