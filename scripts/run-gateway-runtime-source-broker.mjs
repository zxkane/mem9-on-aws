#!/usr/bin/env node
// Owner-run native broker for the Gateway source-condition gate. Start it in
// its own terminal from a clean checkout with the owner's AWS credentials. It
// runs the canary once, then prints the socket to export in the rollout
// terminal. See README "The operator-only Gateway source-condition canary".

import {accessSync,constants,realpathSync,statSync} from 'node:fs';
import {homedir} from 'node:os';
import {delimiter,dirname,isAbsolute,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseArgs} from 'node:util';
import {GATEWAY_SOURCE_BROKER_LIMITS as L,gatewaySourceBrokerAwsDetail,gatewaySourceBrokerDetail,gatewaySourceBrokerExitCode,gatewaySourceBrokerReason,startGatewayRuntimeSourceBroker} from './lib/gateway-runtime-source-broker.mjs';

const usage=`Usage: node scripts/run-gateway-runtime-source-broker.mjs [options]

First runs the synthetic canary once against the live Gateway boundary in
the application region. Only then does it publish its socket, and serve at
most --max-requests verify-source requests, one at a time, until
--deadline-minutes elapse. Each request re-reads the live boundary and gets a
receipt only for the statements the canary exercised.

  --deadline-minutes N  stop accepting requests after N minutes (1-${L.maximumDeadlineMs/60_000}, default ${L.defaultDeadlineMs/60_000})
  --max-requests N      requests to serve before exiting (1-${L.maximumRequests}, default ${L.maximumRequests})
  --evidence-dir PATH   private evidence root (default \${XDG_STATE_HOME:-~/.local/state}/mem9-on-aws/gateway-source-broker)
`;
const repoRoot=resolve(dirname(fileURLToPath(import.meta.url)),'..');

function executable(name){
  for(const directory of (process.env.PATH??'').split(delimiter)){
    if(!isAbsolute(directory))continue;
    const candidate=join(directory,name);
    try{accessSync(candidate,constants.X_OK);if(statSync(candidate).isFile())return realpathSync(candidate);}catch{}
  }
  throw Error(`GatewaySourceBroker${name==='aws'?'Aws':'Git'}ExecutableMissing`);
}
function bounded(value,fallback,maximum){
  if(value===undefined)return fallback;
  if(!/^[1-9][0-9]*$/.test(value)||Number(value)>maximum)throw Error('usage');
  return Number(value);
}

let options;
try{
  const {values}=parseArgs({args:process.argv.slice(2),strict:true,allowPositionals:false,options:{
    'deadline-minutes':{type:'string'},'max-requests':{type:'string'},'evidence-dir':{type:'string'},help:{type:'boolean'}}});
  if(values.help){process.stdout.write(usage);process.exit(0);}
  const state=process.env.XDG_STATE_HOME&&isAbsolute(process.env.XDG_STATE_HOME)?process.env.XDG_STATE_HOME:join(homedir(),'.local','state');
  const evidenceRoot=values['evidence-dir']??join(state,'mem9-on-aws','gateway-source-broker');
  if(!isAbsolute(evidenceRoot))throw Error('usage');
  options={deadlineMs:bounded(values['deadline-minutes'],L.defaultDeadlineMs/60_000,L.maximumDeadlineMs/60_000)*60_000,
    maxRequests:bounded(values['max-requests'],L.maximumRequests,L.maximumRequests),evidenceRoot};
}catch{
  process.stderr.write(usage);process.exit(2);
}

// A closed terminal must not end the process mid-canary; the evidence
// directory remains the record when stderr is gone.
process.stderr.on('error',()=>{});
const log=message=>{try{process.stderr.write(`gateway-source-broker: ${message}\n`);}catch{}};
// Signals during the startup canary stop its normal phase; cleanup still runs.
const startup=new AbortController();let broker,interrupted=false;
for(const signal of ['SIGINT','SIGTERM','SIGHUP'])process.on(signal,()=>{
  if(!interrupted)log('stopping: no new requests; a running canary finishes its cleanup first');
  interrupted=true;startup.abort();broker?.close({abort:true});
});
try{
  log('running the startup canary; this takes several minutes');
  broker=await startGatewayRuntimeSourceBroker({...options,repoRoot,awsExecutable:executable('aws'),gitExecutable:executable('git'),
    socketParent:realpathSync(process.env.TMPDIR&&isAbsolute(process.env.TMPDIR)?process.env.TMPDIR:'/tmp'),environment:process.env,log,signal:startup.signal});
}catch(error){
  const detail=gatewaySourceBrokerAwsDetail(error)??gatewaySourceBrokerDetail(error);
  log(`not started (${gatewaySourceBrokerReason(error)}${detail?'; '+detail:''}). The checkout must be clean, the AWS credentials an assumed role in the application account, the operator role deployed for this owner (scripts/deploy-gateway-canary-operator-role.sh), and the live Gateway boundary the reviewed document.`);
  if(error?.held)log('the canary is HELD: review its evidence directory before any retry');
  process.exit(error?.held?3:1);
}
if(interrupted){await broker.close({abort:true});process.exit(1);}
log(`source ${broker.source.commit} (tree ${broker.source.tree})`);
log(`owner role ${broker.owner.roleArn}; operator role ${broker.operator.roleArn}; application region ${broker.region}; VPC ${broker.vpcId}`);
log(`canary verified; evidence ${broker.evidenceDirectory}`);
log(`serving up to ${broker.maxRequests} request(s) until ${new Date(broker.deadlineAt).toISOString()}. In the rollout terminal run:`);
process.stdout.write(`export MEM9_BOOTSTRAP_REQUEST_SOCKET=${broker.socketPath}\n`);

const {requests}=await broker.closed;
for(const r of requests)log(`request ${r.id}: ${r.status}`);
process.exitCode=gatewaySourceBrokerExitCode(requests);

