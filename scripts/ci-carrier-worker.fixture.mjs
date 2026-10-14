import {digestAliases} from './production-image-response.fixture.mjs';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {Readable} from 'node:stream';
import {createReadStream} from 'node:fs';
import {carrierContextFixture,carrierSourceContextFixture,sha,zero} from './ci-carrier.fixture.mjs';
import {cachedCarrierNativeBase} from './ci-carrier-native-base.fixture.mjs';
import {IMAGE_MEDIA} from './lib/production-image-graph.mjs';
import {CARRIER_SQL_DERIVED_FIXTURE,CARRIER_SQL_NOJIT_FIXTURE} from './lib/ci-carrier-sql-acceptance-format.mjs';
import {CARRIER_CI_JOB,carrierHash as hash,carrierLedgerScope,carrierRunBinding,carrierRunAnnouncement,carrierCheckpointSelection,verifyCarrierBeforeCopyGrant} from './lib/ci-carrier-before-copy.mjs';

function tar(entries){const chunks=[];for(const e of entries){const b=Buffer.from(e.body??''),h=Buffer.alloc(512),oct=(n,at,len)=>h.write(n.toString(8).padStart(len-1,'0')+'\0',at,len);h.write(e.path,0,100);oct(e.mode??0o555,100,8);oct(0,108,8);oct(0,116,8);oct(b.length,124,12);oct(0,136,12);h.fill(32,148,156);h[156]=(e.type??'0').charCodeAt(0);h.write(e.link??'',157,100);h.write('ustar\0',257,6);h.write('00',263,2);h.write([...h].reduce((n,b)=>n+b,0).toString(8).padStart(6,'0')+'\0 ',148,8);chunks.push(h,b,Buffer.alloc((512-b.length%512)%512));}return Buffer.concat([...chunks,Buffer.alloc(1024)]);}
function sourceTree(files){const root=new Map(),entries=[],blobs=new Map(),git=(kind,b)=>createHash('sha1').update(kind+' '+b.length+'\0').update(b).digest('hex');
 for(const [path,text]of Object.entries(files)){const b=Buffer.from(text),oid=git('blob',b);blobs.set(oid,b);entries.push({mode:'100644',type:'blob',oid,path});let node=root;const parts=path.split('/');for(const part of parts.slice(0,-1)){if(!node.has(part))node.set(part,new Map());node=node.get(part);}node.set(parts.at(-1),oid);}
 const tree=node=>git('tree',Buffer.concat([...node].sort(([a,av],[b,bv])=>Buffer.compare(Buffer.from(a+(av instanceof Map?'/':'')),Buffer.from(b+(bv instanceof Map?'/':'')))).flatMap(([name,v])=>[Buffer.from((v instanceof Map?'40000':'100644')+' '+name+'\0'),Buffer.from(v instanceof Map?tree(v):v,'hex')])));
 return {tree:tree(root),entries,blobs};
}
export async function carrierWorkerFixture(use,{loser=false,mutateHttp,sourceOnly=false,nativeBase=false,nativeVariant='valid',material,derivedPg=false,nojitPg=false,cumulativeLimitsHash,fundingFactory,inlineConfig,manifestAliases=false,aliasDefect}={}){
 const tempRoot=await mkdtemp(join(tmpdir(),'carrier-worker-test-'));
 try{
  const data=new Map(),put=(v,mediaType)=>{const b=Buffer.isBuffer(v)?v:Buffer.from(JSON.stringify(v)),d={digest:'sha256:'+sha(b),size:b.length,mediaType};data.set(d.digest,b);return d;};
  const busybox=await readFile('/bin/busybox'),layer=put(tar([
   ...['bin','usr','usr/local','usr/local/bin','bootstrap','bootstrap/operator','carrier'].map(path=>({path,type:'5'})),
   {path:'bin/busybox',body:busybox},...['sh','rm','chmod','find'].map(name=>({path:'bin/'+name,type:'2',mode:0o777,link:'busybox'})),
   {path:'usr/local/bin/node',body:busybox},{path:'bin/setpriv',body:busybox},{path:'bootstrap/operator/stale-file',body:'stale',mode:0o444},
  ]),IMAGE_MEDIA.tar),cfg=put({os:'linux',architecture:'arm64',config:{Env:['PATH=/usr/local/bin:/usr/bin:/bin']},rootfs:{type:'layers',diff_ids:[layer.digest]}},IMAGE_MEDIA.config),arm=put({schemaVersion:2,mediaType:IMAGE_MEDIA.manifest,config:cfg,layers:[layer]},IMAGE_MEDIA.manifest),root=put({schemaVersion:2,mediaType:IMAGE_MEDIA.index,manifests:[{...arm,platform:{os:'linux',architecture:'arm64'}}]},IMAGE_MEDIA.index);
  const native=nativeBase?cachedCarrierNativeBase(tempRoot,{variant:nativeVariant}):null;
  if(native){data.clear();for(const [d,b]of native.data)data.set(d,b);}
  let selectedRoot=native?.root??root;
  if(inlineConfig){
   const selectedArm=native?.arm??arm;
   const payload=put({_type:'https://in-toto.io/Statement/v1',subject:[{name:'bootstrap',digest:{sha256:selectedArm.digest.slice(7)}}],predicateType:'https://slsa.dev/provenance/v0.2'},IMAGE_MEDIA.attestation);
   const empty=put({},IMAGE_MEDIA.emptyConfig),attestation=put({schemaVersion:2,mediaType:IMAGE_MEDIA.manifest,config:{...empty,data:inlineConfig==='valid'?'e30=':inlineConfig},layers:[payload]},IMAGE_MEDIA.manifest);
   selectedRoot=put({schemaVersion:2,mediaType:IMAGE_MEDIA.index,manifests:[{...selectedArm,platform:{os:'linux',architecture:'arm64'}},{...attestation,platform:{os:'unknown',architecture:'unknown'},annotations:{'vnd.docker.reference.digest':selectedArm.digest,'vnd.docker.reference.type':'attestation-manifest'}}]},IMAGE_MEDIA.index);data.delete(empty.digest);
  }
  const baseImage={account:'123456789012',region:'ap-northeast-1',repositoryName:'mem9-on-aws/bootstrap',rootDigest:selectedRoot.digest,arm64Digest:(native?.arm??arm).digest,configDigest:(native?.cfg??cfg).digest};
  const f=sourceOnly?carrierSourceContextFixture({baseImage,material}):carrierContextFixture({baseImage,nativePins:{nodeSha256:sha(busybox),setprivSha256:sha(busybox)}}),t=f.template,p=f.plan;
  if(cumulativeLimitsHash)t.cumulativeLimitsHash=cumulativeLimitsHash;
  if(derivedPg||nojitPg){const pin=nojitPg?CARRIER_SQL_NOJIT_FIXTURE:CARRIER_SQL_DERIVED_FIXTURE;for(const key of ['archive','rootDigest','arm64Digest','configDigest','attestationDigest','uncompressedBytes','processedEntries'])t.sqlFixture[key]=structuredClone(pin[key]);t.profiles.fixturePut.requestBytes=t.sqlFixture.archive.bytesLength;t.profiles.fixtureGet.responseBytes=t.sqlFixture.archive.bytesLength;}
  t.slotNonce=createHash('sha256').update(tempRoot).digest('hex').slice(0,32);
  Object.assign(t.bounds,{compressedBytes:nativeBase?268435456:33554432,uncompressedBytes:nativeBase?536870912:67108864,processedEntries:nativeBase?100000:1000,blobNodes:16,manifestNodes:16,grantBytes:1048576,resultBytes:1048576});
  Object.assign(t.fundedLocal.ci,{logicalBytes:nativeBase?4294967296:2147483648,uncompressedBytes:nativeBase?4294967296:1073741824,processedEntries:200000});
  // This synthetic ledger starts at zero and prepays the complete cold-import
  // test before startup. It is never a fit claim for the original live ledger.
  if(material){t.fundedLocal.ci.logicalBytes=8589934592;t.bounds.contextBytes=8388608;t.bounds.resultBytes=8388608;t.profiles.contextPut.requestBytes=t.bounds.contextBytes;t.profiles.contextConfirm.responseBytes=t.bounds.contextBytes;t.profiles.contextGet.responseBytes=t.bounds.contextBytes;t.profiles.resultPut.requestBytes=t.bounds.resultBytes;t.profiles.resultGet.responseBytes=t.bounds.resultBytes;p.deadlineMs=Date.now()+600000;}
  for(const key of ['baseManifest','baseUrl','initiate','part','complete','manifestPut'])t.profiles[key].count=16;
  t.profiles.part.requestBytes=4*Math.ceil(5242880/3)+16384;
  if(nativeBase)t.profiles.part.count=64;
  const job={name:CARRIER_CI_JOB.jobName,environment:'preview-ci'},role={Type:'AWS::IAM::Role',Properties:{RoleName:{'Fn::Sub':'github-actions-${GitHubRepo}-preview'}}};
  const tree=sourceTree({[CARRIER_CI_JOB.workflowPath]:JSON.stringify({on:{workflow_dispatch:{}},jobs:{[CARRIER_CI_JOB.jobKey]:job}}),[CARRIER_CI_JOB.roleSourcePath]:JSON.stringify({Resources:{[CARRIER_CI_JOB.roleResource]:role}}),...(material?.sourceFiles??{}),...(sourceOnly?{'scripts/lib/production-nonroot-control-prerequisites.mjs':await readFile(new URL('./lib/production-nonroot-control-prerequisites.mjs',import.meta.url),'utf8')}:{})});
  t.source.candidateTree=tree.tree;t.source.jobDefinitionHash=hash(job);t.source.roleDefinitionHash=hash(role);f.rebind();
  f.manifest.templateHash=p.templateHash;f.manifest.sourceTree=tree.tree;const h=Buffer.from(JSON.stringify(f.manifest)),n=Buffer.alloc(4);n.writeUInt32BE(h.length);const context=Buffer.concat([Buffer.from('MEM9-CARRIER-CONTEXT-V1\n'),n,h,...f.manifest.files.map(r=>f.members.get(r.path))]);
  const {carrierObjectKeys}=await import('./lib/ci-carrier-before-copy.mjs');p.context={key:carrierObjectKeys(t).context,manifestHash:hash(f.manifest),sha256:sha(context),bytesLength:context.length};
  let grant,config;
  if(fundingFactory)({grant,config}=await fundingFactory({plan:p,template:t,tempRoot,context}));
  else{
   const start={version:1,mode:'copy',binding:p.ledgerBinding,deadlineMs:p.deadlineMs,startingCounters:zero(),reserve:p.budget.total},startBytes=Buffer.from(JSON.stringify(start));p.ledgerStartHash=sha(startBytes);
   const planHash=hash(p),event={version:1,sequence:1,...p.ledgerBinding,previousHash:null,type:'prepayment',data:{allocationId:planHash,planHash,scopeHash:hash(carrierLedgerScope(t)),charge:p.budget.total,reserveDebit:p.budget.total},spent:p.budget.total,remaining:zero()};
   grant={version:1,kind:'owner-prepaid-carrier-grant',purpose:'premerge-carrier-build',plan:p,planHash,debit:{start,startRaw:startBytes.toString('base64'),events:[event],checkpoint:{binding:p.ledgerBinding,startingCounters:zero(),counters:p.budget.total,remainingReservation:zero(),eventCount:1,lastEventHash:hash(event),active:0,sealed:false}}};
   config={version:1,kind:'carrier-worker-config',grantHash:hash(grant),templateHash:p.templateHash,configHash:p.configHash,ledgerStartHash:p.ledgerStartHash,plan:p};
  }
  verifyCarrierBeforeCopyGrant(grant,{...config,now:Date.now()});
  const env={...f.sourceInput.env,RUNNER_TEMP:tempRoot,ACTIONS_ID_TOKEN_REQUEST_TOKEN:'synthetic-oidc',INPUT_GRANT_COMMITMENT:config.grantHash,INPUT_CONTEXT_COMMITMENT:p.context.sha256,MEM9_CARRIER_WORKER_CONFIG:JSON.stringify(config)};
  const observations=structuredClone(f.sourceInput.observations);observations.commit.tree.sha=tree.tree;const binding=carrierRunBinding(p,config.grantHash,observations),announcement=carrierRunAnnouncement(p,binding);
  let upload,selection,artifactRecord,ghCalls=0;
  const statuses=()=>[{id:1,creator:{id:t.ownerGithubActorId},url:'https://api.github.com/repos/'+t.source.repository+'/'+announcement.path,...announcement.payload},...(selection?[{id:2,creator:{id:t.ownerGithubActorId},url:'https://api.github.com/repos/'+t.source.repository+'/'+announcement.path,...selection.announcement.payload,...(loser?{description:'winner:'+'f'.repeat(64)}:{})}]:[])];
  const host={env,checkout:async()=>({revision:t.source.candidateRevision,tree:tree.tree}),async run(_cmd,args){if(args[0]==='status')return '';if(args[0]==='ls-tree')return tree.entries.map(e=>e.mode+' '+e.type+' '+e.oid+'\t'+e.path+'\0').join('');if(args[0]==='cat-file')return tree.blobs.get(args[2]);throw Error('SyntheticUnexpectedGit');},async api(path){ghCalls++;if(path.startsWith('commits/'))return statuses();if(path==='actions/runs/71')return observations.run;if(path.includes('/jobs?'))return {total_count:1,jobs:[observations.job]};if(path.startsWith('git/commits/'))return observations.commit;if(path.startsWith('pulls/'))return observations.pullRequest;if(path==='actions/artifacts/81')return artifactRecord;throw Error('SyntheticUnexpectedGithub');}};
  const artifactClient={async uploadArtifact(name,files){const payload=JSON.parse(await readFile(files[0]));upload={...payload,artifactId:81,artifactDigest:sha('synthetic-zip-'+payload.nonce)};selection=carrierCheckpointSelection(p,binding,upload);artifactRecord={id:81,name,size_in_bytes:200,digest:'sha256:'+upload.artifactDigest,expired:false,created_at:new Date().toISOString(),expires_at:new Date(Date.now()+172800000).toISOString(),workflow_run:{id:71,head_sha:t.source.candidateRevision,head_branch:t.source.candidateRef.slice(11)}};return {id:81,size:200,digest:upload.artifactDigest};}};
  const calls=[],uploads=new Map(),destination=new Map(),keys=carrierObjectKeys(t);let sessionName,resultBytes;
  const response=(body,headers={})=>{const b=Buffer.isBuffer(body)?body:Buffer.from(body);return {response:{statusCode:200,headers:{'content-length':String(b.length),...headers},body:Readable.from([b])}};};
  const encryption={'x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':t.scope.kmsKeyArn,'x-amz-server-side-encryption-bucket-key-enabled':'true',etag:'"synthetic"'};
  const requestHandler={destroy(){},async handle(request){
   const action=request.headers?.['x-amz-target']?.split('.').at(-1)??(request.hostname.startsWith('sts.')?new URLSearchParams(String(request.body)).get('Action'):request.hostname.startsWith('s3.')?request.method:request.hostname.includes('starport')?'S3BlobGet':'OIDC');
   const c={action,request};calls.push(c);if(mutateHttp){const overridden=await mutateHttp(c);if(overridden)return overridden;}
   if(action==='OIDC')return response(JSON.stringify({value:'synthetic.payload.signature'}));
   if(action==='AssumeRoleWithWebIdentity'){sessionName=new URLSearchParams(String(request.body)).get('RoleSessionName');return response(`<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>${'ASIA'+'A'.repeat(16)}</AccessKeyId><SecretAccessKey>${'s'.repeat(40)}</SecretAccessKey><SessionToken>synthetic-session</SessionToken><Expiration>${new Date(Date.now()+2600000).toISOString()}</Expiration></Credentials><AssumedRoleUser><AssumedRoleId>SYNTHETIC:${sessionName}</AssumedRoleId><Arn>arn:aws:sts::123456789012:assumed-role/${CARRIER_CI_JOB.previewRoleName}/${sessionName}</Arn></AssumedRoleUser></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`,{'content-type':'text/xml'});}
   if(action==='GetCallerIdentity')return response(`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:sts::123456789012:assumed-role/${CARRIER_CI_JOB.previewRoleName}/${sessionName}</Arn><UserId>SYNTHETIC:${sessionName}</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`,{'content-type':'text/xml'});
   if(action==='GET'){const key=request.path.slice(('/'+t.scope.bucket+'/').length);if(key===keys.grant)return response(JSON.stringify(grant),encryption);if(key===keys.context)return response(context,encryption);if(key===keys.fixture){if(!process.env.MEM9_CARRIER_PG_PACKAGE)throw Error('SyntheticPgPackageRequired');return {response:{statusCode:200,headers:{...encryption,'content-length':String(t.sqlFixture.archive.bytesLength)},body:createReadStream(process.env.MEM9_CARRIER_PG_PACKAGE,{highWaterMark:65521})}};}throw Error('SyntheticS3Scope');}
   if(action==='PUT'){resultBytes=Buffer.from(request.body);return response('',encryption);}
   if(action==='S3BlobGet')return response(data.get('sha256:'+request.path.slice(1)));
   const q=JSON.parse(request.body),base={registryId:q.registryId,repositoryName:q.repositoryName};
   if(action==='BatchGetImage'){const d=q.imageIds[0].imageDigest,b=data.get(d);const value={failures:[],images:[{...base,imageId:{imageDigest:d},imageManifest:b.toString(),imageManifestMediaType:JSON.parse(b).mediaType}]};return response(JSON.stringify(manifestAliases?digestAliases(value,aliasDefect):value));}
   if(action==='GetDownloadUrlForLayer'){const date=new Date().toISOString().replace(/[-:]/g,'').replace(/\.\d{3}Z$/,'Z'),search=new URLSearchParams({'X-Amz-Algorithm':'AWS4-HMAC-SHA256','X-Amz-Date':date,'X-Amz-Expires':'900','X-Amz-SignedHeaders':'host','X-Amz-Credential':'ASIA'+'A'.repeat(16)+'/'+date.slice(0,8)+'/'+t.scope.region+'/s3/aws4_request','X-Amz-Signature':'a'.repeat(64)});return response(JSON.stringify({layerDigest:q.layerDigest,downloadUrl:'https://prod-'+t.scope.region+'-starport-layer-bucket.s3.'+t.scope.region+'.amazonaws.com/'+q.layerDigest.slice(7)+'?'+search}));}
   if(action==='BatchCheckLayerAvailability')return response(JSON.stringify({layers:q.layerDigests.map(layerDigest=>({layerDigest,layerAvailability:'UNAVAILABLE'})),failures:[]}));
   if(action==='InitiateLayerUpload'){const uploadId='aaaaaaaa-aaaa-aaaa-aaaa-'+String(uploads.size+1).padStart(12,'0');uploads.set(uploadId,[]);return response(JSON.stringify({...base,uploadId,partSize:5242880}));}
   if(action==='UploadLayerPart'){uploads.get(q.uploadId).push(Buffer.from(q.layerPartBlob,'base64'));return response(JSON.stringify({...base,uploadId:q.uploadId,lastByteReceived:q.partLastByte}));}
   if(action==='CompleteLayerUpload'){const b=Buffer.concat(uploads.get(q.uploadId));if('sha256:'+sha(b)!==q.layerDigests[0])throw Error('SyntheticUploadDigest');destination.set(q.layerDigests[0],b);return response(JSON.stringify({...base,uploadId:q.uploadId,layerDigest:q.layerDigests[0]}));}
   if(action==='PutImage'){destination.set(q.imageDigest,Buffer.from(q.imageManifest));return response(JSON.stringify({image:{...base,imageId:{imageDigest:q.imageDigest}}}));}
   throw Error('SyntheticUnexpectedAws');
  }};
  const seams={host,startup:{artifactClient},transport:{requestHandler,oidcLocation:()=>new URL('https://fixture.actions.githubusercontent.com/fixture/idtoken?api-version=2.0&audience=sts.amazonaws.com')}};
  await use({env,seams,f,config,grant,binding,calls,destination,tempRoot,native,result:()=>resultBytes,ghCalls:()=>ghCalls});
 }finally{await rm(tempRoot,{recursive:true,force:true});}
}
