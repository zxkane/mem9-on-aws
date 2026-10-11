import {createHash,randomBytes} from 'node:crypto';
import {mkdtemp,mkdir,writeFile,readFile,chmod,rm,realpath,lstat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {nonrootHash as hash,NONROOT_LIMITS_HASH} from '../lib/production-nonroot-contracts.mjs';
import {IMAGE_MEDIA as M,createImageBudget,readControlImageGraph,readCollectedControlImageCache} from '../lib/production-image-graph.mjs';
import {inspectImageFilesystem,inspectImageFilesystemEvidence} from '../lib/production-image-filesystem.mjs';
import {createControlSourceContext,controlSourceEntries} from '../lib/production-control-source.mjs';
import {describeProductionControlCompositionPack,encodeProductionControlCompositionPack} from '../lib/production-control-composition-packs.mjs';
import {describeProductionControlCopyManifest} from '../lib/production-control-composition-source.mjs';
import {describeProductionControlComposition,describeProductionControlCompositionFunding,compositionCharge as zero} from '../lib/production-control-composition.mjs';
import {productionControlCompositionCatalog,productionControlCompositionCleanup} from '../lib/production-control-composition-catalog.mjs';
import {createFutureFundingPlan,inspectFutureFundingPlan,FUTURE_OWNER_PUBLICATION,verifyFutureGrantSet} from '../lib/ci-smoke-grants.mjs';
import {makeCiStartupRunBinding,openCiSmokeStartup,ciStartupAnnouncement,ciStartupCheckpointSelection} from '../lib/ci-smoke-startup.mjs';
import {openProductionControlCompositionAllocation,createProductionControlCompositionCacheBudget,closeProductionControlCompositionAllocation,productionControlCompositionSnapshot} from '../lib/production-control-composition-lifetime.mjs';

export const sha=b=>createHash('sha256').update(b).digest('hex');
const git=(type,b)=>createHash('sha1').update(type+' '+b.length+'\0').update(b).digest('hex');
export function tar(rows){
 const chunks=[];
 for(const row of rows){
  const body=Buffer.from(row.body??''),h=Buffer.alloc(512);h.write(row.path,0,100);
  const oct=(n,a,w)=>h.write(n.toString(8).padStart(w-1,'0')+'\0',a,w);
  oct(row.mode??0o644,100,8);oct(0,108,8);oct(0,116,8);oct(body.length,124,12);oct(0,136,12);
  h.fill(32,148,156);h[156]=(row.type??'0').charCodeAt(0);h.write('ustar\0',257);h.write('00',263);
  h.write([...h].reduce((a,b)=>a+b,0).toString(8).padStart(6,'0')+'\0 ',148);
  chunks.push(h,body,Buffer.alloc((512-body.length%512)%512));
 }
 return Buffer.concat([...chunks,Buffer.alloc(1024)]);
}
export function sourceContext(files){
 const map=new Map(Object.entries(files).map(([path,text])=>[path,Buffer.from(text)])),root=new Map(),entries=[];
 for(const [path,raw]of map){
  const oid=git('blob',raw),entry={path,oid,type:'blob',mode:'100644'};entries.push(entry);
  const parts=path.split('/');let node=root;
  for(const part of parts.slice(0,-1)){if(!node.has(part))node.set(part,new Map());node=node.get(part);}node.set(parts.at(-1),entry);
 }
 const tree=node=>git('tree',Buffer.concat([...node].sort(([a,av],[b,bv])=>Buffer.compare(Buffer.from(a+(av instanceof Map?'/':'')),Buffer.from(b+(bv instanceof Map?'/':'')))).flatMap(([name,v])=>[
  Buffer.from((v instanceof Map?'40000':v.mode)+' '+name+'\0'),Buffer.from(v instanceof Map?tree(v):v.oid,'hex')])));
 const treeHash=tree(root),context=createControlSourceContext({tree:treeHash,entries},async(oid,path)=>{const raw=map.get(path);if(git('blob',raw)!==oid)throw Error('fixture source');return Buffer.from(raw);});
 return {context,map,tree:treeHash};
}
export async function fixture({onBuild=false,transport=false,inheritedBytes=0,packed=false,mutatePack,nativeTools=false,runtime}={}){
 const directory=await mkdtemp(join(tmpdir(),'control-composition-test-'));await chmod(directory,0o700);
 const files={'docker/bootstrap/Dockerfile':'FROM example.invalid/base\nCOPY scripts/a.mjs /app/a.mjs\n','scripts/a.mjs':'export const value=1;\n'};
 const src=sourceContext(files),data=new Map();
 const put=(value,mediaType)=>{const raw=Buffer.isBuffer(value)?value:Buffer.from(JSON.stringify(value)),d={mediaType,size:raw.length,digest:'sha256:'+sha(raw)};data.set(d.digest,raw);return d;};
 const layer=put(tar([{path:'app',type:'5',mode:0o755},{path:'app/a.mjs',body:files['scripts/a.mjs']},
  ...(inheritedBytes?[{path:'app/inherited.dat',body:Buffer.alloc(inheritedBytes,9)}]:[])]),M.tar);
 const config=put({architecture:'arm64',os:'linux',config:{User:'node',Env:['SAFE=1'],Entrypoint:['/app/a.mjs'],...(onBuild?{OnBuild:['RUN unsafe']}:{})},
  rootfs:{type:'layers',diff_ids:[layer.digest]},history:[{created_by:'ordinary fixture build'}]},M.config);
 const arm=put({schemaVersion:2,mediaType:M.manifest,config,layers:[layer]},M.manifest);
 const payload=put({_type:'https://in-toto.io/Statement/v1',subject:[{name:'ordinary-bootstrap',digest:{sha256:arm.digest.slice(7)}}],
  predicateType:'https://slsa.dev/provenance/v1',predicate:{fixture:true}},M.attestation);
 const empty=put({},M.emptyConfig),att=put({schemaVersion:2,mediaType:M.manifest,config:empty,layers:[payload]},M.manifest);
 const root=put({schemaVersion:2,mediaType:M.index,manifests:[{...arm,platform:{os:'linux',architecture:'arm64'}},{...att,platform:{os:'unknown',architecture:'unknown'}}]},M.index);
 const binding={account:'123456789012',region:'us-east-1',repositoryName:'mem9-on-aws/preview/bootstrap',root,arm64Digest:arm.digest,configDigest:config.digest};
 const store={async put(d,stream){const parts=[];for await(const b of stream)parts.push(b);if(sha(Buffer.concat(parts))!==d.digest.slice(7))throw Error('fixture bytes');},async *open(d){yield data.get(d.digest);}};
 const budget=createImageBudget({credentialExpiresMs:Date.now()+3600000}),source={manifest:async(_,d)=>data.get(d.digest),blob:async(_,d)=>(async function*(){yield data.get(d.digest);})()};
 const graph=await readControlImageGraph(binding,{source,store,budget}),fs=await inspectImageFilesystem(graph,{component:'bootstrap',budget});
 const copy=await describeProductionControlCopyManifest({sourceContext:src.context,baseFilesystem:fs});
 const codeSource={repository:'example/repository',prNumber:17,candidateRevision:'1'.repeat(40),candidateTree:src.tree,baseRevision:'3'.repeat(40)};
 const input={version:1,kind:'production-control-composition-input',base:{image:{...binding,rootDigest:root.digest},inventory:graph.inventory,
  filesystem:inspectImageFilesystemEvidence(fs),uncompressedBytes:budget.usage().uncompressedBytes,processedEntries:budget.usage().fsEntries},
  source:codeSource,copyManifest:copy.rows,packs:{tools:{ref:{sha256:sha('tools'),bytesLength:512},uncompressedBytes:512,processedEntries:1},
   source:{ref:{sha256:sha('source'),bytesLength:512},uncompressedBytes:512,processedEntries:1}},sourceToolBytes:1024};
 delete input.base.image.root;
 const packBodies={};
 if(packed){
  const sourceEntries=controlSourceEntries(src.context),tool=Buffer.from('synthetic pack member; never executed');
  const manifests={source:{version:1,kind:'native-control-composition-pack',name:'source',source:{tree:src.tree,entries:sourceEntries},
   files:sourceEntries.map(e=>({path:e.path,gitMode:e.mode,oid:e.oid,sha256:sha(src.map.get(e.path)),bytesLength:src.map.get(e.path).length})).sort((a,b)=>a.path<b.path?-1:1)},
   tools:{version:1,kind:'native-control-composition-pack',name:'tools',nodeVersion:process.versions.node,architecture:process.arch,
    files:[{path:'/synthetic/node',role:'node',mode:0o555,sha256:sha(tool),bytesLength:tool.length}]}};
  const contents=new Map([...src.map.values(),tool].map(b=>[sha(b),b]));
  if(nativeTools){
   const node=await realpath(process.execPath),paths=new Set([node]),maps=await readFile('/proc/self/maps','utf8');
   for(const line of maps.split('\n')){const m=/^[a-f0-9]+-[a-f0-9]+\s+\S+\s+\S+\s+\S+\s+\d+\s+(\/.*)$/.exec(line);
    if(m&&(m[1]===process.execPath||/\.(?:so(?:\.[0-9.]+)?|node)$/.test(m[1])))paths.add(await realpath(m[1]));}
   const entry=await realpath(process.argv[1]);paths.add(entry);manifests.tools.files=[];
   for(const path of [...paths].sort()){
    const b=await readFile(path),st=await lstat(path);contents.set(sha(b),b);
    manifests.tools.files.push({path,role:path===node?'node':path===entry?'source':'elf',mode:st.mode&0o7777,sha256:sha(b),bytesLength:b.length});
   }
  }
  for(const name of ['tools','source']){
   const p=describeProductionControlCompositionPack(manifests[name]),chunks=[];
   for await(const b of encodeProductionControlCompositionPack(manifests[name],async function*(d){const raw=contents.get(d.sha256);for(let at=0;at<raw.length;at+=65536)yield raw.subarray(at,at+65536);}))chunks.push(b);
   let body=Buffer.concat(chunks);body=mutatePack?.(name,body)??body;packBodies[name]=body;
   input.packs[name]={ref:{sha256:sha(body),bytesLength:body.length},uncompressedBytes:p.uncompressedBytes,processedEntries:p.processedEntries};
  }
  input.sourceToolBytes=Object.values(manifests).reduce((n,m)=>n+m.files.reduce((n,f)=>n+f.bytesLength,0),0);
 }
 if(runtime){input.version=2;input.runtime=runtime;input.sourceBytes=[...src.map.values()].reduce((n,b)=>n+b.length,0);input.sourceFiles=src.map.size;delete input.sourceToolBytes;delete input.packs.tools;}
 const plan=describeProductionControlComposition(input),row={id:'object',service:'s3',action:'GetObject',count:1,requestBytes:0,responseBytes:4096};
 const funding=describeProductionControlCompositionFunding(transport?{plan,catalog:productionControlCompositionCatalog(plan),...productionControlCompositionCleanup(plan)}:
  {plan,catalog:{owner:[row],ci:[row]},cleanup:{owner:zero({logicalBytes:4*1048576}),ci:zero({logicalBytes:4*1048576})},recordCounts:{owner:8,ci:32}});
 return {directory,src,source:codeSource,data,binding,graph,fs,input,plan,funding,packBodies,async remove(){await rm(directory,{recursive:true,force:true});}};
}

export async function admission(f,{mutateResponse,preloadBase=true,sourceLocalBytes=0}={}){
 const NOW=Date.now(),account='123456789012',region='us-east-1';
 const scope={kind:'source',jobKey:'build-image-transition-control',route:'build-image-transition-control',phase:'source',checkpoint:'build-image-transition-control/source'};
 const ledgerBinding={owner:'a'.repeat(32),executionId:'b'.repeat(32),planHash:'c'.repeat(64),publicationHash:'d'.repeat(64)};
 const reserve={ecrRequests:20000,logicalBytes:12*1024**3,httpBodyBytes:12*1024**3,uncompressedBytes:32*1024**3,processedEntries:1000000};
 const start={version:1,kind:'custody-ledger-start',binding:ledgerBinding,startingCounters:zero(),reserve,deadlineMs:NOW+2700000,mode:'adoption'};
 const startRaw=Buffer.from(JSON.stringify(start));
 const identity={version:1,id:'identity',kind:'EXACT',action:'GetCallerIdentity',request:{},requestBytes:1024,responseBytes:4096,count:1,ecr:false};
 const roots={version:1,kind:'future-owner-root-template',rootBindingHash:'b'.repeat(64),carrierTemplateHash:sha('carrier'),carrierSlot:{owner:ledgerBinding.owner,executionId:ledgerBinding.executionId,slotNonce:'d'.repeat(32)},source:f.source};
 const consumers=[{scope,reader:{version:1,kind:'source-two-reader',terminalResponseBytes:1048576},localBudget:zero({logicalBytes:sourceLocalBytes}),composition:{plan:f.plan,funding:f.funding}},
  ...[[9,'preupdate'],[17,'preconfigure'],[19,'presst'],[21,'preupdate'],[23,'prereadiness']].map(([n,phase])=>({scope:{kind:'target',jobKey:'deploy-prod',route:'deploy-prod',phase,checkpoint:'deploy-prod/'+n},profiles:[identity],localBudget:zero(),handshake:{terminalResponseBytes:1048576}}))];
 const catalog={version:2,kind:'future-ci-profile-catalog',source:f.source,ledgerBinding,consumers,
  owner:{publication:FUTURE_OWNER_PUBLICATION,localBudget:zero(),roots},finalization:{profiles:[identity],localBudget:zero()},localBudget:zero()};
 const grantSetId=sha(randomBytes(32));
 const rootCarrier={...roots,kind:'future-owner-root-carrier',carrierBuildHash:sha('actual-carrier'),image:inputImage(f)};
 const plan=createFutureFundingPlan({binding:{grantSetId,source:f.source,anchors:{predecessorParameterHash:'a'.repeat(64),rootBindingHash:roots.rootBindingHash,
  copyCheckpointHash:'c'.repeat(64),authorizationId:'2'.repeat(32),nextParameterVersion:2}},catalogRaw:Buffer.from(JSON.stringify(catalog)).toString('base64'),
  ledgerStartHash:sha(startRaw),ownerGithubActorId:42,ownerStateDirectory:'/synthetic/grant-'+grantSetId,issuedMs:NOW-1000,rootCarrier});
 const funding=inspectFutureFundingPlan(plan),spent=plan.budget,remaining=Object.fromEntries(Object.entries(reserve).map(([k,v])=>[k,v-spent[k]]));
 const event={version:1,sequence:1,...ledgerBinding,previousHash:null,type:'prepayment',data:{allocationId:funding.planHash,planHash:funding.planHash,scopeHash:funding.scopeHash,
  charge:plan.budget,reserveDebit:plan.budget},spent,remaining};
 const checkpoint={binding:ledgerBinding,startingCounters:zero(),counters:spent,remainingReservation:remaining,eventCount:1,lastEventHash:hash(event),active:0,sealed:false};
 const grantSet={...plan,version:3,kind:'owner-prepaid-future-grant-set',authority:false,planHash:funding.planHash,allocationId:funding.planHash,
  debit:{start,startRaw:startRaw.toString('base64'),events:[event],checkpoint}};
 const expectedRoots={grantSetId,grantHash:hash(grantSet),ledgerStartHash:plan.ledgerStartHash,catalogHash:plan.catalogHash};
 verifyFutureGrantSet({grantSet,expected:expectedRoots});
 const descriptor={version:3,stage:'prod',account,region,controlSourceTree:f.source.candidateTree,dataRevision:'3'.repeat(40),dataSourceTree:'4'.repeat(40),
  dataSourceTag:'mem9-3333333',images:{},runtimeNonce:'1'.repeat(32),authorizationId:'2'.repeat(32),issuedMs:NOW-2000,expiresMs:NOW+600000,
  transition:{version:2,kind:'image-security-nonroot-upgrade',proofHash:'a'.repeat(64),predecessorHash:'b'.repeat(64),limitsHash:NONROOT_LIMITS_HASH}};
 for(const k of ['parentProofHash','backendBindingHash','generation','targetsHash','schemaDigest','operatorDigest','buildInputsHash','securityEvidenceHash','policyHash'])descriptor[k]='b'.repeat(64);
 for(const k of ['llm-proxy','mnemo-server','qwen3-embed'])descriptor.images[k]={rootDigest:'sha256:'+'c'.repeat(64),arm64Digest:'sha256:'+'d'.repeat(64)};
 const startupConfig={version:1,kind:'owner-prepaid-startup-config',...expectedRoots,descriptorHash:hash(descriptor),proofHash:descriptor.transition.proofHash,
  source:f.source,consumers:consumers.map(c=>c.scope),ownerGithubActorId:42,notAfter:NOW+240000};
 const config={version:2,kind:'owner-ci-acquisition-config',startup:startupConfig,target:{kind:'production-data-release',descriptor,parameterVersion:2},
  account,region,ownerRoot:{runtimeNonce:descriptor.runtimeNonce,authorizationId:descriptor.authorizationId},
  storage:{bucket:'example-ci-reader',kmsKeyArn:'arn:aws:kms:'+region+':'+account+':key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',bucketKeyEnabled:true},
  bootstrap:consumers.map(c=>({checkpoint:c.scope.checkpoint,responseBytes:1048576}))};
 const main='4'.repeat(40),source={repository:f.source.repository,event:'push',ref:'refs/heads/main',
  checkout:{sha:main,tree:f.source.candidateTree,parents:[f.source.baseRevision,f.source.candidateRevision],clean:true},
  main:{sha:main,tree:f.source.candidateTree},run:{id:77,attempt:1,event:'push',headSha:main,repository:f.source.repository,path:'.github/workflows/infra-ci.yml',workflowSha:main},
  pullRequest:{number:f.source.prNumber,state:'closed',merged:true,headSha:f.source.candidateRevision,headRepository:f.source.repository,baseRef:'main',mergeCommitSha:main}};
 const binding=makeCiStartupRunBinding(startupConfig,source),env={GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:f.source.repository,GITHUB_RUN_ID:'77',GITHUB_RUN_ATTEMPT:'1',
  GITHUB_JOB:scope.jobKey,GITHUB_SHA:main,GITHUB_WORKFLOW_SHA:main,GITHUB_EVENT_NAME:'push',GITHUB_REF:'refs/heads/main',RUNNER_TEMP:f.directory};
 let claim,uploaded;
 const host={env,checkout:async()=>({revision:main,tree:f.source.candidateTree}),async api(path){
  const run={id:77,run_attempt:1,status:'in_progress',event:'push',head_sha:main,head_branch:'main',path:'.github/workflows/infra-ci.yml',repository:{full_name:f.source.repository}};
  if(path==='actions/runs/77')return run;
  if(path==='actions/artifacts/123')return {id:123,name:uploaded.name,size_in_bytes:uploaded.size,digest:'sha256:'+uploaded.digest,expired:false,
   created_at:new Date(uploaded.createdMs).toISOString(),expires_at:new Date(NOW+86400000).toISOString(),workflow_run:{id:77,head_sha:main,head_branch:'main'}};
  const initial=ciStartupAnnouncement(startupConfig,source);
  const base={id:1,url:'https://api.github.com/repos/'+f.source.repository+'/statuses/'+main,creator:{id:42}};
  const rows=[{...base,...initial.payload}];
  if(claim){const selected=ciStartupCheckpointSelection(startupConfig,binding,scope,{...claim,artifactId:123,artifactDigest:uploaded.digest});rows.push({...base,id:2,...selected.announcement.payload});}
  return rows;
 }};
 const startup=await openCiSmokeStartup({env,host,config:startupConfig,scope,source},{artifactClient:{async uploadArtifact(name,files){
  const raw=await readFile(files[0]);claim=JSON.parse(raw);uploaded={name,id:123,size:raw.length,digest:sha(raw),createdMs:Date.now()};return uploaded;
 }}});
 const response={version:1,kind:'owner-ci-allowance-response',runBinding:binding,scope,nonce:claim.nonce,artifactId:123,requestHash:hash(claim),grantSet,expiresMs:startupConfig.notAfter};
 mutateResponse?.(response);
 const allocation=await openProductionControlCompositionAllocation({startup,response,expected:{config,scope,binding,maximumExpiresMs:startupConfig.notAfter,now:Date.now()},
  source,plan:f.plan,env,tempRoot:f.directory});
 let cache,filesystem;
 if(preloadBase){const cacheDir=join(f.directory,'base');await mkdir(cacheDir,{mode:0o700});
 for(const d of f.plan.input.base.inventory.nodes)await writeFile(join(cacheDir,d.digest.slice(7)),f.data.get(d.digest),{mode:0o600,flag:'wx'});
 const parsing=createProductionControlCompositionCacheBudget(allocation);
 cache=await readCollectedControlImageCache(f.binding,{directory:cacheDir,nodes:f.plan.input.base.inventory.nodes,...parsing});
 filesystem=await inspectImageFilesystem(cache.graph,{component:'bootstrap',budget:parsing.budget});}
 const bytes=Buffer.from(JSON.stringify(source)),actualMain={version:1,kind:'actual-hardening-main',...f.source,mainRevision:main,mainTree:f.source.candidateTree,parents:source.checkout.parents,
  workflowRun:77,workflowAttempt:1,workflowPath:'.github/workflows/infra-ci.yml',workflowSha:main,authenticatedSource:{bytesHash:sha(bytes),canonicalHash:hash(source),bytesLength:bytes.length}};
 return {allocation,plan:f.plan,baseGraph:cache?.graph,baseFilesystem:filesystem,sourceContext:f.src.context,actualMain,tempRoot:f.directory,env,config,
  originalGrant:grantSet,async close(){await cache?.cache.close();if(!productionControlCompositionSnapshot(allocation).closed)closeProductionControlCompositionAllocation(allocation,{cleanupComplete:true});}};
}
function inputImage(f){return f.plan.input.base.image;}
