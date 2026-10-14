import {it,expect} from 'vitest';
import {Readable} from 'node:stream';
import {main} from './verify-image-security-deployment.mjs';
import {resolveApplicationRegion} from './lib/application-region.mjs';
import {imageTransitionFixture,imageTransitionServingFixture} from './production-image-transition.fixture.mjs';
import {buildImageTransitionProof} from './lib/production-image-transition-proof.mjs';
import {imageTransitionContextBindings} from './lib/production-image-transition-proof.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';
import {join,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {removeImageDeploymentBundle,readImageDeploymentBundle} from './lib/production-image-deployment-bundle.mjs';

const parameterName='/mem9-on-aws/prod/consolidation-runtime/data-release';
const identity=account=>`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Account>${account}</Account><Arn>arn:aws:sts::${account}:assumed-role/example/test</Arn><UserId>synthetic</UserId></GetCallerIdentityResult><ResponseMetadata><RequestId>synthetic</RequestId></ResponseMetadata></GetCallerIdentityResponse>`;
async function fixture({denyAt,wrongAccount=false,parameters,failS3=false}={}){
 const region=await resolveApplicationRegion(),events=[],bodies=[];
 const env={STAGE:'prod',GITHUB_ACTIONS:'true',AWS_REGION:region,MEM9_DEPLOY_ROLE_ARN:'arn:aws:iam::123456789012:role/example',
  AWS_ACCESS_KEY_ID:'synthetic-access',AWS_SECRET_ACCESS_KEY:'synthetic-secret',AWS_SESSION_TOKEN:'synthetic-session'};
 let reads=0;
 const metadataReads={async beforeRead(action,request){
  events.push({event:'reserve',action,request});if(++reads===denyAt)throw Error('SyntheticAllocationRejected');
  return {caps:{requestBytes:16384,responseBytes:4194304},finalGuard(){events.push({event:'guard',action});},charge(bytes){events.push({event:'charge',action,bytes});},
   async complete(response,responseHash){events.push({event:'complete',action,responseHash,response});},async unknown(){events.push({event:'unknown',action});}};
 },reserveLocal(charge){events.push({event:'local',charge});},finish(){throw Error('MainMustNotFinishCallerSlot');}};
 const requestHandler={async handle(request){
  let action,raw,headers;
  if(request.hostname.startsWith('sts.')){action='GetCallerIdentity';raw=identity(wrongAccount?'0'.repeat(12):'123456789012');headers={'content-type':'text/xml'};}
  else if(request.hostname.startsWith('ssm.')){
   action='GetParameters';expect(JSON.parse(request.body)).toEqual({Names:[parameterName],WithDecryption:true});
   raw=JSON.stringify(parameters??{Parameters:[],InvalidParameters:[parameterName]});headers={'content-type':'application/x-amz-json-1.1'};
  }else if(request.hostname.startsWith('s3.')){
   action='GetObject';expect(request.headers['x-amz-expected-bucket-owner']).toBe('123456789012');
   expect(request.path).toMatch(/\/data-authorizations\/[a-f0-9]{32}\/[a-f0-9]{32}\/operation.json$/);
   if(failS3){events.push({event:'http',action});throw Error('SyntheticSocketClosed');}
   raw='{}';headers={'content-type':'application/json','content-length':'2'};
  }else throw Error('UnexpectedNetwork');
  events.push({event:'http',action});const body=Readable.from([Buffer.from(raw)]);bodies.push(body);
  return {response:{statusCode:200,headers,body}};
 },destroy(){events.push({event:'destroy'});}};
 return {env,events,bodies,adapters:{metadataReads,requestHandler}};
}
it('main uses actual SDK HTTP handling for its first STS and protected SSM reads',async()=>{
 const f=await fixture();
 await expect(main(f.env,['--deploy','--phase','preupdate'],f.adapters)).resolves.toEqual({phase:'image-target-not-configured'});
 expect(f.events.filter(e=>e.event==='reserve').map(e=>e.action)).toEqual(['GetCallerIdentity','GetParameters']);
 expect(f.events.filter(e=>e.event==='complete')).toHaveLength(2);expect(f.events.some(e=>e.event==='unknown')).toBe(false);
 expect(f.bodies.every(body=>body.destroyed)).toBe(true);
 for(const action of ['GetCallerIdentity','GetParameters'])expect(f.events.findIndex(e=>e.event==='guard'&&e.action===action)).toBeLessThan(f.events.findIndex(e=>e.event==='http'&&e.action===action));
});
it('main rejects missing acquisition before any identity request',async()=>{
 const f=await fixture();await expect(main(f.env,['--deploy','--phase','prereadiness'],{requestHandler:f.adapters.requestHandler})).rejects.toThrow('NonrootAcquisitionRequired');
 expect(f.events).toEqual([]);
});
it.each([1,2])('main never bypasses allocation rejection at read %i',async denyAt=>{
 const f=await fixture({denyAt});await expect(main(f.env,['--deploy','--phase','preupdate'],f.adapters)).rejects.toThrow('SyntheticAllocationRejected');
 expect(f.events.filter(e=>e.event==='http')).toHaveLength(denyAt-1);expect(f.events.filter(e=>e.event==='destroy')).toHaveLength(1);
});
it('main does not continue to SSM after a mismatched actual caller',async()=>{
 const f=await fixture({wrongAccount:true});await expect(main(f.env,['--deploy','--phase','preupdate'],f.adapters)).rejects.toThrow('ImageDeploymentCallerMismatch');
 expect(f.events.filter(e=>e.event==='reserve').map(e=>e.action)).toEqual(['GetCallerIdentity']);
});
it.each([false,true])('main hands the same acquisition to the actual archive loader (socketFailure=%s)',async failS3=>{
 const image=await imageTransitionFixture({observationNow:Date.now()}),proof=await buildImageTransitionProof(image.input,image),served=imageTransitionServingFixture(image,proof);
 const region=await resolveApplicationRegion();expect(served.data.region).toBe(region);
 const parameter={Name:parameterName,ARN:`arn:aws:ssm:${region}:123456789012:parameter${parameterName}`,Type:'SecureString',Version:2,Value:JSON.stringify(served.data)};
 const f=await fixture({failS3,parameters:{Parameters:[parameter],InvalidParameters:[]}});
 await expect(main(f.env,['--deploy','--phase','preupdate'],f.adapters)).rejects.toThrow(failS3?'NonrootBudgetReadFailed':'ImageArchiveProtectionInvalid');
 expect(f.events.filter(e=>e.event==='reserve').map(e=>e.action)).toEqual(['GetCallerIdentity','GetParameters','GetObject']);
 expect(f.events.filter(e=>e.event==='http')).toHaveLength(3);
 expect(f.events.filter(e=>e.event==='unknown')).toHaveLength(failS3?1:0);
 expect(f.bodies.every(body=>body.destroyed)).toBe(true);
});
it('main completes the default archive and six ECR reads through one acquisition and writes the verified bundle',async()=>{
 const image=await imageTransitionFixture({observationNow:Date.now()}),built=await buildImageTransitionProof(image.input,image),s=imageTransitionServingFixture(image,built),data=s.data;
 const b=imageTransitionContextBindings(s.authorizationContext),revision='8'.repeat(40),parents=[b.control.baseRevision,b.control.revision];
 const records={'operation.json':{version:1,kind:'image-security-transition',operation:{owner:data.authorizationId},authorization:{data,hash:hash(data),review:s.review},expected:{transitionProofHash:built.proofHash},predecessor:{Type:'SecureString',Version:1,Value:image.input.predecessorText}},
  'image-transition-proof.json':built.proof,'image-graph-evidence.json':{version:1,graphHash:hash(built.proof.graph),summary:built.proof.graph,inventory:built.proof.graphInventory,destinationReadback:built.proof.destinationReadback},
  'image-filesystem-evidence.json':{version:1,filesystemHash:hash(built.proof.filesystem),evidence:built.proof.filesystemEvidence,filesystem:built.proof.filesystem}};
 const parameter={Name:parameterName,ARN:`arn:aws:ssm:${data.region}:${data.account}:parameter${parameterName}`,Type:'SecureString',Version:2,Value:JSON.stringify(data)};
 const f=await fixture({parameters:{Parameters:[parameter]}}),directory=await mkdtemp(join(tmpdir(),'nonroot-main-http-'));
 let bundleEnv;
 try{
  const commit={sha:revision,commit:{tree:{sha:b.control.sourceTree}},parents:parents.map(sha=>({sha}))};
  const api={['commits/main']:commit,['commits/'+revision]:commit,['pulls/'+b.control.prNumber]:{number:b.control.prNumber,state:'closed',merged:true,head:{sha:b.control.revision,repo:{full_name:b.control.repository}},base:{ref:'main'},merge_commit_sha:revision},
   'actions/runs/123/attempts/1':{id:123,run_attempt:1,event:'push',head_sha:revision,head_repository:{full_name:b.control.repository},path:'.github/workflows/infra-ci.yml'}};
  await writeFile(join(directory,'source.json'),JSON.stringify({api,show:revision+'\n'+b.control.sourceTree+'\n'+parents.join(' ')}),{mode:0o600});
  const script=`#!${process.execPath}\nconst fs=require('node:fs'),path=require('node:path'),s=JSON.parse(fs.readFileSync(path.join(__dirname,'source.json'))),a=process.argv.slice(2);if(path.basename(process.argv[1])==='git'){if(a[0]==='diff')process.exit(0);if(a[0]==='show'){process.stdout.write(s.show);process.exit(0);}}else if(a[0]==='api'&&a[1]==='--hostname'&&a[2]==='github.com'){const k=a[3].split('/').slice(3).join('/');if(s.api[k]){process.stdout.write(JSON.stringify(s.api[k]));process.exit(0);}}process.exit(9);\n`;
  for(const name of ['git','gh'])await writeFile(join(directory,name),script,{mode:0o700});
  Object.assign(f.env,{PATH:directory,GITHUB_REPOSITORY:b.control.repository,GITHUB_EVENT_NAME:'push',GITHUB_REF:'refs/heads/main',GITHUB_SHA:revision,GITHUB_WORKFLOW_SHA:revision,GITHUB_RUN_ID:'123',GITHUB_RUN_ATTEMPT:'1',GITHUB_ENV:join(directory,'env')});
  const base=f.adapters.requestHandler.handle;
  f.adapters.requestHandler.handle=async request=>{
   let action,raw,headers;
   if(request.hostname.startsWith('s3.')){
    action='GetObject';const name=request.path.split('/').at(-1);expect(records[name]).toBeDefined();raw=JSON.stringify(records[name]);
    headers={'content-type':'application/json','content-length':String(Buffer.byteLength(raw)),etag:'"synthetic"','x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':`arn:aws:kms:${data.region}:${data.account}:key/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa`};
   }else if(request.hostname.startsWith('api.ecr.')){
    action='BatchGetImage';expect(request.headers['x-amz-target']).toBe('AmazonEC2ContainerRegistry_V20150921.BatchGetImage');const input=JSON.parse(request.body),name=input.repositoryName.split('/').at(-1);
    expect(input.registryId).toBe(data.account);raw=image.input.artifacts[name][input.imageIds[0].imageDigest===data.images[name].rootDigest?'root':'child'];headers={'content-type':'application/x-amz-json-1.1'};
   }else return base(request);
   f.events.push({event:'http',action});const body=Readable.from([Buffer.from(raw)]);f.bodies.push(body);return {response:{statusCode:200,headers,body}};
  };
  const result=await main(f.env,['--deploy','--phase','preupdate'],f.adapters);
  expect(result.phase).toBe('image-security-source-verified');expect(Object.keys(result).sort()).toEqual(['bundleRef','phase']);
  bundleEnv=Object.fromEntries((await readFile(f.env.GITHUB_ENV,'utf8')).trim().split('\n').map(line=>{const n=line.indexOf('=');return [line.slice(0,n),line.slice(n+1)];}));
  const bundle=await readImageDeploymentBundle(bundleEnv.MEM9_IMAGE_TRANSITION_BUNDLE_FILE,bundleEnv.MEM9_IMAGE_TRANSITION_BUNDLE_HASH);
  expect(result.bundleRef).toEqual({path:bundleEnv.MEM9_IMAGE_TRANSITION_BUNDLE_FILE,sha256:bundleEnv.MEM9_IMAGE_TRANSITION_BUNDLE_HASH});
  expect(bundle.proof).toEqual(built.proof);expect(bundle.parameter.Value).toBe(parameter.Value);
  const actions=['GetCallerIdentity','GetParameters',...Array(4).fill('GetObject'),...Array(6).fill('BatchGetImage'),'GetParameters'];
  expect(f.events.filter(e=>e.event==='reserve').map(e=>e.action)).toEqual(actions);
  expect(f.events.filter(e=>e.event==='complete').map(e=>e.action)).toEqual(actions);
  expect(f.events.some(e=>e.event==='unknown')).toBe(false);expect(f.bodies.every(body=>body.destroyed)).toBe(true);
 }finally{
  if(bundleEnv)await removeImageDeploymentBundle(bundleEnv);
  else {try{const lines=(await readFile(join(directory,'env'),'utf8')).trim().split('\n'),file=lines.find(l=>l.startsWith('MEM9_IMAGE_TRANSITION_BUNDLE_FILE='))?.split('=')[1];if(file)await rm(dirname(file),{recursive:true,force:true});}catch(e){if(e.code!=='ENOENT')throw e;}}
  await rm(directory,{recursive:true,force:true});
 }
});
