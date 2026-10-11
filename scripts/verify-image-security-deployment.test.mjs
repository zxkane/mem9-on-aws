import {it,expect} from 'vitest';
import {imageTransitionFixture,imageTransitionServingFixture} from './production-image-transition.fixture.mjs';
import {buildImageTransitionProof,imageTransitionContextBindings} from './lib/production-image-transition-proof.mjs';
import {verifyImageSecurityDeployment,parseImageDeploymentArguments} from './verify-image-security-deployment.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
import {readFileSync} from 'node:fs';
import {parse} from 'yaml';
import {mkdtemp,readFile,stat,rm,writeFile} from 'node:fs/promises';
import {join,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {writeImageDeploymentBundle,removeImageDeploymentBundle,readImageDeploymentBundle,restoreImageDeploymentBundle} from './lib/production-image-deployment-bundle.mjs';
import {parse as parseJavaScript} from '@babel/parser';
import {controlCompositionActionStep} from './lib/production-control-composition-job.mjs';

function sourceCalls(path,name){
 const ast=parseJavaScript(readFileSync(new URL(path,import.meta.url),'utf8'),{sourceType:'module'});
 const declaration=ast.program.body.find(n=>n.type==='ExportNamedDeclaration'&&n.declaration?.id?.name===name)?.declaration;
 expect(declaration,name).toBeDefined();
 const calls=[];
 const visit=node=>{if(!node||typeof node!=='object')return;if(node.type==='CallExpression')calls.push(node);for(const [key,value]of Object.entries(node)){if(['loc','start','end'].includes(key))continue;if(Array.isArray(value))value.forEach(visit);else visit(value);}};
 visit(declaration.body);return calls.sort((a,b)=>a.start-b.start);
}
const callName=node=>node.callee.type==='Identifier'?node.callee.name:node.callee.type==='MemberExpression'?node.callee.property.name:undefined;
const callOrder=(calls,names)=>calls.map(callName).filter(name=>names.includes(name));
const numberValue=node=>node?.type==='NumericLiteral'?node.value:node?.type==='BinaryExpression'&&node.operator==='*'?numberValue(node.left)*numberValue(node.right):NaN;

it.each([
 [[], 'source',0],[['--build'],'source',35*60*1000],[['--deploy'],'preconfigure',0],
 [['--deploy','--phase','preupdate'],'preupdate',0],[['--deploy','--phase','preconfigure'],'preconfigure',0],
 [['--deploy','--phase','presst'],'presst',80*60*1000],[['--deploy','--phase','prereadiness'],'prereadiness',0],
])('selects only the reserved window for args %j', (args,phase,minimumValidityMs)=>{
 expect(parseImageDeploymentArguments(args)).toEqual({phase,minimumValidityMs});
});
it.each([['--deploy','--phase','unknown'],['--deploy','--phase'],['--build','--phase','presst'],['--deploy','--phase','presst','extra'],['--deploy','--phase','source']].map(args=>[args]))('rejects invalid window arguments %j',args=>{
 expect(()=>parseImageDeploymentArguments(args)).toThrow('ImageDeploymentArgumentsInvalid');
});

it('writes a private bundle by reference and removes only its verified owned directory',async()=>{
 const scratch=await mkdtemp(join(tmpdir(),'mem9-bundle-test-')),environmentFile=join(scratch,'env'),masks=[];
 let written;
 try{
  written=await writeImageDeploymentBundle({fixture:true},{environmentFile,mask:v=>masks.push(v)});
  expect((await stat(written.file)).mode&0o777).toBe(0o600);expect((await stat(dirname(written.file))).mode&0o777).toBe(0o700);
  expect(masks).toEqual([written.digest,written.file]);expect(await readFile(environmentFile,'utf8')).not.toContain('fixture');
  expect(await readImageDeploymentBundle(written.file,written.digest)).toEqual({fixture:true});
  const env={MEM9_IMAGE_TRANSITION_BUNDLE_FILE:written.file,MEM9_IMAGE_TRANSITION_BUNDLE_HASH:written.digest};
  await expect(removeImageDeploymentBundle({...env,MEM9_IMAGE_TRANSITION_BUNDLE_HASH:'0'.repeat(64)})).rejects.toThrow();expect(await stat(written.file)).toBeDefined();
  await removeImageDeploymentBundle(env);await expect(stat(dirname(written.file))).rejects.toMatchObject({code:'ENOENT'});
 }finally{if(written)await rm(dirname(written.file),{recursive:true,force:true});await rm(scratch,{recursive:true,force:true});}
});
it('preserves unrelated files instead of recursively clearing the bundle directory',async()=>{
 const scratch=await mkdtemp(join(tmpdir(),'mem9-bundle-test-'));let written;
 try{
  written=await writeImageDeploymentBundle({fixture:true},{environmentFile:join(scratch,'env')});const unrelated=join(dirname(written.file),'unrelated');await writeFile(unrelated,'keep');
  await expect(removeImageDeploymentBundle({MEM9_IMAGE_TRANSITION_BUNDLE_FILE:written.file,MEM9_IMAGE_TRANSITION_BUNDLE_HASH:written.digest})).rejects.toMatchObject({code:'ENOTEMPTY'});
  expect(await readFile(unrelated,'utf8')).toBe('keep');
 }finally{if(written)await rm(dirname(written.file),{recursive:true,force:true});await rm(scratch,{recursive:true,force:true});}
});

it('gates image publication and production deployment before their first AWS mutations',()=>{
 const workflow=parse(readFileSync(new URL('../.github/workflows/infra-ci.yml',import.meta.url),'utf8'));
 for(const name of ['verify-production-image-transition','build-image-transition-control','deploy-prod']){
  const job=workflow.jobs[name],steps=job.steps;
  expect(steps.find(s=>s.uses?.startsWith('actions/checkout@')).with['fetch-depth']).toBe(0);
  expect(job.permissions).toMatchObject({actions:'read','pull-requests':'read'});
  if(name==='build-image-transition-control'){
   expect(steps).toHaveLength(3);expect(steps[0].name).toBe('Deployment maintenance gate');
   expect(steps[0].run).toContain('exit 1');expect(steps[2]).toEqual(controlCompositionActionStep());
   expect(steps.some(s=>s.uses?.startsWith('aws-actions/configure-aws-credentials@')||s.run==='npm ci')).toBe(false);
   expect(job.permissions['id-token']).toBe('write');
   continue;
  }
  const gate=steps.findIndex(s=>name==='deploy-prod'
   ?s.uses==='./.github/actions/ci-smoke-gate'&&s.with?.mode==='target'&&s.with.phase==='preupdate'
   :/^node scripts\/verify-image-security-deployment.mjs(?: --build)?$/.test(s.run??''));
  expect(gate).toBeGreaterThan(steps.findIndex(s=>s.uses?.startsWith('aws-actions/configure-aws-credentials@')));
  expect(steps.slice(0,gate).some(s=>s.run==='npm ci')).toBe(true);
  expect(steps[gate].env).toMatchObject({STAGE:'prod',MEM9_DEPLOY_ROLE_ARN:'${{ secrets.AWS_PROD_ROLE_ARN }}',GH_TOKEN:'${{ github.token }}'});
  const mutations=steps.map((s,i)=>({s,i})).filter(({s})=>s.with?.push===true||/sst (unlock|secret set|deploy)|run-bootstrap-task|record-nonroot-control-build\.mjs publish/.test(s.run??''));
  if(name==='verify-production-image-transition')expect(mutations).toEqual([]);else expect(mutations.length).toBeGreaterThan(0);
  for(const {i} of mutations)expect(gate).toBeLessThan(i);
  const cleanup=steps.find(s=>s.run==='node scripts/verify-image-security-deployment.mjs --cleanup');expect(cleanup?.if).toContain('always()');
 }
 const build=workflow.jobs['build-and-push-image'],preflight=workflow.jobs['verify-production-image-transition'];
 expect(build.needs).toContain('verify-production-image-transition');expect(build.if).toContain("needs.verify-production-image-transition.outputs.image_transition == 'false'");expect(build.if).toContain("needs.verify-production-image-transition.result == 'success'");
 expect(preflight.if).toContain("github.event_name == 'push' || github.event_name == 'workflow_dispatch'");
 expect(workflow.jobs['deploy-prod'].needs).toContain('verify-production-image-transition');expect(workflow.jobs['deploy-prod'].if).toContain("needs.verify-production-image-transition.result == 'success'");
 const control=workflow.jobs['build-image-transition-control'],deploy=workflow.jobs['deploy-prod'];
 expect(control.if).toContain("needs.verify-production-image-transition.outputs.image_transition == 'true'");expect(control.if).toContain("needs.verify-production-image-transition.result == 'success'");
 expect(control['timeout-minutes']).toBe(30);expect(deploy['timeout-minutes']).toBe(75);
 expect(control.steps.filter(s=>s.uses==='./.github/actions/control-composition')).toEqual([controlCompositionActionStep()]);
 expect(control.outputs).toMatchObject({image_tag:'${{ steps.bootstrap.outputs.image_tag }}',bootstrap_digest:'${{ steps.bootstrap.outputs.digest }}',control_capture:'${{ steps.bootstrap.outputs.commitment }}'});
 for(const command of ['node scripts/run-production-runtime.mjs configure',null]){
  const at=deploy.steps.findIndex(s=>command?s.run===command:s.name==='Deploy prod stage');
  const guard=deploy.steps[at-1];
  expect(guard.run).toBe('node scripts/verify-ci-smoke-isolation.mjs guard --route "$MEM9_CI_SMOKE_ROUTE" --step "$MEM9_CI_SMOKE_STEP" --phase "$MEM9_CI_SMOKE_PHASE"');
  expect(guard.if).toBe('success() && (true)');expect(guard.env.MEM9_CI_SMOKE_ROUTE).toBe('deploy-prod');
  expect(guard.env.MEM9_CI_SMOKE_PHASE).toBe(command?'preconfigure':'presst');
  expect(deploy.steps[at-2].uses).toBe('./.github/actions/ci-smoke-gate');
  expect(deploy.steps[at-2].with).toEqual({mode:'target',phase:command?'preconfigure':'presst'});
 }
 expect(deploy.steps.find(s=>s.name==='Deploy prod stage').env.MEM9_EXPECTED_BOOTSTRAP_DIGEST).toBe('${{ needs.build-image-transition-control.outputs.bootstrap_digest }}');
 expect(deploy.if).toContain("needs.build-image-transition-control.result == 'success'");
});
it('keeps the native SOURCE, 35-minute protected guard, publication and cleanup in the original ordered lifetime',()=>{
 const main=sourceCalls('./lib/production-control-composition-main.mjs','runProductionControlCompositionMain');
 const mainOrder=['openProductionControlCompositionSourceGate','requireProductionControlCompositionAllocation','reserveProductionControlComposition','captureProductionControlCompositionRuntime','removeSmokeDirectory','verifyProductionControlCompositionProtectedSource','requireProductionControlCompositionProtectedSource','runProductionControlComposition'];
 // The second removal is the failure cleanup in finally, after the normal chain.
 expect(callOrder(main,mainOrder)).toEqual([...mainOrder,'removeSmokeDirectory']);
 const protectedCalls=sourceCalls('./lib/production-control-composition-protected-source.mjs','verifyProductionControlCompositionProtectedSource');
 const protectedOrder=['reserveProductionControlCompositionProtectedSource','openProductionControlCompositionProtectedSourceTransport','verifyImageSecurityDeployment'];
 expect(callOrder(protectedCalls,protectedOrder)).toEqual(protectedOrder);
 const invocation=protectedCalls.find(n=>callName(n)==='verifyImageSecurityDeployment'),options=invocation.arguments[1];
 const property=name=>options.properties.find(p=>p.key.name===name)?.value;
 expect(property('phase')?.value).toBe('source');expect(numberValue(property('minimumValidityMs'))).toBe(35*60*1000);
 expect(property('sourceReceiptHash')?.name).toBe('sourceReceiptHash');
 const controller=sourceCalls('./lib/production-control-composition-controller.mjs','runProductionControlComposition');
 const controlOrder=['openProductionControlCompositionTransport','materializeProductionControlCompositionPacks','checkRuntime','acquireProductionControlCompositionBase','composeProductionControl','publishProductionControlComposition','capture'];
 expect(callOrder(controller,controlOrder)).toEqual(['openProductionControlCompositionTransport','materializeProductionControlCompositionPacks','checkRuntime','checkRuntime','acquireProductionControlCompositionBase','checkRuntime','composeProductionControl','checkRuntime','publishProductionControlComposition','checkRuntime','capture','checkRuntime']);
 expect(controller.filter(n=>callName(n)==='checkRuntime').map(n=>n.arguments[0].value)).toEqual(['packs','source','base','composed','published','captured']);
 expect(callOrder(controller,['close','closeProductionControlCompositionOutput','closeProductionControlCompositionBase','closeProductionControlCompositionPacks','closeProductionControlCompositionRuntimeAllocation','closeProductionControlCompositionAllocation','productionControlCompositionRuntimeTerminal'])).toEqual(['close','closeProductionControlCompositionOutput','closeProductionControlCompositionBase','closeProductionControlCompositionPacks','closeProductionControlCompositionRuntimeAllocation','closeProductionControlCompositionAllocation','productionControlCompositionRuntimeTerminal']);
});
it.each([35*60*1000,80*60*1000])('holds a deployment whose authorization cannot cover its %i ms operation window',async minimumValidityMs=>{
 const f=await fixture();await expect(verifyImageSecurityDeployment(f.deps,{...f.options,minimumValidityMs})).rejects.toThrow('ImageDeploymentWindowInsufficient');expect(f.calls).toHaveLength(1);
});
it.each(['preupdate','prereadiness'])('does not require another eighty-minute window at the %s checkpoint',async phase=>{
 const f=await fixture();expect(f.s.data.expiresMs-f.f.now).toBeLessThan(80*60*1000);
 const options=parseImageDeploymentArguments(['--deploy','--phase',phase]);
 await expect(verifyImageSecurityDeployment(f.deps,{...f.options,...options})).resolves.toHaveProperty('bundle');
 f.deps.clock=()=>f.s.data.expiresMs;
 await expect(verifyImageSecurityDeployment(f.deps,{...f.options,...options})).rejects.toThrow();
});
async function fixture(){
 const f=await imageTransitionFixture(),proof=await buildImageTransitionProof(f.input,f),s=imageTransitionServingFixture(f,proof),b=imageTransitionContextBindings(s.authorizationContext),sha='8'.repeat(40),parents=[b.control.baseRevision,b.control.revision];
 const env={STAGE:'prod',GITHUB_ACTIONS:'true',MEM9_DEPLOY_ROLE_ARN:`arn:aws:iam::${s.data.account}:role/deploy`,GITHUB_REPOSITORY:b.control.repository,GITHUB_EVENT_NAME:'push',GITHUB_REF:'refs/heads/main',GITHUB_SHA:sha,GITHUB_WORKFLOW_SHA:sha,GITHUB_RUN_ID:'123',GITHUB_RUN_ATTEMPT:'1'};
 const parameter={Name:'/mem9-on-aws/prod/consolidation-runtime/data-release',Type:'SecureString',Version:2,ARN:`arn:aws:ssm:${s.data.region}:${s.data.account}:parameter/mem9-on-aws/prod/consolidation-runtime/data-release`,Value:JSON.stringify(s.data)},calls=[];
 const clients={sts:{send:async()=>({Account:s.data.account,Arn:`arn:aws:sts::${s.data.account}:assumed-role/deploy/test`})},ssm:{send:async command=>{calls.push(command.input);return {Parameters:[parameter]};}}};
 const api=async path=>{if(path==='commits/main'||path==='commits/'+sha)return {sha,commit:{tree:{sha:b.control.sourceTree}},parents:parents.map(sha=>({sha}))};if(path.startsWith('pulls/'))return {number:b.control.prNumber,state:'closed',merged:true,head:{sha:b.control.revision,repo:{full_name:b.control.repository}},base:{ref:'main'},merge_commit_sha:sha};return {id:123,run_attempt:1,event:'push',head_sha:sha,head_repository:{full_name:b.control.repository},path:'.github/workflows/infra-ci.yml'};};
 const git=async args=>args[0]==='show'?sha+'\n'+b.control.sourceTree+'\n'+parents.join(' '):'';
 const operation={version:1,kind:'image-security-transition',operation:{owner:s.data.authorizationId},authorization:{data:s.data,hash:hash(s.data),review:s.review},expected:{transitionProofHash:proof.proofHash},predecessor:{Type:'SecureString',Version:1,Value:f.input.predecessorText}};
 const loaded={context:s.authorizationContext,records:{proof:proof.proof,operation,
  graphEvidence:{version:1,graphHash:hash(proof.proof.graph),summary:proof.proof.graph,inventory:proof.proof.graphInventory,destinationReadback:proof.proof.destinationReadback},
  filesystemEvidence:{version:1,filesystemHash:hash(proof.proof.filesystem),evidence:proof.proof.filesystemEvidence,filesystem:proof.proof.filesystem}},targetObservation:{observedMs:f.now,artifacts:f.input.artifacts}};
 const deps={clients,git,api,clock:()=>f.now,readEcr:async()=>{},loadAuthority:async()=>loaded};return {f,s,b,env,parameter,calls,deps,options:{env,region:s.data.region}};
}
it('checks real source and unchanged protected readback before returning a deployment bundle',async()=>{
 const f=await fixture(),r=await verifyImageSecurityDeployment(f.deps,f.options);expect(r.phase).toBe('image-security-source-verified');expect(f.calls).toHaveLength(2);expect(hash(r.bundle.operation.authorization.review)).toBe(f.s.data.policyHash);
});
it('restores the exact issued version and rejects a later same-byte overwrite',async()=>{
 const f=await fixture(),r=await verifyImageSecurityDeployment(f.deps,f.options),expected={stage:'prod',account:f.s.data.account,region:f.s.data.region,controlSourceTree:f.s.data.controlSourceTree};
 const options={parameter:f.parameter,expected,controlRevision:f.env.GITHUB_SHA,now:f.f.now};
 await expect(restoreImageDeploymentBundle(r.bundle,options)).resolves.toBeDefined();
 for(const version of [1,3,99]){
  const parameter={...f.parameter,Version:version},bundle={...r.bundle,parameter};
  await expect(restoreImageDeploymentBundle(bundle,{...options,parameter})).rejects.toThrow('ImageDeploymentSourceInvalid');
 }
});
it('rejects wrong caller before parameter access',async()=>{const f=await fixture();f.deps.clients.sts.send=async()=>({Account:'0'.repeat(12),Arn:'foreign'});await expect(verifyImageSecurityDeployment(f.deps,f.options)).rejects.toThrow('ImageDeploymentCallerMismatch');expect(f.calls).toEqual([]);});
it('allows authenticated initial absence without claiming image-transition authority',async()=>{const f=await fixture();f.deps.clients.ssm.send=async()=>({InvalidParameters:[f.parameter.Name]});expect((await verifyImageSecurityDeployment(f.deps,f.options)).phase).toBe('image-target-not-configured');});
it('rejects a descriptor replacement during source checks',async()=>{const f=await fixture();let calls=0;const send=f.deps.clients.ssm.send;f.deps.clients.ssm.send=async command=>{if(++calls===2)f.parameter.Version++;return send(command);};await expect(verifyImageSecurityDeployment(f.deps,f.options)).rejects.toThrow('ImageDeploymentTargetChanged');});
it('rejects a main tree mismatch before any verified bundle is returned',async()=>{const f=await fixture(),api=f.deps.api;f.deps.api=async path=>{const value=await api(path);if(path==='commits/main')value.commit.tree.sha='0'.repeat(40);return value;};await expect(verifyImageSecurityDeployment(f.deps,f.options)).rejects.toThrow('ImageDeploymentSourceInvalid');});
