import {it,expect,beforeEach,afterEach} from 'vitest';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,existsSync,rmSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {parse} from 'yaml';
import {ciSmokeGateActionDefinition} from './lib/ci-smoke-isolation.mjs';

let directory,entry,env;
beforeEach(()=>{
 directory=mkdtempSync(join(tmpdir(),'mem9-node-gate-test-'));
 const action=join(directory,'.github/actions/ci-smoke-gate');mkdirSync(action,{recursive:true});
 entry=join(action,'index.mjs');writeFileSync(entry,readFileSync(new URL('../.github/actions/ci-smoke-gate/index.mjs',import.meta.url)));
 mkdirSync(join(directory,'scripts'));
 // Execute the real action entry in Node. Only the downstream main is replaced;
 // these synthetic credentials must remain in that same process, never files.
 writeFileSync(join(directory,'scripts/verify-ci-smoke-isolation.mjs'),`
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
export async function main(args,env){
 assert.equal(env,process.env);
 assert.equal(env.ACTIONS_RUNTIME_TOKEN,'synthetic-runtime-token');
 assert.equal(env.ACTIONS_RESULTS_URL,'https://example.com/synthetic-results');
 writeFileSync(env.TEST_CALL,JSON.stringify({args,pid:process.pid}));
 if(env.TEST_MAIN_FAIL==='1')throw Error(env.ACTIONS_RUNTIME_TOKEN);
 if(env.TEST_MAIN_CODE)throw Object.assign(Error(env.TEST_MAIN_CODE),{code:env.TEST_ERROR_CODE,phase:env.TEST_READER_PHASE,reason:env.TEST_READER_REASON,ciSmokeTargetStage:env.TEST_TARGET_STAGE});
 return {phase:'synthetic-gate-returned'};
}
`);
 env=Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.startsWith('INPUT_')&&!key.startsWith('AWS_')&&!key.startsWith('ACTIONS_')));
 Object.assign(env,{GITHUB_JOB:'deploy-prod',GITHUB_ENV:join(directory,'github-env'),INPUT_MODE:'source',INPUT_PHASE:'',
  ACTIONS_RUNTIME_TOKEN:'synthetic-runtime-token',ACTIONS_RESULTS_URL:'https://example.com/synthetic-results',TEST_CALL:join(directory,'call.json')});
 writeFileSync(env.GITHUB_ENV,'UNCHANGED=synthetic\n');
});
afterEach(()=>{if(directory)rmSync(directory,{recursive:true,force:true});});
const run=(patch={},argv=[])=>spawnSync(process.execPath,[entry,...argv],{env:{...env,...patch},encoding:'utf8',timeout:10000});

it('declares the one fixed Node 24 entry with only mode and phase inputs',()=>{
 const action=parse(readFileSync(new URL('../.github/actions/ci-smoke-gate/action.yml',import.meta.url),'utf8'));
 expect(action).toEqual(ciSmokeGateActionDefinition());
 expect(action.runs).toEqual({using:'node24',main:'index.mjs'});
 expect(Object.keys(action.inputs).sort()).toEqual(['mode','phase']);
});
it.each([
 [{},['source','--route','deploy-prod']],
 [{INPUT_MODE:'target',INPUT_PHASE:'preupdate'},['target','--route','deploy-prod','--phase','preupdate']],
 [{INPUT_MODE:'target',INPUT_PHASE:'presst',GITHUB_JOB:'runtime-cutover-preview'},['target','--route','runtime-cutover-preview','--phase','presst']],
])('calls main in the original process with runtime credentials and the actual job', (patch,args)=>{
 const result=run(patch);expect(result.status,result.stderr).toBe(0);
 expect(JSON.parse(readFileSync(env.TEST_CALL,'utf8'))).toEqual({args,pid:result.pid});
 expect(JSON.parse(result.stdout)).toEqual({phase:'synthetic-gate-returned'});
 expect(readFileSync(env.GITHUB_ENV,'utf8')).toBe('UNCHANGED=synthetic\n');
 expect(result.stdout+result.stderr).not.toContain(env.ACTIONS_RUNTIME_TOKEN);
});
it.each([
 {INPUT_MODE:'cleanup-source'},{INPUT_MODE:'source; arbitrary-command'},{INPUT_MODE:''},
 {INPUT_MODE:'source',INPUT_PHASE:'preupdate'},{INPUT_MODE:'target',INPUT_PHASE:''},
 {INPUT_MODE:'target',INPUT_PHASE:'future'},{INPUT_ROUTE:'deploy-preview'},
 {INPUT_SCRIPT:'unreviewed.mjs'},{INPUT_ARGS:'--route deploy-preview'},{GITHUB_JOB:''},
])('rejects invalid or executable inputs before invoking main: %j',patch=>{
 const result=run(patch);expect(result.status).toBe(1);expect(existsSync(env.TEST_CALL)).toBe(false);
 expect(JSON.parse(result.stderr)).toEqual({phase:'ci-smoke-held',code:'CiSmokeActionFailed'});
 expect(readFileSync(env.GITHUB_ENV,'utf8')).toBe('UNCHANGED=synthetic\n');
});
it('does not accept caller argv or disclose a downstream error containing credentials',()=>{
 const extra=run({},['--route','deploy-preview']);expect(extra.status).toBe(1);expect(existsSync(env.TEST_CALL)).toBe(false);
 const failed=run({TEST_MAIN_FAIL:'1'});expect(failed.status).toBe(1);
 expect(failed.stdout+failed.stderr).not.toContain(env.ACTIONS_RUNTIME_TOKEN);
 expect(readFileSync(env.GITHUB_ENV,'utf8')).toBe('UNCHANGED=synthetic\n');
});
it('reports only fixed source/read-session error codes and reader phases',()=>{
 const result=run({TEST_MAIN_CODE:'CiSmokeReadSessionHeld',TEST_READER_PHASE:'precheck',TEST_READER_REASON:'CiSmokeOidcEndpoint'});
 expect(result.status).toBe(1);expect(JSON.parse(result.stderr)).toEqual({phase:'ci-smoke-held',code:'CiSmokeReadSessionHeld',readerPhase:'precheck',reason:'CiSmokeOidcEndpoint'});
 const checkout=run({TEST_MAIN_CODE:'CiSmokeCheckoutChanged'});
 expect(JSON.parse(checkout.stderr)).toEqual({phase:'ci-smoke-held',code:'CiSmokeCheckoutChanged'});
});
it('does not echo arbitrary errors, phase values, reasons or code-like token strings',()=>{
 for(const code of ['synthetic-runtime-token','CiSmokeReadSessionHeld-synthetic-runtime-token']){
  const result=run({TEST_MAIN_CODE:code,TEST_READER_PHASE:'synthetic-runtime-token',TEST_READER_REASON:'synthetic-runtime-token'});
  expect(JSON.parse(result.stderr)).toEqual({phase:'ci-smoke-held',code:'CiSmokeActionFailed'});
 }
 const result=run({TEST_MAIN_CODE:'CiSmokeReadSessionHeld',TEST_READER_PHASE:'synthetic-runtime-token',TEST_READER_REASON:'synthetic-runtime-token'});
 expect(JSON.parse(result.stderr)).toEqual({phase:'ci-smoke-held',code:'CiSmokeReadSessionHeld'});
 expect(result.stdout+result.stderr).not.toContain(env.ACTIONS_RUNTIME_TOKEN);
});
it('preserves a cleanup hold without disclosing its original error',()=>{
 const result=run({TEST_MAIN_CODE:'synthetic-runtime-token',TEST_ERROR_CODE:'ECLEANUP'});
 expect(JSON.parse(result.stderr)).toEqual({phase:'ci-smoke-held',code:'ECLEANUP'});
 expect(result.stdout+result.stderr).not.toContain(env.ACTIONS_RUNTIME_TOKEN);
});
it.each(['NonrootPreviewParameterInventory','DataReleaseAuthorizationExpired','PreviewAcquisitionCallLimit','NonrootBudgetReadFailed'])('reports fixed target diagnostics for %s without credentials',code=>{
 const result=run({INPUT_MODE:'target',INPUT_PHASE:'preupdate',TEST_MAIN_CODE:code,TEST_TARGET_STAGE:'verification'});
 expect(result.status).toBe(1);
 expect(JSON.parse(result.stderr)).toEqual({phase:'ci-smoke-held',code,targetStage:'verification'});
 expect(result.stdout+result.stderr).not.toContain(env.ACTIONS_RUNTIME_TOKEN);
});
it('never reflects arbitrary target errors or stage text',()=>{
 const result=run({TEST_MAIN_CODE:'NonrootPreviewParameterInventory-synthetic-runtime-token',TEST_TARGET_STAGE:'synthetic-runtime-token'});
 expect(JSON.parse(result.stderr)).toEqual({phase:'ci-smoke-held',code:'CiSmokeActionFailed'});
});
