// Synthetic source-only records for payment-order regression tests.
// No native funding, completed build or production authority is created.
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {nonrootDeploymentFixture} from './production-nonroot-provenance.fixture.mjs';
import {createControlSourceContext,controlSourceEntries,readControlSourceFile} from './lib/production-control-source.mjs';
import {inspectProductionControlCompositionRecipe} from './lib/production-control-composition-recipe.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {CONTROL_ZERO_FINDINGS_POLICY_HASH as policyHash,CONTROL_ZERO_FINDINGS_POLICY_SOURCE as policyPath} from './lib/production-nonroot-control-scan-policy.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const ACTION='.github/actions/control-composition/action.yml',ENTRY='.github/actions/control-composition/dist/index.mjs',TOOLCHAIN='.github/actions/control-composition/dist/toolchain.json',BUILDER='scripts/build-control-composition-action.mjs';
export async function sourceFixture(){
 const sourceEntry='.github/actions/control-composition/index.mjs',main='scripts/lib/production-control-composition-main.mjs',controller='scripts/lib/production-control-composition-controller.mjs';
 const job={name:'Build image transition control',steps:[{id:'bootstrap',name:'Build CONTROL image',uses:'./.github/actions/control-composition'}]};
 const files={
  [ACTION]:JSON.stringify({name:'Synthetic native action',description:'Complete test source',outputs:Object.fromEntries(['commitment','digest','image_tag'].map(k=>[k,{description:k}])),runs:{using:'node24',main:'dist/index.mjs'}}),
  [sourceEntry]:"import {main} from '../../../scripts/lib/production-control-composition-main.mjs'; main();\n",
  [main]:"import {run} from './production-control-composition-controller.mjs'; export function main(){run();}\n",
  [controller]:"export function run(){}\n",
  [BUILDER]:"export const syntheticBuilder=true;\n",[ENTRY]:"export const bundled=true;\n",
  'package-lock.json':JSON.stringify({lockfileVersion:3,packages:{'node_modules/rolldown':{version:'1.0.0',integrity:'sha512-synthetic'}}})
 };
 const prepPaths=[...Object.keys(files),TOOLCHAIN];
 files[TOOLCHAIN]=JSON.stringify({version:1,kind:'control-composition-ci-toolchain',nodeMajor:24,bundler:{name:'rolldown',version:'1.0.0',integrity:'sha512-synthetic',builderSourceHash:sha(files[BUILDER])},packageLockHash:sha(files['package-lock.json']),
  inputs:[sourceEntry,main,controller].map(path=>({path,sha256:sha(files[path]),bytesLength:Buffer.byteLength(files[path])})),output:{path:ENTRY,sha256:sha(files[ENTRY]),bytesLength:Buffer.byteLength(files[ENTRY])}});
 files['.github/workflows/infra-ci.yml']=JSON.stringify({jobs:{'build-image-transition-control':job}});
 files[policyPath]=await readFile(new URL('../'+policyPath,import.meta.url));
 const d=await nonrootDeploymentFixture({sourceOverrides:new Map(Object.entries(files))}),pin=async path=>(await readControlSourceFile(d.sourceContext,path)).file;
 const members=await Promise.all(prepPaths.map(pin));members.sort((a,b)=>a.path.localeCompare(b.path));
 const preparation={version:1,kind:'git-file-closure',tree:d.sourceContext.tree,files:members,closureHash:hash(members)};
 const recipe=inspectProductionControlCompositionRecipe({...d.contract.recipe,version:2,kind:'native-control-composition-recipe',preparation,
  invocation:{version:2,kind:'native-control-composition-invocation',builder:'mem9-native-control-composition/v1',actionPath:ACTION,actionSource:await pin(ACTION),entryPath:ENTRY,bundle:await pin(ENTRY),toolchain:await pin(TOOLCHAIN),runtime:'node24',format:'ustar',compression:'none',platform:'linux/arm64',tagRule:'mem9-actual-main-sha7',provenanceRule:'authenticated-workflow-run-attempt'},
  composition:{planHash:'a'.repeat(64),copyHash:'b'.repeat(64)}});
 const contract={...d.contract,version:2,recipe,artifactPolicyHash:policyHash,workflow:{...d.contract.workflow,jobSource:d.bytes(JSON.stringify(job))}};
 let reads=0;
 const context=createControlSourceContext({tree:d.sourceContext.tree,entries:controlSourceEntries(d.sourceContext)},async(oid,path)=>{reads++;return (await readControlSourceFile(d.sourceContext,path)).bytes;});
 // Keep the freshly generated schema internally bound. Its legacy raw
 // invocation is deliberately retained for the deployed-build frontier test.
 const build={...d.build,version:2,recipe,contractHash:hash(contract),resolvedLaunches:d.build.resolvedLaunches.map(row=>({...row,contractHash:hash(contract)}))};
 return {d,contract,build,context,job,reads:()=>reads,reset(){reads=0;},source:{repository:contract.repository,prNumber:contract.prNumber,candidateRevision:contract.candidate.revision,candidateTree:contract.candidate.tree,baseRevision:contract.candidate.baseRevision},
  options:()=>({...d.options(),expected:{...d.options().expected,contract,sourceContext:context}})};
}
