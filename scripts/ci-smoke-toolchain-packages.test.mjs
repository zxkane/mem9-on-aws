import {test,expect} from 'vitest';
import {sourceContext,sha} from './control-composition-native/fixture.mjs';
import {readControlSourceFile} from './lib/production-control-source.mjs';
import {verifyCiSmokeCompositionToolchain} from './lib/ci-smoke-isolation.mjs';

const entry='.github/actions/control-composition/index.mjs',bundlePath='.github/actions/control-composition/dist/index.mjs',
 toolchainPath='.github/actions/control-composition/dist/toolchain.json',builderPath='scripts/build-control-composition-action.mjs';
const nested='node_modules/@parent/package/node_modules/@nested/child';
async function fixture(change=()=>{}){
 const bundle=Buffer.from('export {};'),builder=Buffer.from('// synthetic builder'),entryBytes=Buffer.from('// synthetic entry');
 const lock={lockfileVersion:3,packages:{
  'node_modules/rolldown':{version:'1.0.0',integrity:'sha512-synthetic-bundler'},
  'node_modules/@parent/package':{version:'1.0.0',integrity:'sha512-synthetic-parent'},
  'node_modules/@nested/child':{version:'9.0.0',integrity:'sha512-synthetic-top-level'},
  [nested]:{version:'2.0.0',integrity:'sha512-synthetic-nested'},
 }};
 const manifest={version:1,kind:'control-composition-ci-toolchain',nodeMajor:24,
  bundler:{name:'rolldown',...lock.packages['node_modules/rolldown'],builderSourceHash:sha(builder)},
  packageLockHash:sha(JSON.stringify(lock)),
  inputs:[{path:entry,sha256:sha(entryBytes),bytesLength:entryBytes.length},
   {path:nested+'/index.js',sha256:sha('synthetic dependency'),bytesLength:20,
    packagePin:{name:'@nested/child',...lock.packages[nested]}}],
  output:{path:bundlePath,sha256:sha(bundle),bytesLength:bundle.length}};
 change(manifest,lock);manifest.packageLockHash=sha(JSON.stringify(lock));
 const {context}=sourceContext({[entry]:entryBytes,[bundlePath]:bundle,[builderPath]:builder,
  'package-lock.json':JSON.stringify(lock),[toolchainPath]:JSON.stringify(manifest)});
 const assets={bundle:await readControlSourceFile(context,bundlePath),toolchain:await readControlSourceFile(context,toolchainPath)};
 return {context,assets,manifest};
}
test('nested package pins select the exact deepest lock entry despite a different top-level version',async()=>{
 const f=await fixture();expect(await verifyCiSmokeCompositionToolchain(f.context,f.assets)).toEqual(f.manifest);
});
test.each([
 ['top-level version',m=>{m.inputs[1].packagePin.version='9.0.0';}],
 ['changed integrity',m=>{m.inputs[1].packagePin.integrity='sha512-changed';}],
 ['parent attribution',(m,l)=>{m.inputs[1].packagePin={name:'@parent/package',...l.packages['node_modules/@parent/package']};}],
 ['unlocked nested package',(m,l)=>{m.inputs[1].path='node_modules/@parent/package/node_modules/@missing/child/index.js';m.inputs[1].packagePin={name:'@parent/package',...l.packages['node_modules/@parent/package']};}],
 ['removed nested lock',(m,l)=>{delete l.packages[nested];}],
])('rejects %s without falling back to a parent or unrelated package',async(_name,change)=>{
 const f=await fixture(change);await expect(verifyCiSmokeCompositionToolchain(f.context,f.assets)).rejects.toThrow('CiSmokeCompositionToolchainPackage');
});
