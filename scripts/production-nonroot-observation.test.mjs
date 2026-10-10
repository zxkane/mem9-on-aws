import {it,expect} from 'vitest';
import {nonrootDeploymentFixture} from './production-nonroot-provenance.fixture.mjs';
import {collectNonrootControlRuntime,verifyNonrootControlRuntimeObservation} from './lib/production-nonroot-observation.mjs';
import {createRequire} from 'node:module';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {randomUUID} from 'node:crypto';
import {mkdir,writeFile,unlink,rmdir,stat} from 'node:fs/promises';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';

it('does not adopt JSON runtime observations or serialized graph handles',async()=>{
 const f=await nonrootDeploymentFixture();
 expect(()=>verifyNonrootControlRuntimeObservation({},f.build,f.options())).toThrow('NonrootRuntimeObservationRequired');
 const options=f.options();options.controlVerification.graph=structuredClone(options.controlVerification.graph);
 await expect(collectNonrootControlRuntime(f.build,options)).rejects.toThrow();
});

it('loads bundled infrastructure proof code without a colocated host Docker probe',async()=>{
 const root=fileURLToPath(new URL('..',import.meta.url)),platform=join(root,'.sst/platform');
 const require=createRequire(import.meta.url),testRequire=createRequire(require.resolve('vitest/package.json'));
 const bundlerRequire=createRequire(testRequire.resolve('vite/package.json'));
 const {rolldown}=await import(pathToFileURL(bundlerRequire.resolve('rolldown')).href);
 const created=[];
 for(const directory of [join(root,'.sst'),platform])try{await stat(directory);}catch(error){if(error.code!=='ENOENT')throw error;await mkdir(directory);created.push(directory);}
 const file=join(platform,'nonroot-import-test-'+randomUUID()+'.mjs');let bundle;
 try{
  bundle=await rolldown({input:join(root,'scripts/lib/production-nonroot-proof.mjs'),platform:'node',treeshake:false,
   external:id=>!id.startsWith('.')&&!id.startsWith('/')});
  const generated=await bundle.generate({format:'es',codeSplitting:false});
  expect(generated.output).toHaveLength(1);expect(generated.output[0].type).toBe('chunk');
  await writeFile(file,generated.output[0].code,{flag:'wx',mode:0o600});
  const result=spawnSync(process.execPath,['--input-type=module','--eval',`await import(${JSON.stringify(pathToFileURL(file).href)})`],{cwd:root,env:{PATH:process.env.PATH},encoding:'utf8',timeout:30000,maxBuffer:1048576});
  expect(result.status,result.stderr).toBe(0);
 }finally{
  await bundle?.close();await unlink(file).catch(error=>{if(error.code!=='ENOENT')throw error;});
  for(const directory of created.reverse())await rmdir(directory).catch(error=>{if(error.code!=='ENOTEMPTY')throw error;});
 }
},60000);
