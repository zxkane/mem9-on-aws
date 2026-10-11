import {test,expect} from 'vitest';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {ciSmokeHost,captureSmokeTree} from './lib/ci-smoke-host.mjs';
import {readControlSourceFile} from './lib/production-control-source.mjs';
import {CI_SMOKE_ARCHIVE_LIMITS,encodeCiSmokeEnvelope,decodeCiSmokeEnvelope} from './lib/ci-smoke-private-archive.mjs';
import {ciSmokeEvidenceFixture} from './ci-smoke-evidence.fixture.mjs';
import {parse} from '@babel/parser';
import {compactControlCompositionCode} from './build-control-composition-action.mjs';
import {verifyCiSmokeCompositionToolchain} from './lib/ci-smoke-isolation.mjs';
import {previewProgramSourceFixture} from './production-nonroot-preview-provider.fixture.mjs';

const root=fileURLToPath(new URL('../',import.meta.url)),bundlePath='.github/actions/control-composition/dist/index.mjs';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');

test('compaction retains exact license, preserve and ordinary copyright notices without interpreting string data',async()=>{
 const notices=['/*! Example license */','/** @license MIT\n\t* Example authors\n\t*/',
  '// Copyright 2026 Example authors','/** @copyright Example contributors */','// @preserve Example notice'];
 const source=notices.join('\n')+'\n// ordinary removable comment\n'+
  'export const text="/* Copyright inside a string */";\n'+
  'export const raw=String.raw`\\n`;\nexport function namedFunction(){return [text,raw,true];}\n';
 const code=compactControlCompositionCode(source),comments=parse(code,{sourceType:'module'}).comments.map(c=>code.slice(c.start,c.end));
 expect(comments).toEqual(notices);
 const loaded=await import('data:text/javascript;base64,'+Buffer.from(code).toString('base64'));
 expect(loaded.namedFunction.name).toBe('namedFunction');
 expect(loaded.namedFunction()).toEqual(['/* Copyright inside a string */','\\n',true]);
});

test('committed action bundle is reproducible and fits the original complete source object bound',async()=>{
 const output=execFileSync(process.execPath,['scripts/build-control-composition-action.mjs','--check'],{cwd:root,encoding:'utf8',timeout:30000,maxBuffer:1048576});
 const result=JSON.parse(output),bundle=await readFile(join(root,bundlePath));
 expect(result.bundleHash).toBe(sha(bundle));expect(result.bundleBytes).toBe(bundle.length);
 expect(CI_SMOKE_ARCHIVE_LIMITS.objectBytes).toBe(8388608);
 expect(bundle.length).toBeLessThanOrEqual(CI_SMOKE_ARCHIVE_LIMITS.objectBytes);
 const manifest=JSON.parse(await readFile(join(root,'.github/actions/control-composition/dist/toolchain.json'))),lock=JSON.parse(await readFile(join(root,'package-lock.json')));
 for(const input of manifest.inputs.filter(row=>row.path.startsWith('node_modules/'))){
  const key=Object.keys(lock.packages).filter(key=>key.startsWith('node_modules/')&&input.path.startsWith(key+'/')).sort((a,b)=>b.length-a.length)[0];
  expect(input.packagePin).toEqual({name:key.split('node_modules/').at(-1),version:lock.packages[key].version,integrity:lock.packages[key].integrity});
 }
},35000);

test('constant dynamic imports remain literal and executable after compaction',async()=>{
 const code=compactControlCompositionCode('export const load=()=>import("node:path");'),ast=parse(code,{sourceType:'module',createImportExpressions:true});
 const expression=ast.program.body[0].declaration.declarations[0].init.body;
 expect(expression.type).toBe('ImportExpression');expect(expression.source.type).toBe('StringLiteral');
 const loaded=await import('data:text/javascript;base64,'+Buffer.from(code).toString('base64'));
 expect((await loaded.load()).basename('/example/file')).toBe('file');
});

test('the actual emitted manifest passes the original SOURCE toolchain consumer',async()=>{
 const {context}=previewProgramSourceFixture();
 const assets={bundle:await readControlSourceFile(context,bundlePath),
  toolchain:await readControlSourceFile(context,'.github/actions/control-composition/dist/toolchain.json')};
 const result=await verifyCiSmokeCompositionToolchain(context,assets);
 expect(result.output.sha256).toBe(sha(assets.bundle.bytes));
 expect(result.inputs.some(row=>row.path.includes('/node_modules/'))).toBe(true);
 expect(result.inputs.some(row=>row.path==='sst.config.ts')).toBe(true);
},15000);

test('complete actual bundle survives the real bounded Git reader and smoke archive codec',async()=>{
 const bundle=await readFile(join(root,bundlePath)),directory=await mkdtemp(join(tmpdir(),'composition-bundle-source-'));
 try{
  const git=(args,input)=>execFileSync('git',args,{cwd:directory,input,encoding:'utf8',timeout:10000,maxBuffer:8388608});
  git(['init','--quiet']);const oid=git(['hash-object','-w','--stdin'],bundle).trim();
  git(['update-index','--add','--cacheinfo','100644,'+oid+','+bundlePath]);const tree=git(['write-tree']).trim();
  const revision=git(['-c','user.name=Fixture','-c','user.email=user@example.com','commit-tree',tree,'-m','Synthetic bundle source boundary']).trim();
  const env={GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:'example/control-plane',GITHUB_SHA:revision,GITHUB_RUN_ID:'77',GITHUB_RUN_ATTEMPT:'1'};
  const host={...ciSmokeHost(env,directory),api(){throw Error('UnexpectedSourceNetwork');}},objects=new Map();
  const captured=await captureSmokeTree(host,{revision,tree},{bytes(raw){const ref={sha256:sha(raw),bytesLength:raw.length};objects.set(ref.sha256,Buffer.from(raw));return ref;},get(hash){return objects.get(hash);}});
  expect((await readControlSourceFile(captured.context,bundlePath)).bytes).toEqual(bundle);

  // Synthetic surrounding evidence exercises transport only. The embedded
  // bundle is the complete actual artifact, not a smaller substitute.
  const f=ciSmokeEvidenceFixture(),bundleRef=f.bytes(bundle);
  const records={result:f.json(f.result),source:f.json({identity:f.expected.identity,sourceBundle:bundleRef}),
   isolation:f.json({isolationHash:f.expected.isolationHash}),observations:f.json(f.expected),
   commandBindings:f.json({invocationId:f.expected.invocationId}),commandCatalog:f.json(f.expected.commandCatalog)};
  const selected=new Map();
  const visit=value=>{if(!value||typeof value!=='object')return;
   if(value.bytesHash&&value.canonicalHash){if(selected.has(value.bytesHash))return;const bytes=f.objects.get(value.bytesHash);selected.set(value.bytesHash,bytes);visit(JSON.parse(bytes));return;}
   if(value.sha256&&Number.isInteger(value.bytesLength)){selected.set(value.sha256,f.objects.get(value.sha256));return;}
   if(value.gitMode&&value.sha256){selected.set(value.sha256,f.objects.get(value.sha256));return;}
   Object.values(value).forEach(visit);
  };visit(records);
  const encoded=encodeCiSmokeEnvelope({records,objects:[...selected].map(([sha256,bytes])=>({sha256,bytes}))});
  const decoded=decodeCiSmokeEnvelope(encoded.bytes,encoded.commitment);
  expect(decoded.readBytes(bundleRef)).toEqual(bundle);
 }finally{await rm(directory,{recursive:true,force:true});}
},30000);
