import {it,expect} from 'vitest';
import {createHash} from 'node:crypto';
import {verifyArchivedCiSmoke} from './lib/ci-smoke-isolation.mjs';
import {createControlSourceContext,readControlSourceFile} from './lib/production-control-source.mjs';
import {describeDataBuildInputs} from './lib/production-data-build-inputs.mjs';
import {validateCiSmokeEvidence} from './lib/ci-smoke-evidence.mjs';
import {ciSmokeEvidenceFixture} from './ci-smoke-evidence.fixture.mjs';

function lifetime(){let ended=false;return {end(){ended=true;},assertCurrent(){if(ended)throw Error('OriginalOwnerEnded');}};}
const jsonRef={bytesHash:'a'.repeat(64),canonicalHash:'b'.repeat(64),bytesLength:1};
const material={version:1,kind:'ci-smoke-source-material',origin:jsonRef,candidate:jsonRef,baseline:jsonRef,provenance:jsonRef,expected:jsonRef};

it('checks the original owner before decoding an awaited CI source body',async()=>{
 const owner=lifetime();
 await expect(verifyArchivedCiSmoke({}, {},{material,assertCurrent:owner.assertCurrent,resolveJson:async()=>{owner.end();return Uint8Array.of(255);},readBytes:async()=>Buffer.alloc(0)})).rejects.toThrow('OriginalOwnerEnded');
});
it('checks the original owner before hashing an awaited Git blob',async()=>{
 const owner=lifetime(),raw=Buffer.from('export const example = true;\n'),oid=createHash('sha1').update('blob '+raw.length+'\0').update(raw).digest('hex');
 const treeBytes=Buffer.concat([Buffer.from('100644 example.mjs\0'),Buffer.from(oid,'hex')]),tree=createHash('sha1').update('tree '+treeBytes.length+'\0').update(treeBytes).digest('hex');
 const context=createControlSourceContext({tree,entries:[{path:'example.mjs',mode:'100644',type:'blob',oid}]},async()=>{owner.end();return raw;},{assertCurrent:owner.assertCurrent});
 await expect(readControlSourceFile(context,'example.mjs')).rejects.toThrow('OriginalOwnerEnded');
});
it('checks the original owner before parsing an awaited data recipe',async()=>{
 const owner=lifetime();
 await expect(describeDataBuildInputs([{path:'.github/workflows/infra-ci.yml',mode:'100644',type:'blob',oid:'a'.repeat(40)}],async()=>{owner.end();return Buffer.from("'");},{assertCurrent:owner.assertCurrent})).rejects.toThrow('OriginalOwnerEnded');
});
it('checks the original owner before validating an awaited evidence body',async()=>{
 const f=ciSmokeEvidenceFixture(),options=f.options(),owner=lifetime();
 await expect(validateCiSmokeEvidence(f.result,{...options,assertCurrent:owner.assertCurrent,readJson:async ref=>{const raw=await options.readJson(ref);owner.end();return raw;}})).rejects.toThrow('OriginalOwnerEnded');
});
it('requires a synchronous guard and never treats its return value as success',async()=>{
 for(const assertCurrent of [()=>true,()=>Promise.resolve(),false])await expect(verifyArchivedCiSmoke({}, {},{material,assertCurrent})).rejects.toThrow('CiSmokeSynchronousGuard');
});
