import {afterEach,it,expect} from 'vitest';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {collectPreviewEvidence,uploadPreviewEvidence} from './lib/service-nonroot-preview-evidence.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const directories=[];afterEach(async()=>{await Promise.all(directories.splice(0).map(d=>rm(d,{recursive:true,force:true})));});
async function fixture({complete=true,cleanup=true,outcome='PASS'}={}){
 const dir=await mkdtemp(join(tmpdir(),'nonroot-evidence-'));directories.push(dir);
 const files={'register-intent.json':{targetHash:'a'.repeat(64)},'report.local.json':{outcome,cleanup:{verified:cleanup,complete:cleanup,remainingCandidateTasks:[],failures:[]}}},rows=[];
 for(const [name,value]of Object.entries(files)){const b=JSON.stringify(value)+'\n';await writeFile(join(dir,name),b,{mode:0o600});rows.push({name,sha256:sha(b),bytes:Buffer.byteLength(b)});}
 return {dir,report:{...files['report.local.json'],evidence:join(dir,'report.local.json'),evidenceHash:rows[1].sha256,...(complete?{evidenceFiles:rows}:{})}};
}
it('collects every producer record and gates cleanup on the actual report bytes',async()=>{
 const f=await fixture();const bundle=await collectPreviewEvidence(f.report);expect(bundle.files.map(f=>f.name)).toEqual(['register-intent.json','report.local.json']);expect(bundle.cleanupAuthorized).toBe(true);
});
it('rejects modified or truncated report and journal bytes',async()=>{
 for(const name of ['register-intent.json','report.local.json']){const f=await fixture();await writeFile(join(f.dir,name),'{}');await expect(collectPreviewEvidence(f.report)).rejects.toThrow('ProducerEvidenceChanged');}
});
it('never permits cleanup from a fallback summary or unknown mutation',async()=>{
 for(const options of [{complete:false},{cleanup:false}]){const f=await fixture(options);expect((await collectPreviewEvidence(f.report)).cleanupAuthorized).toBe(false);}
});
it('permits cleanup with complete evidence after failed verification, without changing failure outcome',async()=>{
 const f=await fixture({outcome:'HELD'}),bundle=await collectPreviewEvidence(f.report);expect(bundle.cleanupAuthorized).toBe(true);expect(bundle.outcome).toBe('HELD');
});
it('returns cleanup permission only after all objects and manifest pass checksum readback',async()=>{
 const f=await fixture(),bundle=await collectPreviewEvidence(f.report),stored=new Map();let calls=0;
 const args={bundle,bucket:'fixture-audit',account:'123456789012',prefix:'runtime-service-hardening/previews/pr-9/'+'a'.repeat(40)+'/11-1/'};
 const client={send:async c=>{calls++;const i=c.input;if(c.constructor.name==='PutObjectCommand'){stored.set(i.Key,i);return {};}const old=stored.get(i.Key);return {ContentLength:old.Body.length,ChecksumSHA256:old.ChecksumSHA256};}};
 const result=await uploadPreviewEvidence({...args,client});expect(calls).toBe(6);expect(result.cleanupAuthorized).toBe(true);
 let step=0;await expect(uploadPreviewEvidence({...args,client:{send:async c=>{if(++step===4)throw Error('partial upload');return client.send(c);}}})).rejects.toThrow('partial upload');
 await expect(uploadPreviewEvidence({...args,client:{send:async c=>c.constructor.name==='PutObjectCommand'?{}:{ContentLength:0,ChecksumSHA256:'wrong'}}})).rejects.toThrow('EvidenceUploadUnverified');
});
