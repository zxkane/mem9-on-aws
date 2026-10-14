import {it,expect} from 'vitest';
import {mkdtemp,writeFile,rm,readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {graphFixture} from './production-image.fixture.mjs';
import {nonrootControlMetadataReads} from './lib/production-nonroot-control-reads.mjs';

async function fixture(use){
 const directory=await mkdtemp(join(tmpdir(),'nonroot-read-cli-'));
 try{
  const scope={account:'123456789012',region:'ap-northeast-1'},f=graphFixture(),root=f.roots[0],repositoryName='mem9-on-aws/preview/bootstrap';
  const image={images:[{registryId:scope.account,repositoryName,imageId:{imageDigest:root.root.digest},imageManifest:f.data.get(root.root.digest).toString()}],failures:[]};
  const route={...scope,image:`${scope.account}.dkr.ecr.${scope.region}.amazonaws.com/${repositoryName}@${root.root.digest}`,kmsKeyArn:`arn:aws:kms:${scope.region}:${scope.account}:key/synthetic-key`};
  const key={KeyMetadata:{Arn:route.kmsKeyArn,AWSAccountId:scope.account,Enabled:true,KeyState:'Enabled',KeyManager:'AWS'}};
  await writeFile(join(directory,'ecr.json'),JSON.stringify(image));await writeFile(join(directory,'kms.json'),JSON.stringify(key));
  await writeFile(join(directory,'aws'),`#!${process.execPath}\nconst fs=require('node:fs'),p=require('node:path'),d=__dirname,a=process.argv.slice(2);\nif(process.env.AWS_MAX_ATTEMPTS!=='1'||process.env.AWS_PROFILE||process.env.AWS_ENDPOINT_URL||process.env.AWS_CONFIG_FILE!=='/dev/null')process.exit(3);\nfs.appendFileSync(p.join(d,'calls.jsonl'),JSON.stringify(a)+'\\n');\nif(!['ecr','kms'].includes(a[0]))process.exit(4);process.stdout.write(fs.readFileSync(p.join(d,a[0]+'.json')));\n`,{mode:0o700});
  const calls=[],env={PATH:directory,AWS_ACCESS_KEY_ID:'synthetic-key',AWS_SECRET_ACCESS_KEY:'synthetic-secret',AWS_SESSION_TOKEN:'synthetic-token',AWS_PROFILE:'forbidden-profile',AWS_ENDPOINT_URL:'https://example.com'};
  await use({directory,scope,route,calls,env,image,key,reader:nonrootControlMetadataReads(scope,{env,calls})});
 }finally{await rm(directory,{recursive:true,force:true});}
}
it('executes only the fixed metadata reads with scoped args and one-attempt credentials',()=>fixture(async f=>{
 expect((await f.reader.artifact(f.route)).rootDigest).toBe(f.route.image.split('@')[1]);expect(await f.reader.key(f.route)).toBe(f.route.kmsKeyArn);
 const calls=(await readFile(join(f.directory,'calls.jsonl'),'utf8')).trim().split('\n').map(JSON.parse);
 expect(calls[0].slice(0,2)).toEqual(['ecr','batch-get-image']);expect(calls[1].slice(0,2)).toEqual(['kms','describe-key']);
 expect(calls.every(a=>a.includes(f.scope.region)&&a.includes('--no-cli-pager'))).toBe(true);
 expect(f.calls.every(c=>c.status==='completed'&&c.serializedResponseBytes>0)).toBe(true);
}));
it('rejects foreign scope before dispatch and changed returned metadata afterward',()=>fixture(async f=>{
 await expect(f.reader.artifact({...f.route,account:'0'.repeat(12)})).rejects.toThrow();expect(f.calls).toEqual([]);
 f.key.KeyMetadata.AWSAccountId='0'.repeat(12);await writeFile(join(f.directory,'kms.json'),JSON.stringify(f.key));await expect(f.reader.key(f.route)).rejects.toThrow('NonrootControlKeyMismatch');
 f.image.images[0].imageManifest='{}';await writeFile(join(f.directory,'ecr.json'),JSON.stringify(f.image));await expect(f.reader.artifact(f.route)).rejects.toThrow();
}));
