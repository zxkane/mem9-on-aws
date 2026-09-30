import {createHash} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';
import {readFile} from 'node:fs/promises';
import {dirname,resolve} from 'node:path';

export const RUNTIME_LOCK_CLASS=197568;
export const runtimePreviewStage=stage=>/^pr-[1-9][0-9]*$/.test(stage||'');
export const runtimeStage=stage=>stage==='prod'||runtimePreviewStage(stage);
export function runtimeRoleName(stage){
  if(!runtimeStage(stage))throw Error('InvalidRuntimeStage');
  return 'mem9_runtime_'+createHash('sha256').update(stage).digest('hex').slice(0,12);
}
export function runtimeLockKey(stage){
  runtimeRoleName(stage);
  return createHash('sha256').update(stage).digest().readInt32BE(0);
}
export function parseRuntimeConfig(env){
  try{
    const credentials=JSON.parse(env.MEM9_RUNTIME_DB_SECRET);
    if(credentials.username!==runtimeRoleName(env.MEM9_STAGE)||!/^[A-Za-z0-9]{32,128}$/.test(credentials.password)||
      typeof credentials.salt!=='string'||credentials.salt.length<16||!env.MEM9_DB_HOST||!/^\d+$/.test(env.MEM9_DB_PORT||'')||
      !/^[a-zA-Z_][a-zA-Z0-9_]{0,62}$/.test(env.MEM9_DB_NAME||'')||!/^[a-f0-9]{32}$/.test(env.MEM9_TENANT_ID||''))throw Error();
    return {stage:env.MEM9_STAGE,host:env.MEM9_DB_HOST,port:Number(env.MEM9_DB_PORT),database:env.MEM9_DB_NAME,
      tenant:env.MEM9_TENANT_ID,credentials};
  }catch{throw Error('InvalidRuntimeConfiguration');}
}
export async function runtimeSchemaDigest(root){
  const script=fileURLToPath(new URL('../../docker/bootstrap/schema-digest.sh',import.meta.url));
  const result=await promisify(execFile)('sh',[script,root],{timeout:10000,maxBuffer:4096});
  const hash=result.stdout.trim();if(!/^[a-f0-9]{64}$/.test(hash))throw Error('InvalidSchemaDigest');return hash;
}
export async function applyBootstrapSchema(db,file){
  const text=await readFile(file,'utf8'),parts=text.split(/^\\ir\s+([a-zA-Z0-9_./-]+)\s*$/m);
  for(let i=0;i<parts.length;i++){
    if(i%2)await applyBootstrapSchema(db,resolve(dirname(file),parts[i]));
    else if(parts[i].trim())await db.query(parts[i]);
  }
}
