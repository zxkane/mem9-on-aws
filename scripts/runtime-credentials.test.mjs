import {describe,it,expect} from 'vitest';
import {runtimeRoleName,parseRuntimeConfig,runtimeSchemaDigest} from './lib/runtime-credentials.mjs';
import {mkdtemp,writeFile,mkdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

describe('preview runtime credential contract',()=>{
  it('derives one stable bounded role and rejects non-preview input',()=>{
    expect(runtimeRoleName('pr-7')).toMatch(/^mem9_runtime_[a-f0-9]{12}$/);
    expect(runtimeRoleName('pr-7')).toBe(runtimeRoleName('pr-7'));
    expect(runtimeRoleName('pr-7')).not.toBe(runtimeRoleName('pr-8'));
    for(const stage of ['prod','dev','pr-0','pr-7;sql'])expect(()=>runtimeRoleName(stage)).toThrow();
  });
  it('does not accept an owner credential or malformed secret as a runtime identity',()=>{
    const username=runtimeRoleName('pr-7');
    const env={MEM9_STAGE:'pr-7',MEM9_DB_HOST:'db.example.com',MEM9_DB_PORT:'5432',MEM9_DB_NAME:'mem9',MEM9_TENANT_ID:'a'.repeat(32),
      MEM9_RUNTIME_DB_SECRET:JSON.stringify({username,password:'SyntheticPassword'.repeat(3),salt:'SyntheticSaltMarker'})};
    expect(parseRuntimeConfig(env).credentials.username).toBe(username);
    expect(()=>parseRuntimeConfig({...env,MEM9_RUNTIME_DB_SECRET:JSON.stringify({username:'postgres',password:'secret'})})).toThrow();
    expect(()=>parseRuntimeConfig({...env,MEM9_RUNTIME_DB_SECRET:'SENSITIVE_INVALID_JSON'})).toThrow('InvalidRuntimeConfiguration');
  });
  it('hashes schema, ordered migrations and the separate runtime contract',async()=>{
    const dir=await mkdtemp(join(tmpdir(),'mem9-runtime-contract-'));
    try{
      await mkdir(join(dir,'migrations'));await writeFile(join(dir,'schema.sql'),'SELECT 1;');
      await writeFile(join(dir,'migrations/001.sql'),'SELECT 2;');await writeFile(join(dir,'runtime-contract.sql'),'SELECT 3;');
      const first=await runtimeSchemaDigest(dir);expect(first).toMatch(/^[a-f0-9]{64}$/);
      expect(await runtimeSchemaDigest(dir)).toBe(first);
      await writeFile(join(dir,'runtime-contract.sql'),'SELECT 4;');expect(await runtimeSchemaDigest(dir)).not.toBe(first);
    }finally{await rm(dir,{recursive:true,force:true});}
  });
});
