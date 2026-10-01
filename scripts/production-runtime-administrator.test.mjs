import {describe,it,expect} from 'vitest';
import {restoreMissingAdministrator,armAdministratorLoss,deletePreviewAdministrator,administratorLossDeadlines} from './lib/production-runtime-administrator.mjs';
import {schemaAdministratorRole} from './lib/production-runtime-config.mjs';
const restore=(clients,meta)=>restoreMissingAdministrator(clients,meta,{sleep:async()=>{}});

const meta={stage:'pr-7',region:'ap-northeast-1',account:'123456789012'};
const prefix=`arn:aws:ssm:${meta.region}:${meta.account}:parameter/mem9-on-aws/${meta.stage}/runtime/`;
Object.assign(meta,{administratorCredential:prefix+'schema-administrator-credential',administratorBackup:prefix+'schema-administrator-backup'});
const credential={username:schemaAdministratorRole(meta.stage),password:'a'.repeat(48),salt:'s'.repeat(32)};
function fixture({exists=false,backup=credential,race}={}){
  const calls=[];let primary=exists?JSON.stringify(credential):undefined;
  return {calls,clients:{ssm:{send:async command=>{
    calls.push({name:command.constructor.name,input:command.input});
    if(command.constructor.name==='GetParametersCommand'){
      const arn=command.input.Names[0],value=arn===meta.administratorBackup?(backup?JSON.stringify(backup):undefined):primary;
      return value?{Parameters:[{ARN:arn,Type:'SecureString',Value:value}]}:{InvalidParameters:[arn]};
    }
    if(command.constructor.name==='PutParameterCommand'){
      if(race){primary=JSON.stringify(race);throw Object.assign(Error('race'),{name:'ParameterAlreadyExists'});}
      primary=command.input.Value;return {};
    }
    throw Error('UnexpectedCommand');
  }}}};
}
describe('administrator backup restoration',()=>{
  it('reserves time for parameter restoration and fresh-login verification before loss admission',()=>{
    expect(administratorLossDeadlines(2700000,0)).toEqual({lossDeadline:1500000,restoreDeadline:1800000});
    expect(()=>administratorLossDeadlines(2700000,1440000)).toThrow('AdministratorLossDeadline');
  });
  it('does not read the backup or mutate an existing primary',async()=>{
    const f=fixture({exists:true});expect(await restore(f.clients,meta)).toEqual({restored:false});
    expect(f.calls).toHaveLength(1);expect(f.calls[0].input.WithDecryption).toBe(false);
  });
  it('restores the same backup through an exact reference and create-only write',async()=>{
    const f=fixture();expect(await restore(f.clients,meta)).toEqual({restored:true});
    expect(f.calls.find(c=>c.name==='PutParameterCommand').input).toMatchObject({Overwrite:false,Type:'SecureString',Value:JSON.stringify(credential)});
  });
  it.each([null,{...credential,username:'legacy-owner'},{...credential,password:'short'},{...credential,extra:'invalid'}])('refuses unusable backup %o',async backup=>{
    const f=fixture({backup});await expect(restore(f.clients,meta)).rejects.toThrow(/AdministratorBackup/);
    expect(f.calls.some(c=>c.name==='PutParameterCommand')).toBe(false);
  });
  it('does not overwrite a racing primary and requires matching readback',async()=>{
    const f=fixture({race:{...credential,password:'b'.repeat(48)}});
    await expect(restore(f.clients,meta)).rejects.toThrow('AdministratorRecoveryReadbackMismatch');
    expect(f.calls.filter(c=>c.name==='PutParameterCommand')).toHaveLength(1);
    expect(await restore(fixture({race:credential}).clients,meta)).toEqual({restored:true});
  });
  it('rejects a cross-stage backup before contacting SSM',async()=>{
    const f=fixture();await expect(restore(f.clients,{...meta,administratorBackup:meta.administratorBackup.replace('/pr-7/','/prod/')})).rejects.toThrow('InvalidAdministratorRecoveryTarget');
    expect(f.calls).toEqual([]);
  });
  it('waits the required recreation interval and rejects insufficient recovery time',async()=>{
    const f=fixture(),waits=[];
    await restoreMissingAdministrator(f.clients,meta,{sleep:async ms=>{waits.push(ms);}});
    expect(waits).toEqual([30000]);
    const g=fixture();await expect(restoreMissingAdministrator(g.clients,meta,{now:()=>1000,deadlineMs:31000,sleep:async()=>{throw Error('UnexpectedWait');}})).rejects.toThrow('AdministratorRecoveryDeadline');
    expect(g.calls.some(c=>c.name==='PutParameterCommand')).toBe(false);
  });
  it('persists a recoverable intent before deletion and restores using only durable backup state',async()=>{
    const store=new Map([[meta.administratorCredential,JSON.stringify(credential)],[meta.administratorBackup,JSON.stringify(credential)]]);
    const key=name=>name.startsWith('arn:')?name:`arn:aws:ssm:${meta.region}:${meta.account}:parameter${name}`;
    const intentKey=prefix+'administrator-recovery-intent',calls=[];
    const clients={ssm:{send:async command=>{
      const name=command.constructor.name,input=command.input;calls.push(name);
      if(name==='GetParametersCommand')return {
        Parameters:input.Names.filter(n=>store.has(key(n))).map(n=>({ARN:key(n),Type:'SecureString',Value:store.get(key(n))})),
        InvalidParameters:input.Names.filter(n=>!store.has(key(n))),
      };
      if(name==='PutParameterCommand'){expect(input.Overwrite).toBe(false);store.set(key(input.Name),input.Value);return {};}
      if(name==='DeleteParameterCommand'){expect(store.has(intentKey)).toBe(true);store.delete(key(input.Name));return {};}
      throw Error('UnexpectedCommand');
    }}};
    const plan={nonce:'a'.repeat(32),sourceRunId:'123'};
    const intent=await armAdministratorLoss(clients,meta,plan);
    await deletePreviewAdministrator(clients,meta,plan,intent);
    expect(store.has(meta.administratorCredential)).toBe(false);
    expect(JSON.parse(store.get(intentKey))).toMatchObject({nonce:plan.nonce,primary:meta.administratorCredential,backup:meta.administratorBackup});
    await restoreMissingAdministrator(clients,meta,{sleep:async()=>{}});
    expect(store.get(meta.administratorCredential)).toBe(store.get(meta.administratorBackup));
    expect(calls.indexOf('PutParameterCommand')).toBeLessThan(calls.indexOf('DeleteParameterCommand'));
    expect(store.has(intentKey)).toBe(true); // retained until fresh DB verification
  });
});
