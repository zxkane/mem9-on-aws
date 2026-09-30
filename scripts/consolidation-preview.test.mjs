import {describe,it,expect,vi} from 'vitest';
import {previewGeneration,previewConfiguration,previewUuid} from './lib/consolidation-preview-config.mjs';
import {assertSafeCredentialLogging,assertStructuralDatabaseLog,scramVerifier,secureCredentialDdlLogging} from './lib/consolidation-preview-secrets.mjs';
describe('synthetic consolidation configuration and secret guards',()=>{
  const env={MEM9_DEPLOY_COMMIT:'a'.repeat(40),GITHUB_RUN_ID:'42',GITHUB_RUN_ATTEMPT:'1'};
  it('has stable credentials and fresh namespaces for a redeployed attempt',()=>{
    const a=previewConfiguration('pr-7',previewGeneration('pr-7',env),'synthetic-secret');
    const b=previewConfiguration('pr-7',previewGeneration('pr-7',{...env,GITHUB_RUN_ATTEMPT:'2'}),'synthetic-secret');
    expect(a.database).toBe(b.database);expect(a.usernames).toEqual(b.usernames);expect(a.tenantId).toBe(b.tenantId);
    expect(a.namespaces.every(n=>!b.namespaces.includes(n))).toBe(true);
    expect(previewUuid(a.generation,'x')).toMatch(/^[0-9a-f-]{36}$/);
    expect(()=>previewGeneration('prod',env)).toThrow();expect(()=>previewGeneration('pr-7',{})).toThrow();
  });
  it('uses PostgreSQL SCRAM without including the raw password',()=>{
    const password='SyntheticSecretMarker'.repeat(2);
    const verifier=scramVerifier(password,'SyntheticSaltMarker');
    expect(verifier).toMatch(/^SCRAM-SHA-256\$4096:/);expect(verifier).not.toContain(password);
    expect(scramVerifier(password,'SyntheticSaltMarker')).toBe(verifier);
  });
  it('fails on unsafe effective logging without changing server settings',()=>{
    const settings={log_statement:'none',log_min_duration_statement:'-1',log_min_duration_sample:'-1',log_transaction_sample_rate:'0',log_parameter_max_length_on_error:'0'};
    const rows=s=>Object.entries(s).map(([name,setting])=>({name,setting}));
    expect(()=>assertSafeCredentialLogging(rows(settings))).not.toThrow();
    for(const [name,setting] of Object.entries({log_statement:'all',log_min_duration_statement:'0',log_parameter_max_length_on_error:'-1','pgaudit.log':'ddl'})){
      expect(()=>assertSafeCredentialLogging(rows({...settings,[name]:setting}))).toThrow('UnsafeCredentialLogging');
    }
  });
  it('detects structural credential leaks without echoing the offending text',()=>{
    for(const text of ['ALTER ROLE user PASSWORD SECRET_MARKER','DETAIL: parameters: $1 = SECRET_MARKER','SCRAM-SHA-256$4096:SECRET_MARKER']){
      expect(()=>assertStructuralDatabaseLog(text)).toThrow('UnsafeDatabaseLogStructure');
      try{assertStructuralDatabaseLog(text);}catch(error){expect(error.message).not.toContain('SECRET_MARKER');}
    }
    expect(()=>assertStructuralDatabaseLog('LOG: checkpoint complete')).not.toThrow();
  });
  it('fails before credential DDL when safe server error settings cannot be applied',async()=>{
    const query=vi.fn(async()=>{throw Object.assign(Error('permission denied'),{code:'42501'});});
    await expect(secureCredentialDdlLogging({query})).rejects.toMatchObject({code:'42501'});
    expect(query).toHaveBeenCalledOnce();
    expect(query.mock.calls[0][0]).not.toContain('PASSWORD');
  });
  it.each(['csvlog','jsonlog','stderr,csvlog'])('rejects unsupported credential log destination %s',async destination=>{
    const settings={log_statement:'none',log_min_duration_statement:'-1',log_min_duration_sample:'-1',log_transaction_sample_rate:'0',log_parameter_max_length_on_error:'0'};
    const query=vi.fn(async sql=>sql.includes('pg_settings')?
      {rows:Object.entries(settings).map(([name,setting])=>({name,setting}))}:
      {rows:[{safe:destination==='stderr'}]});
    await expect(secureCredentialDdlLogging({query})).rejects.toThrow('UnsafeCredentialLogging');
    expect(query.mock.calls.some(([sql])=>sql.includes("current_setting('log_destination')='stderr'"))).toBe(true);
    expect(query.mock.calls.every(([sql])=>!sql.includes('PASSWORD'))).toBe(true);
  });
});
