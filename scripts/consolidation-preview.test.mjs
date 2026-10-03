import {describe,it,expect,vi} from 'vitest';
import {previewGeneration,previewConfiguration,previewUuid} from './lib/consolidation-preview-config.mjs';
import {assertSafeCredentialLogging,assertStructuralDatabaseLog,scramVerifier,secureCredentialDdlLogging} from './lib/consolidation-preview-secrets.mjs';
import {validatePreviewFixture} from './consolidation-preview-fixture.mjs';
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
  it('WORKER-068: separates post-runtime database, roles and tenant identity from legacy and other contexts',()=>{
    const context={kind:'post-runtime',runtimeNonce:'b'.repeat(32)};
    const postEnv={...env,MEM9_PRODUCTION_RUNTIME_MODE:'active',MEM9_PREVIEW_ACCEPTANCE_CONTEXT:context.kind,MEM9_PREVIEW_RUNTIME_NONCE:context.runtimeNonce};
    const legacy=previewConfiguration('pr-7',previewGeneration('pr-7',env),'synthetic-secret');
    const generation=previewGeneration('pr-7',postEnv),a=previewConfiguration('pr-7',generation,'synthetic-secret',context);
    const b=previewConfiguration('pr-7',previewGeneration('pr-7',{...postEnv,GITHUB_RUN_ATTEMPT:'2'}),'synthetic-secret',context);
    expect(generation).not.toBe(legacy.generation);expect(a.version).toBe(2);expect(a.context).toEqual(context);
    for(const other of [legacy,b]){
      expect(a.database).not.toBe(other.database);expect(a.usernames).not.toEqual(other.usernames);expect(a.tenantId).not.toBe(other.tenantId);
    }
    expect(a.tenantName).not.toBe(b.tenantName);expect(a.tenantName).not.toBe('synthetic-consolidation-pr-7');
    expect(a.database).toMatch(/^mem9_preview_[a-f0-9]{12}$/);
    for(const [kind,name]of Object.entries(a.usernames))expect(name).toBe(a.database+'_'+kind);
    const credentials=Object.fromEntries(Object.entries(a.usernames).map(([kind,username])=>[kind,{username}]));
    expect(validatePreviewFixture(a,credentials,'pr-7',generation)).toEqual(a);
    for(const changed of [{...a,tenantName:'synthetic-consolidation-pr-7'}, {...a,context:{...context,runtimeNonce:'c'.repeat(32)}}, {...a,database:legacy.database}])
      expect(()=>validatePreviewFixture(changed,credentials,'pr-7',generation)).toThrow('InvalidPreviewFixture');
  });
  it('WORKER-067: rejects partial, intermediate and foreign post-runtime contexts',()=>{
    const post={...env,MEM9_PRODUCTION_RUNTIME_MODE:'active',MEM9_PREVIEW_ACCEPTANCE_CONTEXT:'post-runtime',MEM9_PREVIEW_RUNTIME_NONCE:'b'.repeat(32)};
    for(const invalid of [{...post,MEM9_PREVIEW_RUNTIME_NONCE:''},{...post,MEM9_PREVIEW_ACCEPTANCE_CONTEXT:''},
      {...post,MEM9_PRODUCTION_RUNTIME_MODE:'paused'},{...post,MEM9_PRODUCTION_RUNTIME_MODE:'ready'}, {...post,MEM9_PRODUCTION_RUNTIME_MODE:'prepare'}])
      expect(()=>previewGeneration('pr-7',invalid)).toThrow('InvalidPreviewContext');
    expect(()=>previewGeneration('prod',post)).toThrow();
    expect(()=>previewConfiguration('pr-7','a'.repeat(64),'synthetic-secret',{kind:'post-runtime',runtimeNonce:'b'.repeat(32),database:'foreign'})).toThrow('InvalidPreviewContext');
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
