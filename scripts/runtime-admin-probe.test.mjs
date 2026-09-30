import {describe,expect,it,vi} from 'vitest';
import {probeRuntimeAdministrator,probeRoleName} from './runtime-admin-probe.mjs';

function fixture(failAt){
  const statements=[];
  let present=true;
  const owner={query:vi.fn(async(sql,args)=>{
    statements.push({connection:'owner',sql,args});
    if(sql.includes('SELECT oid,shobj_description'))return {rows:present?[{oid:101,marker:'mem9-admin-probe-v1/pr-7/mem9'}]:[]};
    if(sql.startsWith('DROP ROLE '))present=false;
    if(sql.includes('AS owner_name'))return {rows:[{owner_name:'legacy_fixture',database_name:'mem9',owner_oid:100,authorized:true}]};
    if(sql.includes('pg_settings'))return {rows:[
      {name:'log_statement',setting:'none'},{name:'log_min_duration_statement',setting:'-1'},
      {name:'log_min_duration_sample',setting:'-1'},{name:'log_transaction_sample_rate',setting:'0'},
      {name:'log_parameter_max_length_on_error',setting:'0'},
    ]};
    if(sql.includes('pg_extension'))return {rows:[{extname:'vector',extversion:'0.8.0'}]};
    return {rows:[{result:true}]};
  })};
  const admin={query:vi.fn(async(sql,args)=>{
    statements.push({connection:'admin',sql,args});
    if(failAt&&sql.includes(failAt))throw Object.assign(new Error('PRIVATE_PASSWORD_AND_SQL_CONTEXT'),{code:'42501'});
    return {rows:[{result:true}]};
  }),end:vi.fn(async()=>{})};
  const freshOwner={query:vi.fn(async()=>({rows:[{result:true}]})),end:vi.fn(async()=>{})};
  const connect=vi.fn(async credentials=>credentials.username==='legacy_fixture'?freshOwner:admin);
  return {owner,admin,connect,statements,config:{stage:'pr-7',database:'mem9',
    probeCredential:{username:probeRoleName('pr-7'),password:'SyntheticProbePassword'.repeat(3),salt:'SyntheticProbeSalt'},
    ownerCredentials:{username:'legacy_fixture',password:'SYNTHETIC_OWNER_VALUE'}}};
}

describe('preview Aurora administrator authority probe',()=>{
  it('refuses production and malformed stages before SQL or credentials',async()=>{
    for(const stage of ['prod','dev','pr-0','pr-7;sql']){
      const f=fixture();
      await expect(probeRuntimeAdministrator({...f,config:{...f.config,stage}})).rejects.toThrow('PreviewAdminProbeOnly');
      expect(f.owner.query).not.toHaveBeenCalled();expect(f.connect).not.toHaveBeenCalled();
    }
  });
  it('probes real retirement authority inside rollback and removes its temporary administrator',async()=>{
    const f=fixture();
    expect(await probeRuntimeAdministrator(f)).toEqual({event:'runtime_admin_probe',outcome:'ready',retirementAuthority:true,extensionOwnership:true,extensionMaintenanceProven:false});
    const sql=f.statements.filter(s=>s.connection==='admin').map(s=>s.sql);
    expect(sql.some(s=>s.includes('NOLOGIN PASSWORD NULL'))).toBe(true);
    expect(sql.filter(s=>s==='BEGIN').length).toBeGreaterThan(0);
    expect(sql.filter(s=>s==='ROLLBACK')).toHaveLength(sql.filter(s=>s==='BEGIN').length);
    expect(sql).not.toContain('COMMIT');
    expect(f.statements.at(-1).sql).toContain('pg_advisory_unlock');
    expect(f.statements.some(s=>s.sql==='DROP ROLE "'+probeRoleName('pr-7')+'"')).toBe(true);
    expect(f.admin.end).toHaveBeenCalledOnce();
    expect(f.connect).toHaveBeenCalledWith(f.config.ownerCredentials);
  });
  it.each(['NOLOGIN PASSWORD NULL','ALTER EXTENSION'])('cleans up and suppresses raw database errors at %s',async failAt=>{
    const f=fixture(failAt);
    await expect(probeRuntimeAdministrator(f)).rejects.toMatchObject({message:failAt==='ALTER EXTENSION'?'ExtensionAdministrationDenied':'MasterRetirementDenied',code:'42501'});
    expect(f.statements.some(s=>s.connection==='admin'&&s.sql==='ROLLBACK')).toBe(true);
    expect(f.statements.some(s=>s.sql.startsWith('DROP ROLE '))).toBe(true);
    expect(f.admin.end).toHaveBeenCalledOnce();
    expect(f.statements.filter(s=>s.sql.includes('PASSWORD')).every(s=>!s.sql.includes('SYNTHETIC_OWNER_VALUE'))).toBe(true);
  });
  it('attempts independent role removal when closing the administrator fails',async()=>{
    const f=fixture();f.admin.end.mockRejectedValueOnce(Error('PRIVATE_CONNECTION_ERROR'));
    await expect(probeRuntimeAdministrator(f)).rejects.toThrow('AdminProbeCleanupFailed');
    expect(f.statements.some(s=>s.sql.startsWith('DROP ROLE '))).toBe(true);
  });
  it('cleans a created role on graceful interruption and bounds login validity',async()=>{
    const f=fixture(),controller=new AbortController();
    const original=f.owner.query.getMockImplementation();
    f.owner.query.mockImplementation(async(sql,args)=>{
      const result=await original(sql,args);
      if(sql.startsWith('SELECT pg_temp.mem9_admin_probe_role'))controller.abort();
      return result;
    });
    await expect(probeRuntimeAdministrator({...f,signal:controller.signal})).rejects.toThrow('AdminProbeInterrupted');
    expect(f.statements.some(s=>s.sql.startsWith('DROP ROLE '))).toBe(true);
    expect(f.statements.some(s=>s.sql.includes('VALID UNTIL')&&s.sql.includes("interval '15 minutes'"))).toBe(true);
  });
});
