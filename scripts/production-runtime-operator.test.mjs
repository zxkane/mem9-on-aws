import {describe,it,expect} from 'vitest';
import {parseProductionRequest} from './production-runtime-operator.mjs';

describe('production operator request boundary',()=>{
  const request=()=>({operation:'status',nonce:'a'.repeat(32),epoch:1,deadline:Date.now()+60000});
  it('accepts bounded typed operation metadata',()=>{
    const value=request();expect(parseProductionRequest(JSON.stringify(value))).toEqual(value);
  });
  it('accepts an exact event fence only for resume',()=>{
    const value={...request(),operation:'resume',expected_hash:'b'.repeat(64)};
    expect(parseProductionRequest(JSON.stringify(value))).toEqual(value);
    for(const patch of [{operation:'status'},{expected_hash:'invalid'},{expected_hash:4}])
      expect(()=>parseProductionRequest(JSON.stringify({...value,...patch}))).toThrow();
  });
  it.each([{operation:'sql'},{nonce:'bad'},{epoch:0},{epoch:1.5},{deadline:0},{password:'forbidden'},
    {backend_pid:10},{target:{}}])('rejects invalid or extra fields before execution: %o',patch=>{
    expect(()=>parseProductionRequest(JSON.stringify({...request(),...patch}))).toThrow();
  });
  it('does not accept a caller-selected role OID or credential in a preparation target',()=>{
    const value={...request(),operation:'prepare',target:{clusterArn:'cluster',fallbackTaskDefinition:'task',
      fallbackImageDigest:'digest',runtimeCredentialArn:'reference',writerEndpoint:'host',masterUsername:'legacy'}};
    expect(parseProductionRequest(JSON.stringify(value)).operation).toBe('prepare');
    expect(()=>parseProductionRequest(JSON.stringify({...value,target:{...value.target,legacyRoleOid:10}}))).toThrow('InvalidProductionTarget');
    expect(()=>parseProductionRequest('x'.repeat(16385))).toThrow('InvalidProductionRequest');
  });
});
