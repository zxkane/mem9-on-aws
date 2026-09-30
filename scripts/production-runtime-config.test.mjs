import {describe,it,expect} from 'vitest';
import {validateRolloutIdentity,schemaAdministratorRole,assertRolloutClaim} from './lib/production-runtime-config.mjs';

const identity=()=>({stage:'prod',database:'mem9',databaseOid:100,legacyRoleOid:101,administratorRoleOid:102,runtimeRoleOid:103,
  writerEndpoint:'mem9-on-aws-prod-fixture.cluster-example.ap-northeast-1.'+['rds','amazonaws','com'].join('.'),
  clusterArn:'arn:aws:ecs:ap-northeast-1:123456789012:cluster/mem9-on-aws-prod-Fixture',
  fallbackTaskDefinition:'arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-on-aws-prod-Fixture-Mem9RuntimeServer:2',
  runtimeCredentialArn:'arn:aws:ssm:ap-northeast-1:123456789012:parameter/mem9-on-aws/prod/runtime/database-credential',
  schemaDigest:'a'.repeat(64),operatorDigest:'b'.repeat(64),fallbackImageDigest:'sha256:'+'c'.repeat(64)});

describe('production rollout identity and admission',()=>{
  it('binds the database, fallback and runtime reference to one stage/account/region',()=>{
    expect(validateRolloutIdentity(identity())).toEqual(identity());
    expect(schemaAdministratorRole('prod')).toMatch(/^mem9_schema_[a-f0-9]{12}$/);
    for(const patch of [{stage:'dev'},{stage:'pr-1'},{databaseOid:0},{runtimeRoleOid:101},
      {runtimeCredentialArn:'legacy-owner-secret'},{fallbackTaskDefinition:identity().fallbackTaskDefinition.replace('Mem9RuntimeServer','Mem9Server')},
      {writerEndpoint:'foreign.example.com'},{fallbackImageDigest:'mutable-tag'},{password:'FORBIDDEN_FIELD'}])
      expect(()=>validateRolloutIdentity({...identity(),...patch})).toThrow('InvalidRolloutIdentity');
  });
  it('a stale invocation cannot continue after recovery and retries cannot renew the deadline',()=>{
    const nonce='a'.repeat(32),claim={nonce,epoch:1};
    const state={operation_nonce:nonce,epoch:1,phase:'password_fenced',status:'running',deadline_ms:1000};
    expect(()=>assertRolloutClaim(state,claim,{now:999})).not.toThrow();
    expect(()=>assertRolloutClaim(state,claim,{now:1000})).toThrow('RolloutAdmissionClosed');
    expect(()=>assertRolloutClaim({...state,epoch:2,status:'recovering'},claim,{recovery:true,now:999})).toThrow('StaleRolloutClaim');
    expect(()=>assertRolloutClaim({...state,status:'recovering'},claim,{now:999})).toThrow('RolloutAdmissionClosed');
    // Repair is permitted after the deadline; another migration step is not.
    expect(()=>assertRolloutClaim({...state,status:'recovering'},claim,{recovery:true,now:1001})).not.toThrow();
  });
  it('closes migration admission at minute 60 while preserving a restoration reserve',()=>{
    const nonce='a'.repeat(32),claim={nonce,epoch:1};
    const state={operation_nonce:nonce,epoch:1,phase:'transferred',status:'running',started_ms:0,deadline_ms:7200000};
    expect(()=>assertRolloutClaim(state,claim,{now:3599999})).not.toThrow();
    expect(()=>assertRolloutClaim(state,claim,{now:3600000})).toThrow('RolloutAdmissionClosed');
    expect(()=>assertRolloutClaim({...state,phase:'runtime_ready'},claim,{now:3600000})).not.toThrow();
  });
});
