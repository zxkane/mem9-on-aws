import {describe,it,expect} from 'vitest';
import {inspectProductionDatabase,ensureProductionSnapshot,removePreviewSnapshot} from './lib/production-runtime-backup.mjs';

function fixture(){
  const time=Date.now(),account='123456789012',region='ap-northeast-1',stage='prod';
  const meta={account,region,stage,host:'mem9-on-aws-prod-fixture.cluster-example.ap-northeast-1.'+['rds','amazonaws','com'].join('.'),database:'mem9',
    originalOwnerSecret:`arn:aws:secretsmanager:${region}:${account}:secret:mem9-on-aws-prod-owner`};
  const database={DBClusterIdentifier:'mem9-on-aws-prod-fixture',DBClusterArn:`arn:aws:rds:${region}:${account}:cluster:mem9-on-aws-prod-fixture`,
    DbClusterResourceId:'cluster-synthetic',DatabaseName:'mem9',Status:'available',Engine:'aurora-postgresql',EngineVersion:'17.4',StorageEncrypted:true,
    MasterUsername:'legacy',Endpoint:meta.host,BackupRetentionPeriod:14,LatestRestorableTime:new Date(time),EarliestRestorableTime:new Date(time-60000)};
  const plan={...meta,nonce:'a'.repeat(32),createdAt:time-60000,databaseClusterId:database.DBClusterIdentifier,databaseResourceId:database.DbClusterResourceId,masterUsername:'legacy',engineVersion:'17.4'};
  const name=`mem9-on-aws-prod-runtime-${plan.nonce.slice(0,20)}`;
  let snapshot={DBClusterIdentifier:database.DBClusterIdentifier,DbClusterResourceId:database.DbClusterResourceId,
    DBClusterSnapshotArn:`arn:aws:rds:${region}:${account}:cluster-snapshot:${name}`,Engine:database.Engine,
    StorageEncrypted:true,SnapshotCreateTime:new Date(time),Status:'available'};
  const secret={ARN:meta.originalOwnerSecret,RotationEnabled:false},calls=[];
  const send=async command=>{
    const type=command.constructor.name;calls.push({type,input:command.input});
    if(type==='DescribeDBClustersCommand')return {DBClusters:[database]};
    if(type==='DescribeSecretCommand')return secret;
    if(type==='DescribeDBClusterSnapshotsCommand'){
      if(snapshot)return {DBClusterSnapshots:[snapshot]};
      throw Object.assign(Error('missing'),{name:'DBClusterSnapshotNotFoundFault'});
    }
    if(type==='DeleteDBClusterSnapshotCommand')return {};
    throw Error('UnexpectedCommand');
  };
  return {plan,meta,database,secret,calls,get snapshot(){return snapshot;},set snapshot(value){snapshot=value;},clients:{rds:{send},secrets:{send}},now:()=>time};
}
describe('pre-maintenance database and recovery snapshot gates',()=>{
  it('binds the actual Aurora master and cluster and reads no secret value',async()=>{
    const f=fixture();expect(await inspectProductionDatabase(f.clients,f.meta,{now:f.now})).toEqual({
      databaseClusterId:f.database.DBClusterIdentifier,databaseResourceId:f.database.DbClusterResourceId,masterUsername:'legacy',engineVersion:'17.4'});
    expect(f.calls.map(c=>c.type)).toEqual(['DescribeDBClustersCommand','DescribeSecretCommand']);
    expect(await ensureProductionSnapshot(f.clients,f.plan,{now:f.now})).toMatchObject({createdAt:f.now()});
    expect(f.calls.some(c=>c.type==='CreateDBClusterSnapshotCommand')).toBe(false);
  });
  it.each([{BackupRetentionPeriod:1},{StorageEncrypted:false},{DatabaseName:'foreign'},
    {LatestRestorableTime:'invalid'},{LatestRestorableTime:new Date(0)},{PendingModifiedValues:{MasterUserPassword:'synthetic'}}])('blocks unsafe database state %o',async change=>{
    const f=fixture();Object.assign(f.database,change);
    await expect(inspectProductionDatabase(f.clients,f.meta,{now:f.now})).rejects.toThrow('ProductionDatabasePreflightFailed');
  });
  it('blocks enabled credential rotation and snapshots belonging to a replaced cluster',async()=>{
    const f=fixture();f.secret.RotationEnabled=true;
    await expect(inspectProductionDatabase(f.clients,f.meta,{now:f.now})).rejects.toThrow('UnexpectedOwnerCredentialRotation');
    const g=fixture();g.database.DbClusterResourceId='replaced';
    await expect(ensureProductionSnapshot(g.clients,g.plan,{now:g.now})).rejects.toThrow('ProductionDatabaseIdentityChanged');
  });
  it.each([{DBClusterIdentifier:'foreign'},{DbClusterResourceId:'foreign'},{StorageEncrypted:false},
    {Status:'creating'},{SnapshotCreateTime:new Date(0)}])('requires a completed matching recent snapshot %o',async change=>{
    const f=fixture();Object.assign(f.snapshot,change);
    await expect(ensureProductionSnapshot(f.clients,f.plan,{now:f.now})).rejects.toThrow();
    expect(f.calls.some(c=>c.type==='CreateDBClusterSnapshotCommand')).toBe(false);
  });
  it('never deletes a production snapshot',async()=>{
    const f=fixture();await expect(removePreviewSnapshot(f.clients,f.plan)).rejects.toThrow('PreviewSnapshotCleanupOnly');
    expect(f.calls).toEqual([]);
  });
});
