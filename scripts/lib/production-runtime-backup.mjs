import {DescribeDBClustersCommand,DescribeDBClusterSnapshotsCommand,CreateDBClusterSnapshotCommand,DeleteDBClusterSnapshotCommand} from '@aws-sdk/client-rds';
import {DescribeSecretCommand} from '@aws-sdk/client-secrets-manager';
import {setTimeout as delay} from 'node:timers/promises';

const send=(client,command)=>client.send(command,{abortSignal:AbortSignal.timeout(30000)});
const fail=code=>{throw Error(code);};

export async function inspectProductionDatabase(clients,meta,{now=Date.now}={}){
  const clusters=[];let Marker;
  for(let page=0;page<100;page++){
    const result=await send(clients.rds,new DescribeDBClustersCommand({MaxRecords:100,Marker}));
    clusters.push(...(result.DBClusters??[]).filter(c=>c.Endpoint===meta.host));
    if(!result.Marker)break;if(result.Marker===Marker||page===99)fail('DatabaseInventoryIncomplete');Marker=result.Marker;
  }
  const db=clusters[0];
  const latest=new Date(db?.LatestRestorableTime).getTime(),earliest=new Date(db?.EarliestRestorableTime).getTime();
  if(clusters.length!==1||!db.DBClusterIdentifier?.startsWith(`mem9-on-aws-${meta.stage}-`)||
    db.DBClusterArn!==`arn:aws:rds:${meta.region}:${meta.account}:cluster:${db.DBClusterIdentifier}`||
    db.DatabaseName!==meta.database||db.Status!=='available'||db.Engine!=='aurora-postgresql'||!/^\d+\.\d+$/.test(db.EngineVersion??'')||!db.StorageEncrypted||
    !db.DbClusterResourceId||!db.MasterUsername||db.MasterUserSecret||Object.keys(db.PendingModifiedValues??{}).length||
    !Number.isInteger(db.BackupRetentionPeriod)||db.BackupRetentionPeriod<(meta.stage==='prod'?14:1)||
    !Number.isFinite(earliest)||!Number.isFinite(latest)||earliest>latest||latest>now()+30000||now()-latest>15*60000)fail('ProductionDatabasePreflightFailed');
  const secret=await send(clients.secrets,new DescribeSecretCommand({SecretId:meta.originalOwnerSecret}));
  if(secret.ARN!==meta.originalOwnerSecret||secret.RotationEnabled||secret.DeletedDate)fail('UnexpectedOwnerCredentialRotation');
  return {databaseClusterId:db.DBClusterIdentifier,databaseResourceId:db.DbClusterResourceId,masterUsername:db.MasterUsername,engineVersion:db.EngineVersion};
}

export async function ensureProductionSnapshot(clients,plan,{create=false,now=Date.now,sleep=delay,deadline=Date.now()+20*60000}={}){
  const current=await inspectProductionDatabase(clients,plan,{now});
  if(Object.keys(current).some(key=>current[key]!==plan[key]))fail('ProductionDatabaseIdentityChanged');
  const name=`mem9-on-aws-${plan.stage}-runtime-${plan.nonce.slice(0,20)}`;
  let created=false;
  while(now()<deadline){
    let snapshot;
    try{
      const result=await send(clients.rds,new DescribeDBClusterSnapshotsCommand({DBClusterSnapshotIdentifier:name,SnapshotType:'manual'}));
      if(result.DBClusterSnapshots?.length!==1)fail('ProductionSnapshotMissing');snapshot=result.DBClusterSnapshots[0];
    }catch(error){
      if(error.name!=='DBClusterSnapshotNotFoundFault'||!create||created)throw error;
      await send(clients.rds,new CreateDBClusterSnapshotCommand({DBClusterIdentifier:plan.databaseClusterId,DBClusterSnapshotIdentifier:name,
        Tags:[{Key:'Project',Value:'mem9-on-aws'},{Key:'Stage',Value:plan.stage},{Key:'Purpose',Value:'runtime-cutover'}]}));
      created=true;await sleep(5000);continue;
    }
    const snapshotTime=new Date(snapshot.SnapshotCreateTime).getTime();
    if(snapshot.DBClusterIdentifier!==plan.databaseClusterId||(snapshot.DbClusterResourceId&&snapshot.DbClusterResourceId!==plan.databaseResourceId)||
      snapshot.DBClusterSnapshotArn!==`arn:aws:rds:${plan.region}:${plan.account}:cluster-snapshot:${name}`||
      snapshot.Engine!=='aurora-postgresql'||!snapshot.StorageEncrypted||!Number.isFinite(snapshotTime)||
      snapshotTime<plan.createdAt-60000||now()-snapshotTime>24*3600000)fail('ProductionSnapshotMismatch');
    if(snapshot.Status==='available')return {snapshot:name,createdAt:snapshotTime};
    if(!create||snapshot.Status!=='creating')fail('ProductionSnapshotNotReady');await sleep(5000);
  }
  fail('ProductionSnapshotDeadline');
}

export async function removePreviewSnapshot(clients,plan){
  if(!/^pr-[1-9][0-9]*$/.test(plan?.stage??'')||!/^[a-f0-9]{32}$/.test(plan.nonce??''))fail('PreviewSnapshotCleanupOnly');
  const name=`mem9-on-aws-${plan.stage}-runtime-${plan.nonce.slice(0,20)}`;
  try{
    const result=await send(clients.rds,new DescribeDBClusterSnapshotsCommand({DBClusterSnapshotIdentifier:name,SnapshotType:'manual'}));
    const snapshot=result.DBClusterSnapshots?.[0];
    if(result.DBClusterSnapshots?.length!==1||snapshot.DBClusterIdentifier!==plan.databaseClusterId||
      snapshot.DBClusterSnapshotArn!==`arn:aws:rds:${plan.region}:${plan.account}:cluster-snapshot:${name}`)fail('PreviewSnapshotMismatch');
    await send(clients.rds,new DeleteDBClusterSnapshotCommand({DBClusterSnapshotIdentifier:name}));
  }catch(error){if(error.name!=='DBClusterSnapshotNotFoundFault')throw error;}
}
