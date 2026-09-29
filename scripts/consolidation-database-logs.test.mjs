import {describe,it,expect} from 'vitest';
import {captureDatabaseLogCoverage,scanDatabaseLogs} from './consolidation-scheduler-e2e.mjs';

const first='error/postgresql.log.2026-09-29-1805';
const second='error/postgresql.log.2026-09-29-1835';
function fixture(){
  const data=new Map([[first,'2026-09-29 18:13:00 UTC LOG: checkpoint complete\n']]);
  let files=[{LogFileName:first,Size:Buffer.byteLength(data.get(first)),LastWritten:Date.parse('2026-09-29T18:13:00Z')}];
  const requests=[];
  const options={manifest:{stage:'pr-7'},host:'writer.example.com',rds:{},progress:()=>{},send:async(_client,command)=>{
    const kind=command.constructor.name,input=command.input;requests.push({kind,input});
    if(kind==='DescribeDBClustersCommand')return {DBClusters:[{Endpoint:'writer.example.com',DBClusterIdentifier:'mem9-on-aws-pr-7-db',DBClusterArn:'synthetic-arn',DBClusterMembers:[{DBInstanceIdentifier:'mem9-on-aws-pr-7-instance'}]}]};
    if(kind==='ListTagsForResourceCommand')return {TagList:[{Key:'Project',Value:'mem9-on-aws'},{Key:'Stage',Value:'pr-7'}]};
    if(kind==='DescribeDBInstancesCommand')return {DBInstances:[{DBInstanceIdentifier:'mem9-on-aws-pr-7-instance',DBClusterIdentifier:'mem9-on-aws-pr-7-db'}]};
    if(kind==='DescribeDBLogFilesCommand')return {DescribeDBLogFiles:files};
    if(kind==='DownloadDBLogFilePortionCommand')return {LogFileData:data.get(input.LogFileName),Marker:'finished',AdditionalDataPending:false};
    throw Error('UnexpectedCommand');
  }};
  return {options,data,requests,getFiles:()=>files,setFiles:value=>{files=value;}};
}
describe('PostgreSQL log coverage across quiet intervals',()=>{
  it('reads the unchanged pre-run file when no statements were logged during acceptance',async()=>{
    const f=fixture(),coverage=await captureDatabaseLogCoverage(f.options);
    expect(await scanDatabaseLogs({...f.options,coverage})).toEqual({files:1,bytes:f.getFiles()[0].Size});
    expect(f.requests.filter(r=>r.kind==='DescribeDBLogFilesCommand').every(r=>r.input.FileLastWritten===undefined)).toBe(true);
  });
  it('reads the pre-run anchor and later rotations',async()=>{
    const f=fixture(),coverage=await captureDatabaseLogCoverage(f.options);
    f.data.set(second,'LOG: checkpoint complete\n');
    f.setFiles([...f.getFiles(),{LogFileName:second,Size:Buffer.byteLength(f.data.get(second)),LastWritten:Date.parse('2026-09-29T18:35:00Z')}]);
    expect((await scanDatabaseLogs({...f.options,coverage})).files).toBe(2);
    expect(f.requests.filter(r=>r.kind==='DownloadDBLogFilePortionCommand').map(r=>r.input.LogFileName)).toEqual([first,second]);
  });
  it.each(['missing','truncated'])('fails when the initial log anchor is %s',async kind=>{
    const f=fixture(),coverage=await captureDatabaseLogCoverage(f.options);
    f.setFiles(kind==='missing'?[{LogFileName:second,Size:0,LastWritten:Date.now()}]:[{...f.getFiles()[0],Size:0}]);
    await expect(scanDatabaseLogs({...f.options,coverage})).rejects.toThrow('DatabaseLogAnchorMissing');
  });
  it('fails on empty inventories and incomplete downloads',async()=>{
    const f=fixture(),coverage=await captureDatabaseLogCoverage(f.options);
    f.data.set(first,'');
    await expect(scanDatabaseLogs({...f.options,coverage})).rejects.toThrow('DatabaseLogReadIncomplete');
    f.setFiles([]);
    await expect(captureDatabaseLogCoverage(f.options)).rejects.toThrow('DatabaseLogCoverageIncomplete');
  });
  it('still rejects credential-bearing structures without exposing raw text',async()=>{
    const f=fixture(),coverage=await captureDatabaseLogCoverage(f.options);
    f.data.set(first,'SCRAM-SHA-256$4096:SYNTHETIC_CREDENTIAL_MARKER');
    await expect(scanDatabaseLogs({...f.options,coverage})).rejects.toThrow('UnsafeDatabaseLogStructure');
  });
});
