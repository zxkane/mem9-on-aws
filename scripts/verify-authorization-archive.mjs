import {execFile} from 'node:child_process';
import {promisify,parseArgs} from 'node:util';
import {pathToFileURL} from 'node:url';
import {parseStrictJson,expectedArchivePolicy,verifyArchivePolicy,verifyArchiveAvailability,MAX_ARCHIVE_CONFIGURATION_BYTES} from './lib/authorization-archive-policy.mjs';

const execute=promisify(execFile);
export async function collectArchiveTiering({bucket,region,owner},{run=execute}={}){
 expectedArchivePolicy(bucket);
 if(!/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(region??'')||!/^\d{12}$/.test(owner??''))throw Error('ArchiveTargetInvalid');
 const configurations=[],seen=new Set();let token;
 for(let page=0;page<100;page++){
  const args=['s3api','list-bucket-intelligent-tiering-configurations','--bucket',bucket,'--region',region,'--expected-bucket-owner',owner,'--output','json','--no-paginate'];
  if(token!==undefined)args.push('--continuation-token='+token);
  const response=await run('aws',args,{encoding:'utf8',timeout:30000,maxBuffer:MAX_ARCHIVE_CONFIGURATION_BYTES});
  const value=parseStrictJson(response.stdout);
  if(!value||typeof value.IsTruncated!=='boolean'||value.NextToken!==undefined||
    value.ContinuationToken!==undefined&&value.ContinuationToken!==token)throw Error('ArchiveTieringIncomplete');
  const entries=value.IntelligentTieringConfigurationList===undefined?[]:value.IntelligentTieringConfigurationList;
  if(!Array.isArray(entries)||configurations.length+entries.length>10000)throw Error('ArchiveTieringIncomplete');
  configurations.push(...entries);
  if(!value.IsTruncated){
   if(value.NextContinuationToken!==undefined&&value.NextContinuationToken!=='')throw Error('ArchiveTieringIncomplete');
   return {IsTruncated:false,IntelligentTieringConfigurationList:configurations};
  }
  if(typeof value.NextContinuationToken!=='string'||!value.NextContinuationToken||seen.has(value.NextContinuationToken))throw Error('ArchiveTieringIncomplete');
  token=value.NextContinuationToken;seen.add(token);
 }
 throw Error('ArchiveTieringIncomplete');
}
async function input(){
 const chunks=[];let size=0;
 for await(const chunk of process.stdin){size+=chunk.length;if(size>MAX_ARCHIVE_CONFIGURATION_BYTES)throw Error('ArchiveConfigurationInvalid');chunks.push(chunk);}
 return Buffer.concat(chunks).toString('utf8');
}
async function main(){
 const {values,positionals}=parseArgs({options:{bucket:{type:'string'},region:{type:'string'},owner:{type:'string'}},allowPositionals:true});
 if(positionals.length!==1)throw Error('ArchiveVerificationModeInvalid');
 const mode=positionals[0];
 if(mode==='collect-tiering'){process.stdout.write(JSON.stringify(await collectArchiveTiering(values))+'\n');return;}
 if(values.region!==undefined||values.owner!==undefined)throw Error('ArchiveVerificationArgumentsInvalid');
 const raw=await input();
 if(mode==='policy'){
  const response=parseStrictJson(raw);
  if(typeof response?.Policy!=='string')throw Error('ArchivePolicyResponseInvalid');
  verifyArchivePolicy(response.Policy,{bucket:values.bucket});
 }else if(mode==='availability'){
  if(values.bucket!==undefined)throw Error('ArchiveVerificationArgumentsInvalid');
  verifyArchiveAvailability(parseStrictJson(raw));
 }else throw Error('ArchiveVerificationModeInvalid');
 process.stdout.write('Authorization archive '+mode+' verified\n');
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(()=>{
 process.stderr.write('Authorization archive verification failed\n');process.exitCode=1;
});
