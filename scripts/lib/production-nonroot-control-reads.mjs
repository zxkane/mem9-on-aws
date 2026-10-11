/** Existing CLI transport for two fixed read-only CONTROL observations. No
 * registry password, image mutation, secret retrieval, redirect, or retry. */
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {parseImageTransitionJson} from './production-image-transition-proof.mjs';
import {verifyCanaryFixtureImageIndex} from './production-canary-material.mjs';
import {nonrootHash as hash} from './production-nonroot-contracts.mjs';
const execute=promisify(execFile),need=(ok,code='NonrootControlReadInvalid')=>{if(!ok)throw Error(code);};

export function nonrootControlMetadataReads({account,region},{env=process.env,calls=[]}={}){
 need(/^\d{12}$/.test(account??'')&&/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(region??''));
 const credentials=Object.fromEntries(['AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN'].map(key=>{
  need(typeof env[key]==='string'&&env[key].length>0&&env[key].length<=16384,'NonrootControlReadCredentials');return [key,env[key]];
 }));
 const childEnv={...credentials,PATH:env.PATH??process.env.PATH,LANG:'C.UTF-8',AWS_REGION:region,AWS_DEFAULT_REGION:region,
  AWS_MAX_ATTEMPTS:'1',AWS_PAGER:'',AWS_CLI_AUTO_PROMPT:'off',AWS_EC2_METADATA_DISABLED:'true',AWS_CONFIG_FILE:'/dev/null',AWS_SHARED_CREDENTIALS_FILE:'/dev/null'};
 const read=async(service,api,args,request)=>{
  const event={service,api,requestHash:hash(request),status:'attempted'};calls.push(event);let raw;
  try{raw=(await execute('aws',[service,api,...args,'--region',region,'--output','json','--no-cli-pager'],{
   env:childEnv,encoding:'utf8',timeout:30000,maxBuffer:8388608,
  })).stdout;}catch{event.status='failed';throw Error('NonrootControlReadUnavailable');}
  const response=parseImageTransitionJson(raw);
  Object.assign(event,{status:'completed',responseHash:hash(response),serializedResponseBytes:Buffer.byteLength(raw)});return response;
 };
 return Object.freeze({
  async artifact(route){
   need(route.account===account&&route.region===region&&typeof route.image==='string');
   const repositoryName='mem9-on-aws/preview/bootstrap',prefix=`${account}.dkr.ecr.${region}.amazonaws.com/${repositoryName}@`,rootDigest=route.image.slice(prefix.length);
   need(route.image.startsWith(prefix)&&/^sha256:[a-f0-9]{64}$/.test(rootDigest));
   const request={registryId:account,repositoryName,imageIds:[{imageDigest:rootDigest}]};
   const response=await read('ecr','batch-get-image',['--registry-id',account,'--repository-name',repositoryName,'--image-ids','imageDigest='+rootDigest],request);
   return verifyCanaryFixtureImageIndex(response,{account,repositoryName,rootDigest});
  },
  async key(route){
   need(route.account===account&&route.region===region);
   const key=(await read('kms','describe-key',['--key-id','alias/aws/ssm'],{KeyId:'alias/aws/ssm'})).KeyMetadata;
   need(key?.Arn===route.kmsKeyArn&&key.AWSAccountId===account&&key.Enabled===true&&key.KeyState==='Enabled'&&key.KeyManager==='AWS','NonrootControlKeyMismatch');return key.Arn;
  },
 });
}
