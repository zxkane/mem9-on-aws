'use strict';
// Operator-only synthetic verification. No caller selects an operation, key,
// encryption context, endpoint, credentials, or expected authorization result.
const {createHash} = require('node:crypto');
const {KMSClient,DecryptCommand} = require('@aws-sdk/client-kms');
const {EC2Client,DescribeSubnetsCommand} = require('@aws-sdk/client-ec2');
const SYNTHETIC = 'mem9-gateway-runtime-canary-v1';
const sha = value => createHash('sha256').update(value).digest('hex');
const canonical = v => Array.isArray(v) ? v.map(canonical) : v && typeof v === 'object'
  ? Object.fromEntries(Object.keys(v).sort().map(k => [k,canonical(v[k])])) : v;
const hash = v => sha(JSON.stringify(canonical(v)));
const need = (v,code) => {if(!v)throw Error('GatewayCanary'+code);};
const exact = (v,keys) => v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).sort().join() === keys.toSorted().join();
const requestId = v => typeof v === 'string' && /^[A-Za-z0-9-]{8,128}$/.test(v);

exports.handler = async (event,context) => {
  need(process.arch === 'arm64' && /^v24\./.test(process.version),'Runtime');
  need(exact(event,['version','nonce','ciphertextBase64']) && event.version === 1 && /^[a-f0-9]{64}$/.test(event.nonce),'Input');
  need(typeof event.ciphertextBase64 === 'string' && event.ciphertextBase64.length > 0 && event.ciphertextBase64.length <= 8192,'Ciphertext');
  const ciphertext = Buffer.from(event.ciphertextBase64,'base64');
  need(ciphertext.length <= 6144 && ciphertext.toString('base64') === event.ciphertextBase64,'Ciphertext');
  const match = /^arn:aws:lambda:([a-z]{2}-[a-z]+-\d):([0-9]{12}):function:(mem9-on-aws-runtime-check-Mem9ProxyFnFunction-([a-f0-9]{12}))$/.exec(context?.invokedFunctionArn ?? '');
  need(match && process.env.AWS_REGION === match[1] && process.env.AWS_LAMBDA_FUNCTION_NAME === match[3] && requestId(context.awsRequestId),'Identity');
  const [functionArn,region,account,functionName,verificationId] = match;
  const keyArn = process.env.CANARY_KEY_ARN,vpcId = process.env.CANARY_VPC_ID;
  need(new RegExp('^arn:aws:kms:'+region+':'+account+':key/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$').test(keyArn ?? '') && /^vpc-(?:[a-f0-9]{8}|[a-f0-9]{17})$/.test(vpcId ?? ''),'Scope');
  const credentials = {accessKeyId:process.env.AWS_ACCESS_KEY_ID,secretAccessKey:process.env.AWS_SECRET_ACCESS_KEY,sessionToken:process.env.AWS_SESSION_TOKEN};
  need(/^ASIA[A-Z0-9]{16}$/.test(credentials.accessKeyId ?? '') && typeof credentials.secretAccessKey === 'string' && credentials.secretAccessKey.length === 40 && typeof credentials.sessionToken === 'string' && credentials.sessionToken.length > 0,'Credentials');
  const remaining = context.getRemainingTimeInMillis();need(Number.isFinite(remaining) && remaining > 3000,'Deadline');
  const startedMs = Date.now(),controller = new AbortController();
  const sdk = {kms:require('@aws-sdk/client-kms/package.json').version,ec2:require('@aws-sdk/client-ec2/package.json').version};
  need(Object.values(sdk).every(v=>typeof v==='string'&&/^3\.\d+\.\d+$/.test(v)),'Sdk');
  const options = {region,credentials,maxAttempts:1,useFipsEndpoint:false,useDualstackEndpoint:false,requestHandler:{connectionTimeout:2000,requestTimeout:8000}};
  const kms = new KMSClient({...options,endpoint:'https://kms.'+region+'.amazonaws.com'}),ec2 = new EC2Client({...options,endpoint:'https://ec2.'+region+'.amazonaws.com'});
  const timer = setTimeout(()=>controller.abort(),Math.min(20000,remaining-1000));
  const encryptionContext = {'aws:lambda:FunctionArn':functionArn};
  const requests = {
    kms:{KeyId:keyArn,CiphertextBlob:event.ciphertextBase64,EncryptionAlgorithm:'SYMMETRIC_DEFAULT',EncryptionContext:encryptionContext},
    ec2:{DryRun:true,Filters:[{Name:'vpc-id',Values:[vpcId]}]},
  };
  const observe = async(service,action,client,command) => {
    const begin = Date.now();
    try {
      const result = await client.send(command,{abortSignal:controller.signal});
      need(requestId(result.$metadata?.requestId) && result.$metadata.httpStatusCode === 200,'ResponseIdentity');
      if(service === 'kms'){
        const plain = result.Plaintext;need(plain instanceof Uint8Array && plain.length <= 4096 && result.KeyId === keyArn && result.EncryptionAlgorithm === 'SYMMETRIC_DEFAULT','DecryptResponse');
        const digest = sha(plain);plain.fill(0);need(digest === sha(SYNTHETIC),'Plaintext');
        return {service,action,requestHash:hash(requests[service]),outcome:'success',requestId:result.$metadata.requestId,httpStatus:200,plaintextHash:digest,startedMs:begin,completedMs:Date.now()};
      }
      // A successful EC2 describe is not the required DryRun authorization result.
      return {service,action,requestHash:hash(requests[service]),outcome:'unexpected-success',requestId:result.$metadata.requestId,httpStatus:200,startedMs:begin,completedMs:Date.now()};
    } catch(error) {
      const meta = error?.$metadata;
      if(requestId(meta?.requestId) && Number.isInteger(meta.httpStatusCode) && meta.httpStatusCode >= 400 && meta.httpStatusCode < 600 && typeof error.name === 'string' && /^[A-Za-z][A-Za-z0-9]{0,80}$/.test(error.name))
        return {service,action,requestHash:hash(requests[service]),outcome:'service-error',errorCode:error.name,requestId:meta.requestId,httpStatus:meta.httpStatusCode,startedMs:begin,completedMs:Date.now()};
      // Transport errors, malformed bodies, and local validation failures are
      // inconclusive. Never manufacture an AWS request ID or an IAM decision.
      return {service,action,requestHash:hash(requests[service]),outcome:'unknown',startedMs:begin,completedMs:Date.now()};
    }
  };
  try {
    const results = [await observe('kms','Decrypt',kms,new DecryptCommand({...requests.kms,CiphertextBlob:ciphertext}))];
    if(results[0].outcome !== 'unknown' && !controller.signal.aborted)results.push(await observe('ec2','DescribeSubnets',ec2,new DescribeSubnetsCommand(requests.ec2)));
    return {version:1,kind:'gateway-runtime-canary-observation',verificationId,functionArn,functionName,invocationRequestId:context.awsRequestId,nonce:event.nonce,keyArn,vpcId,ciphertextHash:sha(ciphertext),eventHash:hash(event),runtime:{node:process.version,architecture:process.arch,sdk},startedMs,completedMs:Date.now(),results};
  } finally {clearTimeout(timer);controller.abort();kms.destroy();ec2.destroy();ciphertext.fill(0);}
};
