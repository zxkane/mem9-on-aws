import net from 'node:net';
import {lstat,mkdir,mkdtemp,open,readFile,realpath,rm,unlink,writeFile,chmod} from 'node:fs/promises';
import {isAbsolute,join} from 'node:path';
import {randomBytes,randomUUID} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {setTimeout as sleep} from 'node:timers/promises';
import {runBoundedCommand} from './bounded-subprocess.mjs';
import {resolveApplicationRegion} from './application-region.mjs';
import {expectedGatewayBoundaryPolicyDocument,gatewayBoundaryArn} from './gateway-workload-boundary.mjs';
import {compileGatewayRuntimeCanaryScope,renderGatewayRuntimeCanaryTemplate,verifyGatewayRuntimeCanaryPlan,buildGatewayCanaryOperatorPolicies,
  buildGatewayCanarySessionPolicyBootstrap,gatewayCanaryDocumentHash as hash} from './gateway-runtime-canary-resources.mjs';
import {withGatewayCanaryProvisioningPolicy} from './gateway-runtime-canary-session-policy.mjs';
import {createGatewayCanaryAwsAdapter,inspectGatewayCanaryAwsEvidence} from './gateway-runtime-canary-aws.mjs';
import {runGatewayRuntimeCanaryLifecycle} from './gateway-runtime-canary-lifecycle.mjs';
import {verifyGatewayCanaryPhase,gatewayCanaryInternalReason} from './gateway-runtime-canary-evidence.mjs';
import {verifyGatewayRuntimeSourceMaterial} from './gateway-runtime-source-gate.mjs';
import {GATEWAY_CANARY_OPERATOR_ROLE_NAME,GATEWAY_CANARY_OPERATOR_POLICY_NAME,gatewayCanaryOperatorRoleArn,gatewayCanaryOperatorPolicy,gatewayCanaryOperatorTrustPolicy,
  gatewayCanaryOwnerRoleRefusal,verifyGatewayCanaryOwnerHoldsOperator,gatewayCanaryOrganizationPoliciesAcknowledged,checkGatewayCanaryOrganizationPolicies} from './gateway-canary-operator-role.mjs';

/** Owner-run native broker behind MEM9_BOOTSTRAP_REQUEST_SOCKET. Before it
 * publishes its socket it runs the full A/B/A canary once against the live
 * Gateway boundary, through the native adapter and its own scoped sessions, and
 * confirms cleanup. Each verify-source request is then answered within the
 * client's limit: only for the live default version, only for the reviewed
 * document of this clean checkout, and only when its statements, ignoring the
 * revision Sid, are the ones the canary exercised. The request document is a
 * claim to check, never an input to the canary. */
export const GATEWAY_SOURCE_BROKER_LIMITS=Object.freeze({maximumFrameBytes:16384,requestReadMs:5000,
  defaultDeadlineMs:75*60_000,maximumDeadlineMs:240*60_000,maximumRequests:3,
  sessionSeconds:3600,sessionMarginMs:120_000,journalBytes:4*1024*1024,
  propagationAttempts:6,propagationDelayMs:5000,commandMs:30_000});
export const GATEWAY_CANARY_SOURCE_PATHS=Object.freeze({
  handler:'scripts/test-fixtures/gateway-runtime-canary/handler.cjs',
  template:'scripts/test-fixtures/gateway-runtime-canary/template.json'});
const L=GATEWAY_SOURCE_BROKER_LIMITS;
const LANES=['observe','bootstrap','provision'];
const STATUS={receipt:0,failed:1,request:64};

const need=(ok,why)=>{if(!ok)throw Error('GatewaySourceBroker'+why);};
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.toSorted().join();
const freeze=v=>{if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;};
const doc=v=>{if(typeof v!=='string')return v;try{return JSON.parse(v);}catch{return JSON.parse(decodeURIComponent(v));}};
const own=(v,k)=>v&&typeof v==='object'?Object.getOwnPropertyDescriptor(v,k)?.value:undefined;
/** Never forward an arbitrary message; names from this file or the canary libraries only. */
export const gatewaySourceBrokerReason=error=>{
  const message=own(error,'message');
  if(typeof message==='string'&&/^(?:GatewaySourceBroker|GatewayRuntimeSource)[A-Za-z]+$/.test(message))return message;
  return gatewayCanaryInternalReason(error);
};

// The AWS CLI formatter contract the native adapter also relies on.
function serviceErrorCode(error,operation){
  if(![254,255].includes(error?.code)||typeof error.stderr!=='string')return null;
  const match=/^\s*(?:aws: \[ERROR\]: )?An error occurred \(([A-Za-z0-9]+)\) when calling the ([A-Za-z0-9]+) operation(?: \(reached max retries: [0-9]+\))?: [\s\S]*$/.exec(error.stderr);
  return match&&match[2]===operation?match[1]:null;
}

async function privateDirectory(path,{create=false}={}){
  need(typeof path==='string'&&isAbsolute(path),'PrivatePath');
  if(create)await mkdir(path,{recursive:true,mode:0o700});
  const resolved=await realpath(path),stat=await lstat(resolved);
  need(stat.isDirectory()&&stat.uid===process.getuid()&&(stat.mode&0o777)===0o700,'PrivateDirectory');
  return resolved;
}
async function childDirectory(parent,name){
  const path=join(parent,name);await mkdir(path,{mode:0o700});return privateDirectory(path);
}

/** "<service> <Operation>: <ErrorCode>" for a failed AWS call, or null. Only
 * the service, the operation name and the error code are kept: never the
 * message body, an ARN or an account. */
const DETAIL=/^[a-z0-9-]+ [A-Za-z0-9]+: [A-Za-z0-9._-]{1,80}$/;
export const gatewaySourceBrokerAwsDetail=error=>{const d=own(error,'awsDetail');return typeof d==='string'&&DETAIL.test(d)?d:null;};
const withDetail=(reason,cause)=>Object.assign(Error('GatewaySourceBroker'+reason),gatewaySourceBrokerAwsDetail(cause)?{awsDetail:gatewaySourceBrokerAwsDetail(cause)}:{});
/** A non-AWS detail: field or resource names only, e.g. "differs: templateBody". */
const PLAIN=/^[A-Za-z0-9.,:; -]{1,200}$/;
export const gatewaySourceBrokerDetail=error=>{const d=own(error,'detail');return typeof d==='string'&&PLAIN.test(d)?d:null;};
const detailOf=error=>gatewaySourceBrokerAwsDetail(error)??gatewaySourceBrokerDetail(error);
const describe=(reason,error)=>reason+(detailOf(error)?'; '+detailOf(error):'');

/** Fixed AWS CLI request shape shared with the native adapter. Bodies go through
 * private request files; stdout is parsed only after a zero exit. A failure
 * carries awsDetail, e.g. "sts AssumeRole: InvalidParameterValue". */
export function createGatewaySourceBrokerAwsCli({awsExecutable,region}){
  need(isAbsolute(awsExecutable??''),'AwsExecutable');
  return async function call(environment,service,operation,body,{directory,signal}){
    signal?.throwIfAborted();
    const file=join(directory,'broker-request-'+randomUUID()+'.json');
    const name=operation.split('-').map(w=>w[0].toUpperCase()+w.slice(1)).join('');
    await writeFile(file,JSON.stringify(body),{mode:0o600,flag:'wx'});
    try{
      let result;
      try{
        result=await runBoundedCommand(awsExecutable,['--region',service==='iam'||service==='organizations'?'us-east-1':region,'--output','json','--no-cli-pager','--no-paginate','--cli-binary-format','base64',
          '--cli-connect-timeout','10','--cli-read-timeout','20',service,operation,'--cli-input-json','file://'+file],
          {env:environment,signal,timeoutMs:L.commandMs,maxBufferBytes:1048576});
      }catch(error){
        throw Object.assign(error,{awsDetail:`${service} ${name}: ${/^[A-Z][A-Z_]{1,40}$/.test(String(error?.code))?error.code:'transport'}`});
      }
      if(result.status!==0){
        const match=/An error occurred \(([A-Za-z0-9._-]{1,80})\) when calling the ([A-Za-z0-9]+) operation/.exec(result.stderr);
        throw Object.assign(Error('GatewaySourceBrokerAwsServiceError'),{code:result.status,stderr:result.stderr,
          awsDetail:match?`${service} ${match[2]}: ${match[1]}`:`${service} ${name}: exit-${result.status}`});
      }
      return result.stdout.trim()?JSON.parse(result.stdout):{};
    }finally{await unlink(file).catch(()=>{});}
  };
}

/** The owner's own ambient credentials, minus any endpoint redirection. They
 * read identity, the live boundary and the VPC, and issue the scoped lanes. */
export function gatewaySourceBrokerOwnerEnvironment(environment){
  need(environment&&typeof environment==='object','OwnerEnvironment');
  need(!Object.keys(environment).some(k=>k.startsWith('AWS_ENDPOINT_URL')||k==='AWS_USE_FIPS_ENDPOINT'&&environment[k]==='true'),'OwnerEndpointOverride');
  // Config-file endpoint_url settings are ignored too, not only the env vars.
  return freeze({...environment,AWS_PAGER:'',AWS_CLI_AUTO_PROMPT:'off',AWS_IGNORE_CONFIGURED_ENDPOINT_URLS:'true'});
}

/** Session tags for the lanes, from CC_PROJECT and CC_USAGE, which the
 * operator trust requires as aws:RequestTag/Project and usage. Neither set: no
 * tags. GATEWAY_CANARY_SESSION_TAGS selects how they reach STS:
 * - transitive (default): the caller's own session already carries them as
 *   transitive tags, which role chaining forwards. Setting them again is an
 *   STS conflict, so the lanes pass no explicit tags.
 * - explicit: a caller without transitive tags passes them on each AssumeRole.
 * Anything else, or a mode without tags, fails. */
export function gatewaySourceBrokerSessionTags(environment){
  const set=v=>v!==undefined&&v!=='',project=environment?.CC_PROJECT,usage=environment?.CC_USAGE,mode=environment?.GATEWAY_CANARY_SESSION_TAGS;
  need(!set(mode)||mode==='transitive'||mode==='explicit','SessionTags');
  if(!set(project)&&!set(usage)){need(!set(mode),'SessionTags');return null;}
  need(typeof project==='string'&&/^[a-z0-9-]{1,64}$/.test(project)&&(usage===`cc-${project}`||usage===`codex-${project}`),'SessionTags');
  return freeze({mode:mode==='explicit'?'explicit':'transitive',tags:[{Key:'Project',Value:project},{Key:'usage',Value:usage}]});
}

/** A clean checkout binds every receipt to HEAD. The handler and template the
 * canary deploys must be byte-identical to their committed blobs. */
export async function readGatewayCanaryCheckoutSource({repoRoot,gitExecutable,signal}){
  need(isAbsolute(repoRoot??'')&&isAbsolute(gitExecutable??''),'CheckoutPaths');
  const root=await realpath(repoRoot);
  const git=async(...args)=>{
    const result=await runBoundedCommand(gitExecutable,['-C',root,...args],{env:{PATH:process.env.PATH??'/usr/bin:/bin',HOME:process.env.HOME??root,LC_ALL:'C',GIT_NO_REPLACE_OBJECTS:'1',GIT_OPTIONAL_LOCKS:'0'},
      signal,timeoutMs:L.commandMs,maxBufferBytes:4*1048576});
    need(result.status===0,'Git');return result.stdout;
  };
  need(await realpath((await git('rev-parse','--show-toplevel')).trim())===root,'CheckoutRoot');
  need((await git('status','--porcelain=v1','--untracked-files=all','--ignore-submodules=none'))==='','DirtyCheckout');
  const commit=(await git('rev-parse','--verify','HEAD^{commit}')).trim(),tree=(await git('rev-parse','--verify','HEAD^{tree}')).trim();
  need(/^[a-f0-9]{40}$/.test(commit)&&/^[a-f0-9]{40}$/.test(tree),'CheckoutIdentity');
  const blobs={};
  for(const [name,path] of Object.entries(GATEWAY_CANARY_SOURCE_PATHS)){
    blobs[name]=await git('cat-file','blob',`${commit}:${path}`);
    need(await readFile(join(root,path),'utf8')===blobs[name],'CheckoutSourceChanged');
  }
  return freeze({repoRoot:root,commit,tree,handlerSource:blobs.handler});
}

/** The caller's authenticated assumed-role identity: account and role name. */
export async function readGatewaySourceBrokerCaller({call,environment,directory,signal}){
  const identity=await call(environment,'sts','get-caller-identity',{},{directory,signal});
  const match=/^arn:aws:sts::(\d{12}):assumed-role\/([\w+=,.@-]{1,64})\/[\w+=,.@-]{2,64}$/.exec(identity?.Arn??'');
  need(match&&identity.Account===match[1],'OwnerIdentity');
  return {accountId:match[1],roleName:match[2],sessionName:identity.Arn.slice(identity.Arn.lastIndexOf('/')+1)};
}
/** Best-effort warnings about the calling owner session. The operator trust
 * names the owner role, so it admits every session of that role, including
 * a narrowed one: a session policy, or a permission set or federation that
 * scopes the session below the role, is invisible to the owner check. STS
 * does not expose session policies, so this only flags what the identity
 * shows: an IAM Identity Center role and a federated-looking (e-mail) session name. */
export function gatewaySourceBrokerOwnerSessionWarnings({owner,sessionName}){
  const warnings=['the operator trust is equivalent to an unrestricted session of the owner role; '+
    'session policies on the calling session are not checked, so never grant a narrowed owner session sts:AssumeRole or sts:TagSession on the operator role'];
  if(/\/aws-reserved\/sso\.amazonaws\.com\//.test(owner.roleArn)||/^AWSReservedSSO_/.test(owner.roleName))
    warnings.push('the owner is an IAM Identity Center role: every session of its permission set can assume the operator; do not narrow that permission set below the role');
  if(typeof sessionName==='string'&&sessionName.includes('@'))
    warnings.push('the owner session looks federated; its session policy, if any, cannot be checked here');
  return Object.freeze(warnings);
}
/** The caller resolved to its exact role ARN, path included. */
export async function resolveGatewaySourceBrokerOwner({call,environment,directory,signal}){
  const {accountId,roleName}=await readGatewaySourceBrokerCaller({call,environment,directory,signal});
  const role=(await call(environment,'iam','get-role',{RoleName:roleName},{directory,signal})).Role;
  need(role?.RoleName===roleName&&typeof role.Arn==='string'&&role.Arn.startsWith(`arn:aws:iam::${accountId}:role/`)&&role.Arn.endsWith('/'+roleName),'OwnerRole');
  // The operator itself, project roles and CI deploy roles may not own the operator.
  need(gatewayCanaryOwnerRoleRefusal(role.Arn)===null,'OwnerRoleRefused');
  return freeze({accountId,roleName,roleArn:role.Arn});
}

/** The dedicated operator role, at its fixed name. Its trust must name exactly
 * this owner (with the configured session tags), and its only permission is
 * the generalized lane policy for this account and application region. */
export async function resolveGatewayCanaryOperator({call,environment,directory,signal,owner,region,tags=null,log=()=>{}}){
  const roleArn=gatewayCanaryOperatorRoleArn(owner.accountId),iam=(operation,body)=>call(environment,'iam',operation,body,{directory,signal});
  // The owner check below excludes SCPs and RCPs; refuse if any visibly keys on the principal.
  let organization;
  try{organization=await checkGatewayCanaryOrganizationPolicies({organizations:(operation,body)=>call(environment,'organizations',operation,body,{directory,signal}),accountId:owner.accountId});}
  catch(error){throw withDetail(error?.message==='GatewayCanaryOperatorOrgPolicyUnparseable'?'OrgPolicyUnparseable':'OrgPolicyPrincipalScoped',error);}
  log(organization.status==='unreadable'
    ?'organization policies are not fully readable; relying on GATEWAY_CANARY_ORG_POLICIES_PRINCIPAL_NEUTRAL=true'
    :`organization policies: ${organization.status} (${organization.policies} scanned)`);
  // The operator is administrator-equivalent; it must grant the owner nothing
  // new. The owner's own policies and boundary must allow every operator pair.
  try{await verifyGatewayCanaryOwnerHoldsOperator({iam,accountId:owner.accountId,applicationRegion:region,ownerRoleArn:owner.roleArn});}
  catch(error){throw withDetail({GatewayCanaryOperatorOwnerLacksPermission:'OwnerLacksOperatorPermission',GatewayCanaryOperatorOperatorSimulationDrift:'OperatorSimulationDrift'}[error?.message]??'OwnerPoliciesUnverifiable',error);}
  const role=(await iam('get-role',{RoleName:GATEWAY_CANARY_OPERATOR_ROLE_NAME})).Role;
  need(role?.RoleName===GATEWAY_CANARY_OPERATOR_ROLE_NAME&&role.Arn===roleArn&&role.MaxSessionDuration===3600,'OperatorRole');
  need(hash(doc(role.AssumeRolePolicyDocument))===hash(gatewayCanaryOperatorTrustPolicy({ownerRoleArn:owner.roleArn,tags})),'OperatorTrust');
  const inline=await iam('list-role-policies',{RoleName:GATEWAY_CANARY_OPERATOR_ROLE_NAME}),attached=await iam('list-attached-role-policies',{RoleName:GATEWAY_CANARY_OPERATOR_ROLE_NAME});
  need(!inline.IsTruncated&&isDeepStrictEqual(inline.PolicyNames,[GATEWAY_CANARY_OPERATOR_POLICY_NAME])&&!attached.IsTruncated&&isDeepStrictEqual(attached.AttachedPolicies,[]),'OperatorPolicy');
  const policy=await iam('get-role-policy',{RoleName:GATEWAY_CANARY_OPERATOR_ROLE_NAME,PolicyName:GATEWAY_CANARY_OPERATOR_POLICY_NAME});
  need(hash(doc(policy.PolicyDocument))===hash(gatewayCanaryOperatorPolicy({accountId:owner.accountId,applicationRegion:region})),'OperatorPolicy');
  return freeze({accountId:owner.accountId,roleName:GATEWAY_CANARY_OPERATOR_ROLE_NAME,roleArn});
}

/** Same resolution as the application VPC: MEM9_VPC_ID, else the region's default VPC. */
export async function resolveGatewaySourceBrokerVpc({call,environment,directory,signal,configuredVpcId}){
  const vpcPattern=/^vpc-(?:[a-f0-9]{8}|[a-f0-9]{17})$/;
  const configured=typeof configuredVpcId==='string'?configuredVpcId.trim():'',explicit=configured!=='';
  if(explicit)need(vpcPattern.test(configured),'Vpc');
  const response=await call(environment,'ec2','describe-vpcs',explicit?{VpcIds:[configured]}:{Filters:[{Name:'is-default',Values:['true']}]},{directory,signal});
  need(Array.isArray(response.Vpcs)&&response.Vpcs.length===1&&!response.NextToken,'Vpc');
  const vpcId=response.Vpcs[0].VpcId;
  need(vpcPattern.test(vpcId??'')&&(explicit?vpcId===configured:response.Vpcs[0].IsDefault===true),'Vpc');
  return vpcId;
}

/** Read the live default version through the owner's credentials. */
export async function readLiveGatewayBoundary({call,environment,directory,signal,accountId}){
  const arn=gatewayBoundaryArn({partition:'aws',accountId});
  const metadata=(await call(environment,'iam','get-policy',{PolicyArn:arn},{directory,signal})).Policy;
  need(metadata?.Arn===arn&&/^v[1-9][0-9]*$/.test(metadata.DefaultVersionId??''),'LivePolicyIdentity');
  const version=(await call(environment,'iam','get-policy-version',{PolicyArn:arn,VersionId:metadata.DefaultVersionId},{directory,signal})).PolicyVersion;
  need(version?.VersionId===metadata.DefaultVersionId&&version.IsDefaultVersion===true,'LivePolicyVersion');
  return freeze({arn,versionId:version.VersionId,document:doc(version.Document)});
}

/** The request is only a claim. It must equal the reviewed document for this
 * owner's account, the checkout's application region and the document's own
 * revision, and the live default version must equal both. */
export function gatewaySourceBrokerContract(request,{accountId,applicationRegion}){
  const revisions=Array.isArray(request.document?.Statement)?request.document.Statement.filter(s=>typeof s?.Sid==='string'&&/^Gr[0-9]{1,20}$/.test(s.Sid)):[];
  need(revisions.length===1,'RequestedRevision');
  need(request.region===applicationRegion,'RequestedRegion');
  const contract=freeze({partition:'aws',accountId,applicationRegion,policyRevision:revisions[0].Sid.slice(1)});
  const expected=expectedGatewayBoundaryPolicyDocument(contract);
  need(hash(request.document)===hash(expected)&&isDeepStrictEqual(request.document,expected),'RequestedDocument');
  return {contract,expected};
}
export function verifyLiveGatewayBoundary(live,{request,expected}){
  need(live.versionId===request.policyVersion,'LiveVersionMismatch');
  need(hash(live.document)===hash(expected)&&isDeepStrictEqual(live.document,expected),'LiveDocumentMismatch');
}

export function parseGatewaySourceBrokerRequest(body){
  need(Buffer.isBuffer(body)&&body.length>0&&body.length<=L.maximumFrameBytes,'RequestSize');
  let value;try{value=JSON.parse(body.toString('utf8'));}catch{need(false,'RequestJson');}
  need(Buffer.from(JSON.stringify(value)).equals(body)&&exact(value,['version','id','argv'])&&value.version===1&&
    typeof value.id==='string'&&/^[a-f0-9]{32}$/.test(value.id),'Request');
  const a=value.argv;
  const fail=why=>Object.assign(Error('GatewaySourceBroker'+why),{requestId:value.id});
  if(!(Array.isArray(a)&&a.length===8&&a.every(x=>typeof x==='string')&&a[0]==='gateway-runtime'&&a[1]==='verify-source'&&
    a[2]==='--boundary-document'&&a[4]==='--policy-version'&&a[6]==='--region'&&/^v[1-9][0-9]*$/.test(a[5])&&/^[a-z]{2}-[a-z]+-\d$/.test(a[7])))throw fail('RequestArguments');
  let document;try{document=JSON.parse(a[3]);}catch{throw fail('RequestDocument');}
  if(!(document&&typeof document==='object'&&!Array.isArray(document)&&JSON.stringify(document)===a[3]))throw fail('RequestDocument');
  return freeze({id:value.id,document,policyVersion:a[5],region:a[7]});
}
export function encodeGatewaySourceBrokerFrame(value){
  const body=Buffer.from(JSON.stringify(value));need(body.length>0&&body.length<=L.maximumFrameBytes,'ResponseSize');
  const frame=Buffer.alloc(body.length+4);frame.writeUInt32BE(body.length);body.copy(frame,4);return frame;
}
export function gatewaySourceBrokerResponse(id,status,receipt){
  return {version:1,id,status,stdout:status===STATUS.receipt?Buffer.from(JSON.stringify(receipt)).toString('base64'):'',stderr:''};
}
/** Exactly one length-prefixed frame; a trailing byte, oversize or slow writer is rejected. */
export function readGatewaySourceBrokerFrame(socket,{timeoutMs=L.requestReadMs}={}){
  return new Promise((resolve,reject)=>{
    const chunks=[];let size=0,settled=false;
    const finish=(error,value)=>{if(settled)return;settled=true;clearTimeout(timer);socket.off('data',data);socket.off('end',ended);socket.off('close',ended);error?reject(error):resolve(value);};
    const timer=setTimeout(()=>finish(Error('GatewaySourceBrokerRequestTimeout')),timeoutMs);
    const ended=()=>finish(Error('GatewaySourceBrokerRequestIncomplete'));
    const data=chunk=>{
      size+=chunk.length;if(size>L.maximumFrameBytes+4)return finish(Error('GatewaySourceBrokerRequestSize'));
      chunks.push(chunk);const wire=Buffer.concat(chunks);if(wire.length<4)return;
      const length=wire.readUInt32BE(0);if(length===0||length>L.maximumFrameBytes)return finish(Error('GatewaySourceBrokerRequestSize'));
      if(wire.length>length+4)return finish(Error('GatewaySourceBrokerRequestTrailing'));
      if(wire.length===length+4)finish(null,wire.subarray(4));
    };
    socket.on('data',data);socket.once('end',ended);socket.once('close',ended);
  });
}

/** Append-only private journal for lifecycle, session-policy and diagnostic records. */
async function openJournal(path){
  const handle=await open(path,'wx',0o600);let bytes=0,tail=Promise.resolve(),closed=false;
  const append=value=>{
    const run=tail.then(async()=>{
      need(!closed,'JournalClosed');
      const line=Buffer.from(JSON.stringify({at:new Date().toISOString(),...value})+'\n');
      need(bytes+line.length<=L.journalBytes,'JournalFull');bytes+=line.length;
      await handle.write(line);await handle.sync();
    });
    tail=run.catch(()=>{});return run;
  };
  return {append,async close(){await tail;closed=true;await handle.close();}};
}
async function writePrivateJson(path,value){await writeFile(path,JSON.stringify(value,null,1)+'\n',{mode:0o600,flag:'wx'});}

/** Scoped STS sessions of the operator role, issued with the owner's
 * credentials. The operator cannot assume anything, so a lane cannot renew
 * itself; its session policy narrows it further. Each lane has its own private
 * config/credentials files and a session policy; the adapter's environment
 * check rejects ambient keys, metadata credentials and endpoint overrides. */
export function createGatewayCanarySessions({call,ownerEnvironment,operator,region,directory,verificationId,signal,tags=null,now=Date.now}){
  const lanes=new Map();
  async function issue(lane,restriction,{attempts=1}={}){
    need(LANES.includes(lane)&&!lanes.has(lane),'SessionLane');
    need(exact(restriction,['Policy'])&&typeof restriction.Policy==='string'||exact(restriction,['PolicyArns'])&&restriction.PolicyArns.length===1,'SessionRestriction');
    const sessionName=`mem9-gateway-${lane}-${verificationId}`;
    let response;
    for(let i=0;;i++){
      try{response=await call(ownerEnvironment,'sts','assume-role',{RoleArn:operator.roleArn,RoleSessionName:sessionName,DurationSeconds:L.sessionSeconds,...restriction,...(tags?{Tags:tags}:{})},{directory,signal});break;}
      // A just-created managed session policy can lag in STS. Issuance is not a
      // resource mutation; retry only that, never a provisioning call.
      catch(error){if(i+1>=attempts)throw error;await sleep(L.propagationDelayMs,undefined,{signal});}
    }
    const c=response?.Credentials,expires=Date.parse(c?.Expiration);
    need(/^ASIA[A-Z0-9]{16}$/.test(c?.AccessKeyId??'')&&typeof c.SecretAccessKey==='string'&&/^[A-Za-z0-9/+=]{40}$/.test(c.SecretAccessKey)&&
      typeof c.SessionToken==='string'&&c.SessionToken.length>0&&!/[\s]/.test(c.SessionToken)&&Number.isFinite(expires)&&expires>now()+L.sessionMarginMs,'SessionCredentials');
    need(response.AssumedRoleUser?.Arn===`arn:aws:sts::${operator.accountId}:assumed-role/${operator.roleName}/${sessionName}`,'SessionIdentity');
    const home=await childDirectory(directory,lane),config=join(home,'config'),credentials=join(home,'credentials');
    await writeFile(config,`[profile cc-tracked]\nregion = ${region}\n`,{mode:0o600,flag:'wx'});
    await writeFile(credentials,`[cc-tracked]\naws_access_key_id = ${c.AccessKeyId}\naws_secret_access_key = ${c.SecretAccessKey}\naws_session_token = ${c.SessionToken}\n`,{mode:0o600,flag:'wx'});
    const files=await Promise.all([config,credentials].map(async path=>({path,ino:(await lstat(path)).ino})));
    lanes.set(lane,freeze({expires,files,environment:{PATH:process.env.PATH??'/usr/bin:/bin',HOME:home,LC_ALL:'C',
      AWS_PROFILE:'cc-tracked',AWS_CONFIG_FILE:config,AWS_SHARED_CREDENTIALS_FILE:credentials,AWS_EC2_METADATA_DISABLED:'true',
      AWS_MAX_ATTEMPTS:'1',AWS_RETRY_MODE:'standard',AWS_PAGER:'',AWS_CLI_AUTO_PROMPT:'off'}}));
  }
  return Object.freeze({
    issue,
    async check(){
      need(lanes.size>0,'SessionMissing');
      for(const lane of lanes.values()){
        need(now()<lane.expires-L.sessionMarginMs,'SessionExpiring');
        for(const file of lane.files){const s=await lstat(file.path);need(s.isFile()&&s.ino===file.ino&&s.uid===process.getuid()&&(s.mode&0o777)===0o600,'SessionFileChanged');}
      }
    },
    async environment(lane){need(lanes.has(lane),'SessionLane');return lanes.get(lane).environment;},
    // Every lane directory, including one whose issuance failed half-written.
    async destroy(){lanes.clear();await rm(directory,{recursive:true,force:true});},
  });
}

/** withGatewayCanaryProvisioningPolicy's adapter over the bootstrap lane only.
 * It takes no request signal: deleting the policy is cleanup and must still run
 * after a cancelled request. Each call is bounded by the command timeout. */
export function createGatewayCanarySessionPolicyOps({call,sessions,directory}){
  const iam=async(operation,body)=>call(await sessions.environment('bootstrap'),'iam',operation,body,{directory});
  async function read(arn){
    let policy;
    try{policy=(await iam('get-policy',{PolicyArn:arn})).Policy;}
    catch(error){if(serviceErrorCode(error,'GetPolicy')==='NoSuchEntity')return null;throw error;}
    need(policy?.Arn===arn,'SessionPolicyRead');
    const versions=await iam('list-policy-versions',{PolicyArn:arn});need(!versions.IsTruncated&&Array.isArray(versions.Versions),'SessionPolicyRead');
    const version=(await iam('get-policy-version',{PolicyArn:arn,VersionId:policy.DefaultVersionId})).PolicyVersion;
    need(version?.VersionId===policy.DefaultVersionId,'SessionPolicyRead');
    const tags=await iam('list-policy-tags',{PolicyArn:arn});need(!tags.IsTruncated&&Array.isArray(tags.Tags),'SessionPolicyRead');
    const entities=await iam('list-entities-for-policy',{PolicyArn:arn});need(!entities.IsTruncated,'SessionPolicyRead');
    const listed=['PolicyGroups','PolicyUsers','PolicyRoles'].reduce((n,k)=>n+(Array.isArray(entities[k])?entities[k].length:Number.NaN),0);
    return {arn,policyId:policy.PolicyId,defaultVersionId:policy.DefaultVersionId,versions:versions.Versions.map(v=>v.VersionId),document:doc(version.Document),
      tags:tags.Tags,attachmentCount:Math.max(policy.AttachmentCount,listed),boundaryUsageCount:policy.PermissionsBoundaryUsageCount};
  }
  // IAM reads are eventually consistent. Wait for the create/delete to become
  // visible here, so the caller's single readback sees the settled state.
  async function settle(arn,present){
    for(let i=0;i<L.propagationAttempts;i++){
      try{if((await read(arn)!==null)===present)return;}catch{}
      await sleep(L.propagationDelayMs);
    }
    need(false,present?'SessionPolicyNotVisible':'SessionPolicyStillVisible');
  }
  return Object.freeze({
    async assertSessionPolicyAbsent({PolicyArn}){need(await read(PolicyArn)===null,'SessionPolicyExists');},
    async createSessionPolicy(body){const created=await iam('create-policy',body);if(created?.Policy?.Arn)await settle(created.Policy.Arn,true);return created;},
    readSessionPolicy:({PolicyArn})=>read(PolicyArn),
    async deleteSessionPolicy({PolicyArn}){await iam('delete-policy',{PolicyArn});await settle(PolicyArn,false);},
  });
}

/** Lifecycle verifyPhase over the adapter's raw round: rebuild the phase
 * evidence the evidence verifier defines from the exact invoked payload. */
export function verifyGatewayCanaryRound(round,context){
  need(exact(round,['phase','before','invoke','after'])&&round.phase===context.phase,'Round');
  const request=JSON.parse(Buffer.from(round.invoke?.request?.Payload??'','base64').toString('utf8'));
  const validation=verifyGatewayCanaryPhase({version:1,kind:'gateway-runtime-canary-phase',request,invoke:round.invoke},context);
  return {validation,round};
}

/** Full native canary for one live boundary version. Returns the adapter's
 * inspected material only when the lifecycle and session policy both closed;
 * otherwise the outcome carries everything retained for recovery. */
/** The top-level plan fields (and template resources) that differ from the
 * reviewed rendering, compared as serialized JSON, so key order counts. */
export function gatewayCanaryPlanDifference(plan,reviewed){
  const fields=Object.keys(reviewed).filter(k=>JSON.stringify(plan[k])!==JSON.stringify(reviewed[k]));
  const resources=Object.keys(reviewed.template.Resources).filter(k=>JSON.stringify(plan.template?.Resources?.[k])!==JSON.stringify(reviewed.template.Resources[k]));
  return 'differs: '+[...fields,...resources.map(r=>'Resources.'+r)].join(', ');
}
export async function runNativeGatewayCanary({call,ownerEnvironment,operator,region,vpcId,live,reviewed,source,awsExecutable,directory,journal,signal,sessionTags=null,log=()=>{},verificationId=randomBytes(6).toString('hex')}){
  // The canary's key administrator and encrypter is the operator role its lanes run as.
  const scope=compileGatewayRuntimeCanaryScope({accountId:operator.accountId,applicationRegion:region,verificationId,vpcId,ownerRoleArn:operator.roleArn});
  // Render from the reviewed document, which the live one was verified to equal.
  // IAM returns the same statements with its own key order, and the plan's
  // template body is a serialization: the lifecycle re-renders from the
  // reviewed document and requires byte equality. The canary still attaches
  // and reads the live policy itself.
  need(hash(live.document)===hash(reviewed)&&isDeepStrictEqual(live.document,reviewed),'LiveDocumentMismatch');
  const plan=renderGatewayRuntimeCanaryTemplate({scope,originalBoundary:reviewed,handlerSource:source.handlerSource});
  // The lifecycle's own plan check, before any session or mutation.
  try{verifyGatewayRuntimeCanaryPlan(plan);}
  catch{throw Object.assign(Error('GatewaySourceBrokerPlanChanged'),{detail:gatewayCanaryPlanDifference(plan,renderGatewayRuntimeCanaryTemplate({scope,originalBoundary:reviewed,handlerSource:source.handlerSource}))});}
  const policies=buildGatewayCanaryOperatorPolicies(scope);
  const sessionsDirectory=await childDirectory(directory,'sessions'),work=await childDirectory(directory,'work');
  const sessions=createGatewayCanarySessions({call,ownerEnvironment,operator,region,directory:sessionsDirectory,verificationId,signal,
    tags:sessionTags?.mode==='explicit'?sessionTags.tags:null});
  const record=value=>journal.append({source:'lifecycle',...value});
  let ops,lifecycle=null,sessionPolicy=null,thrown=null,retained=false,provisionFailure=null;
  await journal.append({source:'broker',event:'canary-start',verificationId,stackName:scope.stackName,templateHash:plan.templateHash,
    provisionPolicyHash:policies.provisionHash,observePolicyHash:policies.observeHash,boundaryVersion:live.versionId});
  // Runs inside the provisioning restriction. Anything that fails before the
  // lifecycle starts has created no canary resource, so cleanup is complete.
  async function provisionAndRun(restriction){
    try{
      need(!restriction.PolicyArns||restriction.maximumDurationSeconds>=L.sessionSeconds,'SessionRestriction');
      await sessions.issue('provision',restriction.PolicyArns?{PolicyArns:restriction.PolicyArns}:restriction,{attempts:restriction.PolicyArns?L.propagationAttempts:1});
      ops=await createGatewayCanaryAwsAdapter({plan,sessions,directory:work,awsExecutable,recordPhaseDiagnostic:value=>journal.append({source:'diagnostic',...value})});
    }catch(error){provisionFailure=describe(gatewaySourceBrokerReason(error),error);await journal.append({source:'broker',event:'provision-session-failed',reason:gatewaySourceBrokerReason(error),awsDetail:gatewaySourceBrokerAwsDetail(error)});return {cleanupComplete:true,started:false};}
    // The lifecycle sees a forwarding view of the adapter, to learn whether any
    // operation ran. The original stays the one the evidence getter inspects.
    let touched=false;
    const tracked=Object.freeze(Object.fromEntries(Object.entries(ops).map(([k,f])=>[k,(...a)=>{touched=true;return f(...a);}])));
    try{lifecycle=await runGatewayRuntimeCanaryLifecycle({plan,ops:tracked,record,verifyPhase:verifyGatewayCanaryRound,signal});}
    catch(error){
      // A throw before any adapter operation created nothing: cleanup is
      // complete and the session policy is deleted. After one, hold.
      thrown=gatewaySourceBrokerReason(error);
      await journal.append({source:'broker',event:'lifecycle-threw',reason:thrown,detail:detailOf(error),touchedAws:touched});
      log(`lifecycle threw (${describe(thrown,error)}) ${touched?'after':'before'} any AWS operation`);
      return {cleanupComplete:!touched,started:touched};
    }
    return {cleanupComplete:lifecycle.cleanupComplete===true&&lifecycle.cleanupUnconfirmed!==true,started:true};
  }
  try{
    await sessions.issue('observe',{Policy:JSON.stringify(policies.observe)});
    if(policies.requiresManagedProvisionPolicy){
      const bootstrap=buildGatewayCanarySessionPolicyBootstrap(scope);
      await sessions.issue('bootstrap',{Policy:bootstrap.policyJson});
      sessionPolicy=await withGatewayCanaryProvisioningPolicy({scope,ops:createGatewayCanarySessionPolicyOps({call,sessions,directory:sessionsDirectory}),
        record:value=>journal.append({source:'session-policy',...value}),run:provisionAndRun});
    }else{
      const result=await provisionAndRun({Policy:JSON.stringify(policies.provision)});
      sessionPolicy={status:result.cleanupComplete?'CLOSED':'HELD',cleanupComplete:result.cleanupComplete,reason:null,policyArn:null};
    }
  }finally{
    // Credential files that cannot be removed are retained secrets: hold.
    try{await sessions.destroy();}catch{retained=true;}
  }
  const closed=sessionPolicy?.status==='CLOSED'&&sessionPolicy.cleanupComplete===true;
  const complete=closed&&lifecycle?.status==='OBSERVATIONS_COMPLETE'&&lifecycle.cleanupComplete===true;
  const held=retained||!closed||lifecycle!==null&&lifecycle.cleanupComplete!==true;
  const outcome={verificationId,scope,status:complete&&!retained?'OBSERVATIONS_COMPLETE':held?'HELD':'FAILED',
    reason:(retained?'GatewaySourceBrokerSessionFilesRetained':null)??lifecycle?.reason??thrown??sessionPolicy?.reason??(lifecycle?null:'GatewaySourceBrokerCanaryNotStarted'),
    sessionPolicy:sessionPolicy&&{status:sessionPolicy.status,policyArn:sessionPolicy.policyArn,policyId:sessionPolicy.policyId??null,cleanupComplete:sessionPolicy.cleanupComplete,reason:sessionPolicy.reason},
    lifecycle,...(provisionFailure?{provisionFailure}:{})};
  if(provisionFailure)log(`provision lane not issued (${provisionFailure})`);
  let material=null;
  if(outcome.status==='OBSERVATIONS_COMPLETE')try{material=inspectGatewayCanaryAwsEvidence(ops);}catch(error){outcome.status='FAILED';outcome.reason=gatewaySourceBrokerReason(error);}
  return {outcome,material};
}

/** The Gateway statements with the revision label removed. The Gr<rev> Sid
 * names a revision and takes no part in evaluation; every other byte counts. */
export function gatewayBoundaryStatementsHash(document){
  const revisions=Array.isArray(document?.Statement)?document.Statement.filter(s=>typeof s?.Sid==='string'&&/^Gr[0-9]{1,20}$/.test(s.Sid)):[];
  need(revisions.length===1,'RequestedRevision');
  return hash({...document,Statement:document.Statement.map(s=>revisions.includes(s)?{...s,Sid:'G'}:s)});
}

/** Run once before the socket exists: the canary against the live boundary,
 * which must already be the reviewed document at its own revision. Returns the
 * verified statements and the receipt the source gate derives from the native
 * material; nothing here is caller-selected. */
export async function establishGatewayRuntimeSourceEvidence(context,{signal}={}){
  const {call,ownerEnvironment,source,owner,operator,region,vpcId,awsExecutable,evidenceRoot,sessionTags=null,log=()=>{}}=context;
  const directory=await privateDirectory(await mkdtemp(join(evidenceRoot,new Date().toISOString().replaceAll(':','').replace(/\.\d+Z$/,'Z')+'-')));
  const journal=await openJournal(join(directory,'journal.jsonl'));
  const summary={version:1,kind:'gateway-source-broker-canary',source:{commit:source.commit,tree:source.tree},status:'FAILED',reason:null};
  log(`canary evidence in ${directory}`);
  try{
    const live=await readLiveGatewayBoundary({call,environment:ownerEnvironment,directory,signal,accountId:owner.accountId});
    // The canary attaches the live policy itself in phase B. Statements that are
    // not live yet cannot be exercised; the rollout writes them first.
    let contract,expected;
    try{({contract,expected}=gatewaySourceBrokerContract({document:live.document,region},{accountId:owner.accountId,applicationRegion:region}));}
    catch{need(false,'LiveNotReviewed');}
    summary.policyVersion=live.versionId;summary.policyRevision=contract.policyRevision;
    await journal.append({source:'broker',event:'live-verified',contract,boundaryVersion:live.versionId,policyHash:hash(live.document)});
    const {outcome,material}=await runNativeGatewayCanary({call,ownerEnvironment,operator,region,vpcId,live,reviewed:expected,source,awsExecutable,directory,journal,signal,sessionTags,log});
    summary.verificationId=outcome.verificationId;summary.status=outcome.status;summary.reason=outcome.reason;
    if(outcome.status==='HELD')log(`canary HELD (${outcome.reason}); canary stack ${outcome.scope.stackName} and session policy ${outcome.sessionPolicy?.policyArn??'(none)'} need owner review before any retry`);
    await writePrivateJson(join(directory,'canary-outcome.json'),outcome);
    need(material,'CanaryIncomplete');
    await writePrivateJson(join(directory,'evidence.json'),material);
    const after=await readLiveGatewayBoundary({call,environment:ownerEnvironment,directory,signal,accountId:owner.accountId});
    need(after.versionId===live.versionId&&hash(after.document)===hash(live.document),'BoundaryChangedDuringCanary');
    const receipt=verifyGatewayRuntimeSourceMaterial(material,{boundary:live.document,contract,policyVersion:live.versionId,handlerSource:source.handlerSource,source:{commit:source.commit,tree:source.tree}});
    await writePrivateJson(join(directory,'receipt.json'),receipt);
    summary.status='VERIFIED';
    return freeze({receipt,statementsHash:gatewayBoundaryStatementsHash(live.document),directory});
  }catch(error){
    summary.reason??=gatewaySourceBrokerReason(error);if(summary.status!=='HELD')summary.status='FAILED';
    summary.awsDetail=gatewaySourceBrokerAwsDetail(error);summary.detail=gatewaySourceBrokerDetail(error);
    throw Object.assign(Error(summary.reason),{held:summary.status==='HELD'},summary.awsDetail?{awsDetail:summary.awsDetail}:{},summary.detail?{detail:summary.detail}:{});
  }finally{
    // The terminal line below stays the record when a private write fails.
    await journal.append({source:'broker',event:'canary-complete',status:summary.status,reason:summary.reason,awsDetail:summary.awsDetail??null,detail:summary.detail??null}).catch(()=>log('journal write failed'));
    await journal.close().catch(()=>log('journal close failed'));
    await writePrivateJson(join(directory,'outcome.json'),summary).catch(()=>log('outcome write failed'));
    const detail=summary.awsDetail??summary.detail;
    log(`canary ${summary.status}${summary.reason?' ('+summary.reason+(detail?'; '+detail:'')+')':''}`);
  }
}

/** One verify-source request against the startup evidence. No AWS mutation:
 * a fresh owner identity and live-boundary read, then a receipt for the exact
 * requested document. Throws (no receipt) on any doubt. */
export async function answerGatewayRuntimeSourceRequest(context,verified,request,{signal}={}){
  const {call,ownerEnvironment,source,owner,region,repoRoot,gitExecutable,journal}=context;
  const record={source:'request',requestId:request.id,policyVersion:request.policyVersion,status:'FAILED',reason:null};
  try{
    const current=await readGatewayCanaryCheckoutSource({repoRoot,gitExecutable,signal});
    need(current.commit===source.commit&&current.tree===source.tree&&current.handlerSource===source.handlerSource,'CheckoutChanged');
    // One STS call keeps the request inside the client's 15 s limit.
    const caller=await readGatewaySourceBrokerCaller({call,environment:ownerEnvironment,directory:context.directory,signal});
    need(caller.accountId===owner.accountId&&caller.roleName===owner.roleName,'OwnerChanged');
    const {contract,expected}=gatewaySourceBrokerContract(request,{accountId:owner.accountId,applicationRegion:region});
    record.policyRevision=contract.policyRevision;
    const live=await readLiveGatewayBoundary({call,environment:ownerEnvironment,directory:context.directory,signal,accountId:owner.accountId});
    verifyLiveGatewayBoundary(live,{request,expected});
    need(gatewayBoundaryStatementsHash(live.document)===verified.statementsHash,'StatementsNotVerified');
    // The same exercised statements at the requested revision and version.
    const receipt=freeze({...verified.receipt,source:{...verified.receipt.source},coverage:[...verified.receipt.coverage],policyHash:hash(live.document),policyVersion:live.versionId});
    // An unrecorded receipt is never issued: the journal write gates it.
    try{await journal.append({...record,status:'RECEIPT_ISSUED',policyHash:receipt.policyHash});}catch{need(false,'JournalWriteFailed');}
    record.status='RECEIPT_ISSUED';
    return receipt;
  }catch(error){
    record.reason=gatewaySourceBrokerReason(error);
    if(gatewaySourceBrokerAwsDetail(error))record.awsDetail=gatewaySourceBrokerAwsDetail(error);
    if(record.reason!=='GatewaySourceBrokerJournalWriteFailed')await journal.append(record).catch(()=>{record.reason+=' [journal write failed]';});
    throw Object.assign(Error(record.reason),{recorded:true});
  }finally{context.log?.(`request ${request.id}: ${record.status}${record.reason?' ('+record.reason+(record.awsDetail?'; '+record.awsDetail:'')+')':''}`);}
}

/** CLI status after serving: 1 when any request got no receipt, else 0 (3 is
 * reserved for HELD; only the startup canary can hold, and start throws it). */
export const gatewaySourceBrokerExitCode=requests=>requests.some(r=>r.status==='HELD')?3:requests.some(r=>r.status!=='RECEIPT_ISSUED')?1:0;

/** Start the broker: the canary first, then the socket. It serves at most
 * maxRequests verify-source requests, strictly one at a time, until its
 * deadline, then removes its socket. A failed canary publishes nothing. */
export async function startGatewayRuntimeSourceBroker(options){
  need(options&&Object.keys(options).every(k=>['repoRoot','awsExecutable','gitExecutable','evidenceRoot','socketParent','deadlineMs','maxRequests','environment','log','signal'].includes(k)),'Options');
  const {repoRoot,awsExecutable,gitExecutable,evidenceRoot,socketParent,deadlineMs=L.defaultDeadlineMs,maxRequests=L.maximumRequests,environment=process.env,log=()=>{},signal}=options;
  need(Number.isSafeInteger(deadlineMs)&&deadlineMs>0&&deadlineMs<=L.maximumDeadlineMs&&Number.isSafeInteger(maxRequests)&&maxRequests>=1&&maxRequests<=L.maximumRequests,'Limits');
  need(isAbsolute(awsExecutable??'')&&isAbsolute(gitExecutable??'')&&isAbsolute(socketParent??''),'Paths');
  const source=await readGatewayCanaryCheckoutSource({repoRoot,gitExecutable,signal});
  const region=await resolveApplicationRegion({configPath:join(source.repoRoot,'sst.config.ts')});
  need(/^[a-z]{2}-[a-z]+-\d$/.test(region),'ApplicationRegion');
  // The owner check excludes SCPs and RCPs only on this explicit acknowledgement.
  need(gatewayCanaryOrganizationPoliciesAcknowledged(environment),'OrgPoliciesNotAcknowledged');
  const ownerEnvironment=gatewaySourceBrokerOwnerEnvironment(environment),sessionTags=gatewaySourceBrokerSessionTags(environment);
  const evidence=await privateDirectory(evidenceRoot,{create:true});
  const socketDirectory=await privateDirectory(await mkdtemp(join(await realpath(socketParent),'mem9-gw-')));
  const call=createGatewaySourceBrokerAwsCli({awsExecutable,region});
  let server,timer,journal;
  try{
    // Checked before the canary spends minutes and AWS resources.
    const socketPath=join(socketDirectory,'broker.sock');need(Buffer.byteLength(socketPath)<104,'SocketPath');
    const owner=await resolveGatewaySourceBrokerOwner({call,environment:ownerEnvironment,directory:socketDirectory,signal});
    const {sessionName}=await readGatewaySourceBrokerCaller({call,environment:ownerEnvironment,directory:socketDirectory,signal});
    for(const warning of gatewaySourceBrokerOwnerSessionWarnings({owner,sessionName}))log('warning: '+warning);
    const operator=await resolveGatewayCanaryOperator({call,environment:ownerEnvironment,directory:socketDirectory,signal,owner,region,tags:sessionTags?.tags??null,log});
    if(sessionTags)log(`lane session tags: ${sessionTags.mode} (${sessionTags.mode==='transitive'?'forwarded from the calling session':'passed on each AssumeRole'})`);
    const vpcId=await resolveGatewaySourceBrokerVpc({call,environment:ownerEnvironment,directory:socketDirectory,signal,configuredVpcId:environment.MEM9_VPC_ID});
    const verified=await establishGatewayRuntimeSourceEvidence({call,ownerEnvironment,source,owner,operator,region,vpcId,awsExecutable,evidenceRoot:evidence,sessionTags,log},{signal});
    signal?.throwIfAborted();
    journal=await openJournal(join(verified.directory,'requests.jsonl'));
    const context=freeze({call,ownerEnvironment,source,owner,region,log,repoRoot:source.repoRoot,gitExecutable,journal,directory:socketDirectory});
    const results=[],sockets=new Set(),shutdown=new AbortController();let active=null,accepted=0,closing=false,resolveClosed;
    const closed=new Promise(resolve=>{resolveClosed=resolve;});
    server=net.createServer({allowHalfOpen:false},socket=>{
      socket.on('error',()=>{});
      if(closing||active||accepted>=maxRequests){socket.destroy();return;}
      sockets.add(socket);socket.once('close',()=>sockets.delete(socket));
      active=serve(socket).catch(error=>log(`request handling failed (${gatewaySourceBrokerReason(error)})`)).finally(()=>{active=null;if(accepted>=maxRequests)close();});
    });
    async function serve(socket){
      let request;
      try{request=parseGatewaySourceBrokerRequest(await readGatewaySourceBrokerFrame(socket));}
      catch(error){
        if(error?.requestId)socket.end(encodeGatewaySourceBrokerFrame(gatewaySourceBrokerResponse(error.requestId,STATUS.request)));else socket.destroy();
        log(`rejected malformed request (${gatewaySourceBrokerReason(error)})`);return;
      }
      accepted++;
      const disconnected=new AbortController();socket.once('close',()=>disconnected.abort());
      const requestSignal=AbortSignal.any([disconnected.signal,shutdown.signal]);
      let status=STATUS.failed,receipt;
      try{receipt=await answerGatewayRuntimeSourceRequest(context,verified,request,{signal:requestSignal});status=STATUS.receipt;}
      catch(error){if(!error?.recorded)log(`request ${request.id}: FAILED (${describe(gatewaySourceBrokerReason(error),error)})`);}
      results.push({id:request.id,status:status===STATUS.receipt?'RECEIPT_ISSUED':'FAILED'});
      if(!socket.destroyed){socket.end(encodeGatewaySourceBrokerFrame(gatewaySourceBrokerResponse(request.id,status,receipt)));socket.setTimeout(L.requestReadMs,()=>socket.destroy());}
    }
    async function close({abort=false}={}){
      if(abort)shutdown.abort();
      if(closing)return closed;closing=true;clearTimeout(timer);
      try{
        const stopped=new Promise(resolve=>server.close(()=>resolve()));
        await active;for(const socket of sockets)socket.destroy();await stopped;
        await unlink(socketPath).catch(()=>{});await rm(socketDirectory,{recursive:true,force:true});
      }catch(error){log(`socket cleanup failed (${error?.code??'unknown'}); remove ${socketDirectory}`);}
      finally{await journal.close().catch(()=>log('request journal close failed'));resolveClosed(freeze({requests:results.slice()}));}
      return closed;
    }
    timer=setTimeout(()=>{log('deadline reached; no new requests are accepted');close();},deadlineMs);
    await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(socketPath,resolve);});
    await chmod(socketPath,0o600);
    const stat=await lstat(socketPath);need(stat.isSocket()&&stat.uid===process.getuid()&&(stat.mode&0o777)===0o600&&await realpath(socketPath)===socketPath,'SocketPermissions');
    return Object.freeze({socketPath,source:{commit:source.commit,tree:source.tree},owner,operator,region,vpcId,evidenceRoot:evidence,evidenceDirectory:verified.directory,
      receipt:verified.receipt,deadlineAt:Date.now()+deadlineMs,maxRequests,closed,close});
  }catch(error){
    // A cleanup fault must not replace the original error, or its HELD flag.
    clearTimeout(timer);server?.close();await journal?.close().catch(()=>{});
    await rm(socketDirectory,{recursive:true,force:true}).catch(()=>log(`socket cleanup failed; remove ${socketDirectory}`));throw error;
  }
}
