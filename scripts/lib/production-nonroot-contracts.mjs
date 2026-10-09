/**
 * Closed R4/R5 data contracts. These functions validate data, never authenticate
 * an archive, approve a review, mint a permit, or authorize an AWS operation.
 * Adapters must authenticate evidence before supplying independent expectations.
 */
import {createHash} from 'node:crypto';
import {types} from 'node:util';

export const NONROOT_TRANSITION_KIND = 'image-security-nonroot-upgrade';
export const NONROOT_DATA_COMPONENTS = Object.freeze(['llm-proxy','mnemo-server','qwen3-embed']);
export const NONROOT_TASK_KEYS = Object.freeze(['backend','bootstrap','control','executor','fallback','planner','preaudit','promotion','provision','transition']);
export const CONTROL_NODE = '/usr/local/bin/node';
export const NONROOT_LIMITS = Object.freeze({
  version:2,imageCopyLimitsHash:'59a5bf6d08f4e1a787d1f016a320c625fd43bb973bb924d6999427dfcfe71ced',
  maxProofBytes:4194304,maxDescriptorBytes:4096,maxCertificateBytes:6000,maxReviewBytes:8192,
  maxJsonDepth:64,maxTaskKeys:10,maxFieldChanges:96,maxProcessesPerContainer:256,
  maxRuntimeRecordBytes:1048576,maxArtifactObservationAgeMs:300000,maxRootAuditAgeMs:300000,
  maxRootAuditWindowMs:300000,maxReviewLifetimeMs:86400000,maxPreauditTasksPerInvocation:1,
  maxPreauditTasksTotal:8,maxIssuanceOperationMs:1800000,maxLineageRecords:1000,
  maxPreviewEvidenceAgeMs:86400000,maxTargetAuditWindowMs:300000,
  maxOverlapObservationMs:1800000,maxPlannedOutageMs:7200000,
});
export const NONROOT_HARDENING_POLICY = Object.freeze({
  version:2,kind:'ecs-fixed-nonroot-nnp-policy',user:'1000:1000',capabilityAdd:Object.freeze([]),
  capabilityDrop:Object.freeze(['ALL']),privileged:false,applicationNoNewPrivs:1,preserveInit:true,
  preserveRootFilesystem:true,preserveDataBytes:true,preserveOriginalApplicationArgv:true,preserveSecrets:true,
});
export const NONROOT_GUARD_BUILTINS = Object.freeze(['node:fs','node:crypto','node:buffer','node:path','node:process']);
const fail = () => { throw Error('NonrootContractInvalid'); };
const need = condition => { if (!condition) fail(); };
const rawHash = value => createHash('sha256').update(value).digest('hex');
const freeze = value => {
  if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
};

/** Copy only inert JSON data. Never invoke getters, toJSON, or proxy traps. */
function copyJson(value, maxBytes = NONROOT_LIMITS.maxProofBytes) {
  need(Number.isSafeInteger(maxBytes) && maxBytes > 0 && maxBytes <= NONROOT_LIMITS.maxProofBytes);
  let bytes=0, nodes=0;
  const active=new Set();
  const add=n=>{bytes+=n;need(bytes<=maxBytes);};
  const string=v=>{need(v.isWellFormed());add(Buffer.byteLength(JSON.stringify(v)));};
  function copy(v, depth) {
    need(depth<=NONROOT_LIMITS.maxJsonDepth && ++nodes<=100000);
    if (v===null || typeof v==='boolean') {add(v===null?4:v?4:5);return v;}
    if (typeof v==='number') {need(Number.isSafeInteger(v)&&!Object.is(v,-0));add(String(v).length);return v;}
    if (typeof v==='string') {string(v);return v;}
    need(v && typeof v==='object' && !types.isProxy(v) && !active.has(v));
    const array=Array.isArray(v), proto=Object.getPrototypeOf(v);
    need(array?proto===Array.prototype:proto===Object.prototype||proto===null);
    const descriptors=Object.getOwnPropertyDescriptors(v),keys=Reflect.ownKeys(descriptors);
    need(keys.every(k=>typeof k==='string'));
    active.add(v);add(2);
    let result;
    if (array) {
      const length=descriptors.length?.value;
      need(Number.isSafeInteger(length)&&length>=0&&keys.length===length+1);
      result=[];
      for(let i=0;i<length;i++){
        const d=descriptors[String(i)];
        need(d?.enumerable&&Object.hasOwn(d,'value'));
        if(i)add(1);result.push(copy(d.value,depth+1));
      }
    } else {
      result={};
      for(const [i,k] of keys.entries()){
        const d=descriptors[k];need(d.enumerable&&Object.hasOwn(d,'value'));
        if(i)add(1);string(k);add(1);
        Object.defineProperty(result,k,{value:copy(d.value,depth+1),enumerable:true,configurable:true,writable:true});
      }
    }
    active.delete(v);return result;
  }
  return copy(value,0);
}
const canonical=v=>Array.isArray(v)?v.map(canonical):v&&typeof v==='object'
  ?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;
/** Same JSON hash convention as existing canary evidence; not an authority token. */
export const nonrootHash=value=>rawHash(JSON.stringify(canonical(copyJson(value))));
export const NONROOT_LIMITS_HASH = nonrootHash(NONROOT_LIMITS);
/** Immutable inert snapshot, useful for pure adapters handling raw AWS JSON. */
export const copyNonrootJson=value=>freeze(copyJson(value));

/** Duplicate decoded keys must be rejected before JSON.parse loses them. */
export function parseNonrootJson(text, options={}) {
  const o=copyJson(options);need(Object.keys(o).every(k=>k==='maxBytes'));
  const maxBytes=o.maxBytes??NONROOT_LIMITS.maxProofBytes;
  need(Number.isSafeInteger(maxBytes)&&maxBytes>0&&maxBytes<=NONROOT_LIMITS.maxProofBytes);
  need(typeof text==='string'&&text.isWellFormed()&&Buffer.byteLength(text)<=maxBytes);
  let i=0;
  const ws=()=>{while(/[\x20\t\r\n]/.test(text[i]??'!'))i++;};
  const str=()=>{
    const start=i;need(text[i++]==='"');let escape=false;
    while(i<text.length){const c=text[i++];if(!escape&&c==='"')return JSON.parse(text.slice(start,i));if(escape)escape=false;else if(c==='\\')escape=true;}
    fail();
  };
  function scan(depth){
    need(depth<=NONROOT_LIMITS.maxJsonDepth);ws();const c=text[i];
    if(c==='{'){
      i++;ws();const keys=new Set();if(text[i]==='}'){i++;return;}
      while(true){ws();const key=str();need(!keys.has(key));keys.add(key);ws();need(text[i++]===':');scan(depth+1);ws();if(text[i]==='}'){i++;return;}need(text[i++]===',');}
    }
    if(c==='['){i++;ws();if(text[i]===']'){i++;return;}while(true){scan(depth+1);ws();if(text[i]===']'){i++;return;}need(text[i++ ]===',');}}
    if(c==='"'){str();return;}
    const m=/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(i));need(m);i+=m[0].length;
  }
  try{scan(0);ws();need(i===text.length);return freeze(copyJson(JSON.parse(text),maxBytes));}
  catch {fail();}
}

// Validators operate on a previously copied inert tree. No coercion/defaulting.
const text=(max=4096,min=1)=>v=>need(typeof v==='string'&&v.length>=min&&v.isWellFormed()&&!v.includes('\0')&&Buffer.byteLength(v)<=max);
const pattern=re=>v=>{text()(v);need(re.test(v));};
const integer=(min=0,max=Number.MAX_SAFE_INTEGER)=>v=>need(Number.isSafeInteger(v)&&v>=min&&v<=max);
const literal=expected=>v=>need(v===expected);
const oneOf=(...values)=>v=>need(values.includes(v));
const array=(item,min=0,max=1000)=>v=>{need(Array.isArray(v)&&v.length>=min&&v.length<=max);v.forEach(item);};
const object=(fields,check=()=>{})=>v=>{
  need(v&&typeof v==='object'&&!Array.isArray(v));
  need(Object.keys(v).length===Object.keys(fields).length&&Object.keys(fields).every(k=>Object.hasOwn(v,k)));
  for(const [k,validator] of Object.entries(fields))validator(v[k]);
  check(v);
};
const union=(...validators)=>v=>{for(const check of validators){try{check(v);return;}catch{}}fail();};
const schemas=Object.create(null);
const ref=name=>v=>{need(Object.hasOwn(schemas,name));schemas[name](v);};
const define=(name,fields,check)=>{schemas[name]=object(fields,check);};
const H=pattern(/^[a-f0-9]{64}$/),G=pattern(/^[a-f0-9]{40}$/),N=pattern(/^[a-f0-9]{32}$/);
const D=pattern(/^sha256:[a-f0-9]{64}$/),A=pattern(/^\d{12}$/),R=pattern(/^[a-z]{2}(?:-[a-z]+)+-\d$/);
const P=integer(1),Z=integer(),B=oneOf(true,false),S=text(),MS=P;
const ARN=pattern(/^arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^\s*?]+$/);
const ROLE=pattern(/^arn:aws:iam::\d{12}:role\/[A-Za-z0-9+=,.@_/-]+$/);
const TASK=pattern(/^arn:aws:ecs:[a-z0-9-]+:\d{12}:task\/[A-Za-z0-9_-]+\/[a-f0-9]{32}$/);
const TD=pattern(/^arn:aws:ecs:[a-z0-9-]+:\d{12}:task-definition\/[A-Za-z0-9_-]+:[1-9][0-9]*$/);
const CLUSTER=pattern(/^arn:aws:ecs:[a-z0-9-]+:\d{12}:cluster\/[A-Za-z0-9_-]+$/);
const COMPONENT=oneOf(...NONROOT_DATA_COMPONENTS),KEY=oneOf(...NONROOT_TASK_KEYS);
const SAFE_PATH=v=>{text(4096)(v);need(!v.startsWith('/')&&!v.split('/').some(p=>p==='..'||p==='')&&!/[\r\n\\]/.test(v));};
const ABS=v=>{text(4096)(v);need(v.startsWith('/')&&!v.split('/').includes('..')&&!/[\r\n\\]/.test(v));};
const unique=(items,key=x=>x)=>need(new Set(items.map(key)).size===items.length);
const equal=(a,b)=>need(nonrootHash(a)===nonrootHash(b));
const named=(items,names)=>{unique(items,x=>x.name??x.containerName??x.taskKey);equal(items.map(x=>x.name??x.containerName??x.taskKey).sort(),[...names].sort());};
const time=v=>need(v.completedMs>=v.startedMs);
const image=v=>{need(v.rootDigest!==v.arm64Digest&&v.configDigest!==v.rootDigest&&v.configDigest!==v.arm64Digest);};
const ARGV=v=>{array(text(8192,0),0,64)(v);need(Buffer.byteLength(JSON.stringify(v))<=8192);};
const JSON_REF=ref('JsonRef'),BYTE_REF=ref('ByteRef'),IMG=ref('ImageBinding'),CIMG=ref('ControlImageBindingV1');
const hashes=keys=>Object.fromEntries(keys.split(' ').filter(Boolean).map(k=>[k,H]));
const refs=keys=>Object.fromEntries(keys.split(' ').filter(Boolean).map(k=>[k,JSON_REF]));
const clocks={startedMs:MS,completedMs:MS};

define('JsonRef',{bytesHash:H,canonicalHash:H,bytesLength:P});
define('ByteRef',{sha256:H,bytesLength:Z});
schemas.Argv=ARGV;
schemas.PresenceString=union(object({present:literal(false)}),object({present:literal(true),value:text(8192,0)}));
schemas.PresenceArgv=union(object({present:literal(false)}),object({present:literal(true),value:ARGV}));
define('ImageBinding',{rootDigest:D,arm64Digest:D,configDigest:D},image);
define('ControlImageBindingV1',{account:A,region:R,repositoryName:oneOf('mem9-on-aws/bootstrap','mem9-on-aws/preview/bootstrap'),rootDigest:D,arm64Digest:D,configDigest:D},image);
schemas.ImageSet=object(Object.fromEntries(NONROOT_DATA_COMPONENTS.map(c=>[c,IMG])));
schemas.NonrootLimitsV2=v=>equal(v,NONROOT_LIMITS);
schemas.HardeningPolicyV2=v=>equal(v,NONROOT_HARDENING_POLICY);
define('SourceIdentityV1',{revision:G,tree:G,baseRevision:G,sourceEvidence:JSON_REF});
define('SourceFileV1',{path:SAFE_PATH,gitMode:oneOf('100644','100755'),sha256:H,bytes:Z,blob:BYTE_REF},v=>{need(v.bytes===v.blob.bytesLength&&v.sha256===v.blob.sha256);});
define('SourceClosureV1',{version:literal(1),kind:literal('git-file-closure'),tree:G,files:array(ref('SourceFileV1'),0,20000),closureHash:H},v=>{unique(v.files,x=>x.path);need(v.closureHash===nonrootHash(v.files));});
define('DataOriginV1',{revision:G,tree:G,sourceHead:G,...refs('sourceEvidence buildCommit buildRun buildJobs'),buildLog:BYTE_REF,recipeHash:H,images:ref('ImageSet')});
// Deployment-specific values are supplied by an authenticated predecessor, never
// hardcoded as public repository operating data. Equality is checked by adapters.
// receiptSetHash is the original parent canary's ordered [namespace,id,result]
// commitment (replayResultHash). The global population is in conservationHash.
define('RootBindingV1',{stage:literal('prod'),account:A,region:R,runtimeNonce:N,
  ...hashes('schemaDigest operatorDigest rootIdentity generation targetsHash parentProofHash originalBackendBindingHash originalReleaseHash protectedBaselineHash receiptSetHash conservationHash'),
  validationId:N,plannerOid:P,executorOid:P,protectedRows:Z,receipts:integer(1,20),spent:integer(1,19),cap:literal(20)},
  v=>need(v.receipts<=v.spent));
define('PrimitiveEvidenceV1',{version:literal(1),kind:literal('verified-nnp-primitive'),image:IMG,invokedPath:ABS,resolvedPath:ABS,fileSha256:H,mode:literal(493),uid:literal(0),gid:literal(0),...refs('symlinkChain loaderAndLibraries privilegeMetadata featureProbe inheritanceAndNegativeProbes')});
define('RuntimePlatformObservationV1',{version:literal(1),kind:literal('actual-runtime-platform'),taskArn:TASK,taskDefinitionArn:TD,launchType:literal('FARGATE'),platformVersion:pattern(/^[0-9]+\.[0-9]+\.[0-9]+$/),platformFamily:S,cpuArchitecture:literal('ARM64'),operatingSystemFamily:literal('LINUX'),...refs('rawTask rawDefinition independentHealthProbe'),observedMs:MS});
define('NodeRuntimeV1',{version:literal(1),kind:literal('pinned-node-runtime'),versionString:pattern(/^v?24\.[0-9]+\.[0-9]+$/),executablePath:literal(CONTROL_NODE),executableSha256:H,loaderAndNativeLibraries:JSON_REF,image:IMG,inventory:JSON_REF});
const builtinPolicy=v=>equal(v,NONROOT_GUARD_BUILTINS);
define('GuardImportPolicyV1',{version:literal(1),kind:literal('guard-source-import-policy'),allowedBuiltins:builtinPolicy,guardSource:ref('SourceClosureV1'),sourceImportAudit:JSON_REF});
define('GuardModuleImportsV1',{version:literal(1),kind:literal('minimal-guard-imports'),entryModule:BYTE_REF,localGuardFiles:ref('SourceClosureV1'),allowedBuiltins:builtinPolicy,policyHash:H,importAudit:JSON_REF,nodeRuntime:ref('NodeRuntimeV1')});
define('CaBindingV1',{name:literal('NODE_EXTRA_CA_CERTS'),value:oneOf('/app/global-bundle.pem','/bootstrap/global-bundle.pem'),file:BYTE_REF,resolvedPath:ABS,mode:integer(0,4095),uid:literal(0),gid:literal(0),parentPathEvidence:JSON_REF},v=>{need(v.value===v.resolvedPath&&(v.mode&0o022)===0&&(v.mode&0o6000)===0);});
define('EnvironmentGateV1',{version:literal(1),kind:literal('prelaunch-environment-gate'),image:IMG,...hashes('registrationBodyHash overrideHash forbiddenNamesHash'),...refs('imageEnvironment taskEnvironment secretNamesAndReferences overrideEnvironment loaderFileEvidence'),caBindings:array(ref('CaBindingV1'),0,1),checkedMs:MS,result:literal('pass')});
schemas.HealthLaunchV1=union(object({kind:literal('absent')}),object({kind:literal('fixed-health-nnp'),before:ARGV,after:ARGV,originalShell:ref('PresenceArgv'),primitiveEvidence:JSON_REF}));
define('FixedDataLaunchV1',{version:literal(1),kind:literal('fixed-data-nnp-launch'),taskKey:oneOf('backend','planner','executor'),containerName:S,image:IMG,originalEntryPoint:ARGV,originalCommand:ARGV,prefix:ARGV,targetEntryPoint:ARGV,targetCommand:ARGV,workingDirectory:ref('PresenceString'),pathEvidence:JSON_REF,primitiveEvidence:JSON_REF,healthLaunch:ref('HealthLaunchV1')});
const purposes=['bootstrap-runtime-verify','consolidation-control','consolidation-promote','denied-provision','denied-transition','bootstrap-runtime-bootstrap','bootstrap-admin-probe','bootstrap-admin-probe-cleanup','preview-fixture-setup','preview-fixture-pause','preview-fixture-verify-planned','preview-fixture-verify-executed','preview-fixture-verify-repeated','post-runtime-fixture','canary-fixture','bootstrap-schema-seed'];
define('ControlLaunchTemplateV1',{version:literal(1),kind:literal('guard-first-control-launch'),taskKey:KEY,containerName:S,purpose:oneOf(...purposes),entryPoint:ARGV,command:array(S,0,0),dispatcherPath:literal('/bootstrap/nonroot-dispatch.mjs'),dispatcherSha256:H,guardClosure:JSON_REF,originalModule:ref('PresenceString'),originalModuleSha256:ref('PresenceString'),originalArgv:ARGV,permittedOperations:array(S,0,64),primitiveContract:JSON_REF,buildContractKey:literal('deployed-bootstrap')},
 v=>equal(v.entryPoint,['/bin/setpriv','--no-new-privs','--',CONTROL_NODE,v.dispatcherPath,v.purpose]));
define('PreviewLaunchInventoryV1',{version:literal(1),kind:literal('preview-guard-launch-inventory'),sourceTree:G,entries:JSON_REF,tests:JSON_REF});
define('CarrierSourceV1',{repository:pattern(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/),revision:G,tree:G,baseRevision:G,prNumber:P,sourceEvidence:JSON_REF});
define('LegacyHostOriginV1',{kind:literal('historical-host-audit'),...refs('authenticatedArchiveAnchor sourceFiles historicalInvocation priorReview'),exactCode:BYTE_REF,expandedSource:BYTE_REF,codeHash:H,sourceHash:H},v=>{need(v.codeHash===v.exactCode.sha256&&v.sourceHash===v.expandedSource.sha256);});
// A reviewed descendant does not claim its bytes ran in the historical
// invocation. Build/SQL receipts belong to the completed carrier proof.
define('ReviewedHostOriginV2',{version:literal(2),kind:literal('reviewed-derived-host-audit'),ancestor:ref('LegacyHostOriginV1'),...refs('sourceFiles deltaReview derivation'),exactCode:BYTE_REF,expandedSource:BYTE_REF,codeHash:H,sourceHash:H},v=>{need(v.codeHash===v.exactCode.sha256&&v.sourceHash===v.expandedSource.sha256&&v.codeHash!==v.ancestor.codeHash);});
schemas.CarrierHostOrigin=union(ref('LegacyHostOriginV1'),ref('ReviewedHostOriginV2'));
define('LegacyImageOriginV1',{kind:literal('historical-deployed-control'),deployedBinding:JSON_REF,source:ref('SourceIdentityV1'),buildEvidence:JSON_REF,image:CIMG,imageGraph:JSON_REF,effectiveFilesystem:JSON_REF});
define('LegacyFileCopyV1',{sourceKind:oneOf('host','image'),role:oneOf('audit-program','module','package','lockfile','native-addon'),sourcePath:S,destinationPath:ABS,sourceBytes:BYTE_REF,destinationBytes:BYTE_REF,...refs('sourceMetadata destinationMetadata sourceEvidence destinationEvidence')},v=>equal(v.sourceBytes,v.destinationBytes));
const auditNames=['MEM9_SUPERSESSION_ROOT_INPUT','MEM9_SUPERSESSION_ROOT_HASH','MEM9_SUPERSESSION_ROOT_CODE_HASH'];
define('LegacyInvocationV1',{nodeMode:literal('esm-file'),legacyProgramPath:literal('/carrier/legacy-audit.mjs'),logicalArgv:ARGV,inputEncoding:literal('deflate-raw-base64'),inputSchemaSource:BYTE_REF,maximumDecodedInputBytes:literal(32768),requiredEnvironmentNames:v=>equal(v,auditNames),executionTest:JSON_REF});
define('LegacyClosureProofV1',{version:literal(1),kind:literal('byte-authenticated-legacy-closure'),hostOrigin:ref('CarrierHostOrigin'),imageOrigin:ref('LegacyImageOriginV1'),files:array(ref('LegacyFileCopyV1'),1,20000),closureInventory:JSON_REF,sourceBundle:BYTE_REF,destinationImage:CIMG,destinationFilesystem:JSON_REF,logicalInvocation:ref('LegacyInvocationV1'),sourceClosureHash:H,destinationClosureHash:H,verifiedMs:MS},
 v=>{unique(v.files,x=>x.destinationPath);need(v.sourceClosureHash===v.destinationClosureHash);});
const carrierEntry=['/bin/setpriv','--no-new-privs','--',CONTROL_NODE,'/carrier/guard-first.mjs','audit-original-root'];
define('CarrierBuildV1',{version:literal(1),kind:literal('premerge-audit-carrier'),source:ref('CarrierSourceV1'),build:object({revision:G,tree:G,workflowPath:S,runId:P,attempt:P,jobId:P,evidence:JSON_REF}),image:CIMG,secureBase:JSON_REF,legacyClosureProof:ref('LegacyClosureProofV1'),guard:object({path:literal('/carrier/guard-first.mjs'),sha256:H,closure:JSON_REF}),entryPoint:ARGV,command:array(S,0,0),primitiveEvidence:JSON_REF,guardImports:ref('GuardModuleImportsV1'),...refs('codeReview artifactSecurity syntheticTests'),completedMs:MS},
 v=>{equal(v.entryPoint,carrierEntry);need(v.image.repositoryName==='mem9-on-aws/preview/bootstrap'&&v.source.tree===v.build.tree);equal(v.image,v.legacyClosureProof.destinationImage);});
const network=object({awsvpcConfiguration:object({subnets:array(pattern(/^subnet-(?:[a-f0-9]{8}|[a-f0-9]{17})$/),1,16),securityGroups:array(pattern(/^sg-(?:[a-f0-9]{8}|[a-f0-9]{17})$/),1,1),assignPublicIp:literal('DISABLED')},v=>{unique(v.subnets);unique(v.securityGroups);})});
const tags=array(object({key:literal('mem9-supersession-owner'),value:N}),1,1);
define('CarrierRunOverridesV1',{containerOverrides:array(object({name:literal('ControlMem9Bootstrap'),environment:array(object({name:oneOf(...auditNames),value:text(8192)}),3,3)}),1,1)},
 v=>{const e=v.containerOverrides[0].environment;equal(e.map(x=>x.name),auditNames);pattern(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/)(e[0].value);H(e[1].value);H(e[2].value);need(Buffer.byteLength(JSON.stringify(v))<=8192);});
const runFixed={cluster:CLUSTER,count:literal(1),launchType:literal('FARGATE'),platformVersion:pattern(/^[0-9]+\.[0-9]+\.[0-9]+$/),networkConfiguration:network,enableExecuteCommand:literal(false),enableECSManagedTags:literal(false),propagateTags:literal('NONE'),tags};
define('CarrierRunTaskContractV1',{version:literal(1),kind:literal('carrier-runtask-contract'),...runFixed,taskDefinitionSource:literal('exact-carrier-registration-readback'),clientTokenSource:literal('permit-invocation'),startedByRule:literal('root-prefix-invocation-first-29'),overridesSource:literal('exact-carrier-overrides')});
define('CarrierRunTaskRequestV1',{...runFixed,taskDefinition:TD,clientToken:N,startedBy:S,overrides:ref('CarrierRunOverridesV1')},
 v=>{need(v.startedBy==='root-'+v.clientToken.slice(0,29));need(v.cluster.split(':').slice(0,5).join(':')===v.taskDefinition.split(':').slice(0,5).join(':'));});
define('CarrierRunTaskBindingV1',{version:literal(1),kind:literal('permit-bound-carrier-runtask'),request:ref('CarrierRunTaskRequestV1'),...hashes('requestHash launchPlanHash runTaskContractHash registrationReadbackHash environmentGateHash carrierPresenceHash'),authorization:object({...hashes('permissionsDossierHash requestHash'),callerArn:ARN,action:literal('ecs:RunTask'),taskDefinitionArn:TD,clusterArn:CLUSTER,taskRoleArn:ROLE,executionRoleArn:ROLE,decision:literal('allowed')})},
 v=>{need(v.requestHash===nonrootHash(v.request)&&v.authorization.requestHash===v.requestHash&&v.authorization.taskDefinitionArn===v.request.taskDefinition&&v.authorization.clusterArn===v.request.cluster);});
define('PreauditLaunchPlanV1',{version:literal(1),kind:literal('standalone-preaudit-launch-plan'),owner:N,account:A,region:R,...hashes('carrierBuildHash legacyClosureProofHash guardImportsHash environmentPolicyHash'),carrierImage:CIMG,existingControlBinding:JSON_REF,registrationBody:JSON_REF,containerName:literal('ControlMem9Bootstrap'),entryPoint:ARGV,command:array(S,0,0),taskRoleArn:ROLE,executionRoleArn:ROLE,network:JSON_REF,...refs('secretNamesAndReferences logDestination'),environmentGate:ref('EnvironmentGateV1'),maxRuntimeMs:literal(140000),cleanupReserveMs:literal(30000),runTaskContract:ref('CarrierRunTaskContractV1'),carrierPlatform:ref('RuntimePlatformObservationV1')},
 v=>{equal(v.entryPoint,carrierEntry);need(v.account===v.carrierImage.account&&v.region===v.carrierImage.region&&v.carrierImage.repositoryName==='mem9-on-aws/preview/bootstrap'&&v.runTaskContract.tags[0].value===v.owner&&v.carrierPlatform.platformVersion===v.runTaskContract.platformVersion);});
define('CarrierRegistrationReadbackV1',{version:literal(1),kind:literal('exact-carrier-registration-readback'),taskDefinitionArn:TD,carrierImage:CIMG,requestedRegistrationBodyHash:H,rawDefinition:JSON_REF,rawDefinitionHash:H,observedMs:MS});
define('CarrierRegistryPresenceV1',{version:literal(1),kind:literal('same-carrier-registry-presence'),carrierBuildHash:H,image:CIMG,rootManifest:BYTE_REF,arm64Manifest:BYTE_REF,config:BYTE_REF,...refs('blobAvailability registryObservation'),observedMs:MS,expiresMs:MS},
 v=>{need(v.expiresMs>v.observedMs&&v.expiresMs-v.observedMs<=300000);for(const [key,digest]of [['rootManifest','rootDigest'],['arm64Manifest','arm64Digest'],['config','configDigest']])need('sha256:'+v[key].sha256===v.image[digest]);});
define('CarrierPrerequisiteReviewV1',{version:literal(1),kind:literal('premerge-carrier-prerequisite-review'),decision:literal('pass-for-preaudit'),...hashes('designReviewHash carrierBuildHash sourceEvidenceHash launchPlanHash permissionsHash legacyBindingsHash'),reviewedMs:MS,expiresMs:MS},v=>need(v.expiresMs>v.reviewedMs&&v.expiresMs-v.reviewedMs<=86400000));
define('PreauditPermitV1',{version:literal(1),kind:literal('premerge-readonly-audit-permit'),owner:N,invocation:N,...hashes('carrierBuildHash prerequisiteReviewHash permissionsHash launchPlanHash rootBindingHash predecessorParameterHash oldCertificateHash oldAuditInputHash'),registrationReadback:ref('CarrierRegistrationReadbackV1'),runOverrides:ref('CarrierRunOverridesV1'),environmentGate:ref('EnvironmentGateV1'),carrierPresence:ref('CarrierRegistryPresenceV1'),runTask:ref('CarrierRunTaskBindingV1'),issuedMs:MS,deadlineMs:MS},
 v=>{need(v.deadlineMs>v.issuedMs);equal(v.runOverrides,v.runTask.request.overrides);need(v.runTask.request.clientToken===v.invocation&&v.runTask.request.tags[0].value===v.owner&&v.runTask.launchPlanHash===v.launchPlanHash&&v.runTask.authorization.permissionsDossierHash===v.permissionsHash&&v.runTask.registrationReadbackHash===nonrootHash(v.registrationReadback)&&v.runTask.environmentGateHash===nonrootHash(v.environmentGate)&&v.runTask.carrierPresenceHash===nonrootHash(v.carrierPresence));});
define('PermissionsDossierV1',{version:literal(1),kind:literal('existing-permissions-preflight'),account:A,applicationRegion:R,iamRegion:R,...refs('caller actorBindings identityPolicies boundaries trustAndResourcePolicies organizationAndEndpointControls actionMatrix positiveNegativeTests analyzerScannerReview'),carrierRunTaskContractHash:H,observedMs:MS,result:literal('pass')});
define('HistoricalCopyV1',{version:literal(1),kind:literal('historical-copy-adoption'),owner:N,control:ref('SourceIdentityV1'),...refs('stageConfig initialJournal recoveryDesign recoveryReviews recoverySource recoveryTerminal completedGraph destinationReadback originalVerifierClosure cumulativeBudget oldIdDenial')});
define('ArtifactReverificationV1',{version:literal(1),kind:literal('readonly-artifact-reverification'),copyRecordHash:H,...refs('verifierClosure graph destinationReadback filesystem imageConfigs pathPermissions primitiveEvidence readAccounting'),contentHash:H,...clocks},time);
define('ArtifactReverificationV2',{version:literal(2),kind:literal('readonly-cached-artifact-reverification'),copyRecordHash:H,...refs('verifierClosure graph cacheCustody historicalDestinationReadback freshDestinationMetadata filesystem imageConfigs pathPermissions primitiveEvidence readAccounting'),contentHash:H,...clocks},time);
define('HealthyBaselineV1',{observedMs:MS,service:JSON_REF,task:JSON_REF,taskArn:TASK,taskDefinitionArn:TD,...refs('containerBindings privateApiEvidence')});
define('AvailabilityCaseV1',{name:oneOf('successful-handover','prefix-start-failure','sidecar-readiness-failure','post-liveness-regression','nonterminal-timeout'),...clocks,maximumObservedOutageMs:integer(0,7200000),oldTaskPreserved:B,deploymentState:oneOf('COMPLETED','FAILED','IN_PROGRESS'),privateApiPassed:B,rootRelaunchCount:literal(0),evidence:JSON_REF},time);
define('AvailabilityRehearsalV1',{version:literal(1),kind:literal('bounded-overlap-rehearsal'),sourceTree:G,dataImages:ref('ImageSet'),controlBuild:JSON_REF,configurationHash:H,cases:array(ref('AvailabilityCaseV1'),5,5),outcome:literal('overlap-sufficient'),evidence:JSON_REF,completedMs:MS},v=>unique(v.cases,x=>x.name));
define('HealthyOverlapPlanV1',{version:literal(1),kind:literal('rolling-healthy-overlap'),serviceName:literal('Mem9Server'),strategy:literal('ROLLING'),controller:literal('ECS'),desiredCount:literal(1),minimumHealthyPercent:literal(100),maximumPercent:literal(200),bakeTimeInMinutes:literal(0),circuitBreaker:object({enable:literal(true),beforeRollback:literal(true),afterRollback:literal(false)}),baseline:ref('HealthyBaselineV1'),cloudMap:JSON_REF,ordinaryWorkflow:JSON_REF,rehearsal:ref('AvailabilityRehearsalV1'),maxPlannedOutageMs:literal(7200000)});
define('ControlInvocationContractV1',{context:literal('.'),file:literal('docker/bootstrap/Dockerfile'),platforms:v=>equal(v,['linux/arm64']),pull:literal(true),noCacheFilters:v=>equal(v,['runtime']),buildArgs:array(S,0,0),buildContexts:array(S,0,0),secretMounts:array(S,0,0),ssh:array(S,0,0),target:literal(null),cacheFrom:array(S,0,8),cacheTo:array(S,0,8),buildActionSha:G,tagRule:literal('mem9-actual-main-sha7'),provenanceRule:literal('authenticated-workflow-run-attempt')});
define('ControlRecipeV1',{dockerfilePath:literal('docker/bootstrap/Dockerfile'),dockerfile:ref('SourceFileV1'),context:ref('SourceClosureV1'),ignoreFiles:JSON_REF,preparation:ref('SourceClosureV1'),invocation:ref('ControlInvocationContractV1')});
define('ControlBuildContractV1',{version:literal(1),kind:literal('reviewed-deployed-control-build-contract'),key:literal('deployed-bootstrap'),repository:S,candidate:ref('SourceIdentityV1'),prNumber:P,workflow:object({path:literal('.github/workflows/infra-ci.yml'),sourceFile:ref('SourceFileV1'),jobKey:literal('build-image-transition-control'),buildStepId:literal('bootstrap'),jobSource:BYTE_REF}),recipe:ref('ControlRecipeV1'),guardSource:ref('SourceClosureV1'),guardImportPolicy:ref('GuardImportPolicyV1'),launchTemplates:array(ref('ControlLaunchTemplateV1'),1,10),output:object({account:A,region:R,repositoryName:literal('mem9-on-aws/bootstrap')}),artifactPolicyHash:H,...refs('guardTestContract sourceReview')},v=>unique(v.launchTemplates,x=>x.taskKey));
define('ResolvedControlLaunchV1',{version:literal(1),kind:literal('resolved-control-launch'),taskKey:KEY,containerName:S,templateHash:H,contractHash:H,image:CIMG,entryPoint:ARGV,command:ARGV,dispatcherSha256:H,guardClosureHash:H,originalModule:ref('PresenceString'),originalModuleSha256:ref('PresenceString'),originalArgv:ARGV,primitiveEvidence:JSON_REF,guardImports:ref('GuardModuleImportsV1'),environment:ref('EnvironmentGateV1'),registrationBody:JSON_REF,registrationBodyHash:H},v=>{need(v.entryPoint[3]===CONTROL_NODE);});
define('ControlScanEvidenceV1',{version:literal(1),kind:literal('deployed-control-scan-evidence'),image:CIMG,...refs('rawPages normalizedFindings artifactReview'),policyHash:H,observedMs:MS,result:literal('pass')});
define('ActualMainV1',{version:literal(1),kind:literal('actual-hardening-main'),repository:S,candidateRevision:G,candidateTree:G,baseRevision:G,mainRevision:G,mainTree:G,parents:array(G,1,2),prNumber:P,workflowRun:P,workflowAttempt:P,workflowPath:literal('.github/workflows/infra-ci.yml'),workflowSha:G,authenticatedSource:JSON_REF},
 v=>{need(v.mainTree===v.candidateTree&&v.workflowSha===v.mainRevision&&v.parents[0]===v.baseRevision&&(v.parents.length===1||v.parents[1]===v.candidateRevision));unique(v.parents);});
define('DeployedControlBuildV1',{version:literal(1),kind:literal('actual-main-deployed-control-build'),contractHash:H,actualMain:ref('ActualMainV1'),source:object({repository:S,revision:G,tree:G,checkout:JSON_REF,sourceEvidence:JSON_REF}),workflow:object({path:literal('.github/workflows/infra-ci.yml'),workflowSha:G,runId:P,attempt:P,jobId:P,jobKey:literal('build-image-transition-control'),buildStepId:literal('bootstrap'),jobName:S,authenticatedRun:JSON_REF,authenticatedJob:JSON_REF}),recipe:ref('ControlRecipeV1'),actualInvocation:JSON_REF,buildLog:BYTE_REF,image:CIMG,imageGraph:JSON_REF,guardSource:ref('SourceClosureV1'),guardImports:ref('GuardModuleImportsV1'),scan:ref('ControlScanEvidenceV1'),guardTests:JSON_REF,resolvedLaunches:array(ref('ResolvedControlLaunchV1'),1,10),...clocks},
 v=>{time(v);need(v.source.revision===v.actualMain.mainRevision&&v.source.tree===v.actualMain.mainTree&&v.source.repository===v.actualMain.repository&&v.workflow.workflowSha===v.actualMain.workflowSha&&v.workflow.runId===v.actualMain.workflowRun&&v.workflow.attempt===v.actualMain.workflowAttempt&&v.image.repositoryName==='mem9-on-aws/bootstrap');equal(v.scan.image,v.image);unique(v.resolvedLaunches,x=>x.taskKey);for(const l of v.resolvedLaunches){equal(l.image,v.image);need(l.contractHash===v.contractHash);}});
// Content addressed by DeploymentSourceRecordV2.resolvedTaskPlan. The archive
// adapter authenticates every referenced body and compares the complete preplan
// with only its typed deployed-CONTROL replacements, plus build.resolvedLaunches.
// Retained fallback and the separately permitted carrier are never update tasks.
const updateTaskKeys=NONROOT_TASK_KEYS.filter(k=>k!=='fallback'&&k!=='preaudit');
define('ResolvedTaskPlanV1',{version:literal(1),kind:literal('resolved-nonroot-task-plan'),taskPlanHash:H,deployedControlBuildHash:H,
 tasks:array(object({taskKey:oneOf(...updateTaskKeys),registrationBody:JSON_REF}),8,8),
 controlLaunches:array(ref('ResolvedControlLaunchV1'),1,10)},
 v=>{named(v.tasks,updateTaskKeys);unique(v.controlLaunches,x=>x.taskKey);});
define('DeploymentSourceRecordV2',{version:literal(2),kind:literal('nonroot-deployment-source'),descriptorHash:H,parameterVersion:P,proofHash:H,actualMain:ref('ActualMainV1'),deployedControlBuild:ref('DeployedControlBuildV1'),resolvedTaskPlan:JSON_REF,checkedMs:MS},v=>equal(v.actualMain,v.deployedControlBuild.actualMain));
const processFields={pid:P,ppid:Z,startTimeTicks:P,executablePath:ABS,executableDigest:D,entrypointIdentityHash:H,uid:v=>equal(v,[1000,1000,1000,1000]),gid:v=>equal(v,[1000,1000,1000,1000]),groups:union(v=>equal(v,[]),v=>equal(v,[1000])),...Object.fromEntries(['capInh','capPrm','capEff','capBnd','capAmb'].map(k=>[k,literal('0000000000000000')]))};
define('ProcessIdentityV2',{...processFields,noNewPrivs:literal(1)});
const {entrypointIdentityHash:ignoredEntrypoint,...trustedProcessFields}=processFields;
define('TrustedLaunchV1',{kind:oneOf('init','fixed-nnp-prefix'),...trustedProcessFields,noNewPrivs:oneOf(0,1),evidence:JSON_REF});
define('ManagedProcessV1',{pid:P,ppid:Z,startTimeTicks:P,executablePath:ABS,executableDigest:D,managedAgentName:S,sessionIdHash:H,classificationEvidence:JSON_REF});
schemas.RuntimeArtifactBindingV1=union(
 object({kind:literal('artifact-test'),image:IMG,sourceRevision:G,sourceTree:G,buildFactsHash:H,launchTemplateHash:H}),
 object({kind:literal('data'),descriptorHash:H,launchContractHash:H}),
 object({kind:literal('carrier'),carrierBuildHash:H,preauditPermitHash:H,launchPlanHash:H}),
 object({kind:literal('deployed-control'),deployedControlBuildHash:H,resolvedControlLaunchHash:H}));
define('RuntimeIdentityV2',{version:literal(2),kind:literal('application-process-identity'),phase:oneOf('preview','preaudit','target','operator','worker'),taskKey:KEY,account:A,region:R,taskArn:TASK,taskDefinitionArn:TD,containerName:S,runtimeId:text(256),image:IMG,...hashes('registrationHash launchContractHash sourceBindingHash collectorCodeHash'),artifactBinding:ref('RuntimeArtifactBindingV1'),sessionBinding:JSON_REF,...clocks,application:array(ref('ProcessIdentityV2'),1,256),trustedLaunch:array(ref('TrustedLaunchV1'),0,256),managed:array(ref('ManagedProcessV1'),0,256),samples:JSON_REF,coverage:JSON_REF,result:literal('pass')},
 v=>{time(v);const all=[...v.application,...v.trustedLaunch,...v.managed];need(all.length<=256);unique(all,p=>p.pid+':'+p.startTimeTicks);need((v.phase==='preview')===(v.artifactBinding.kind==='artifact-test'));need(v.taskArn.startsWith('arn:aws:ecs:'+v.region+':'+v.account+':')&&v.taskDefinitionArn.startsWith('arn:aws:ecs:'+v.region+':'+v.account+':'));});
define('TargetContainerBindingV1',{name:COMPONENT,runtimeId:text(256),image:IMG,launchContractHash:H});
define('TargetBindingV1',{account:A,region:R,clusterArn:CLUSTER,serviceName:literal('Mem9Server'),serviceDeploymentId:S,taskArn:TASK,taskDefinitionArn:TD,registrationHash:H,containers:array(ref('TargetContainerBindingV1'),3,3)},v=>named(v.containers,NONROOT_DATA_COMPONENTS));
define('TargetRoutingEvidenceV1',{version:literal(1),kind:literal('target-private-routing'),targetBindingHash:H,...refs('probeSource routeObservations targetAttribution dependencyChecks'),...clocks,result:literal('pass')},time);
define('TargetPreReadinessV1',{version:literal(1),kind:literal('target-before-root-audit'),descriptorHash:H,parameterVersion:P,deploymentSourceHash:H,target:ref('TargetBindingV1'),identity:array(ref('RuntimeIdentityV2'),3,3),routing:ref('TargetRoutingEvidenceV1'),platform:ref('RuntimePlatformObservationV1'),rawObservations:JSON_REF,...clocks},
 v=>{time(v);named(v.identity,NONROOT_DATA_COMPONENTS);need(v.routing.targetBindingHash===nonrootHash(v.target));});
define('TargetIdentityRecheckV1',{version:literal(1),kind:literal('typed-post-audit-target-identities'),...hashes('preTargetHash targetBindingHash registrationHash'),identities:array(ref('RuntimeIdentityV2'),3,3),mainProcesses:array(object({containerName:COMPONENT,preMain:ref('ProcessIdentityV2'),postMain:ref('ProcessIdentityV2')}),3,3),healthCoverage:array(object({containerName:COMPONENT,runtimeId:S,image:IMG,registrationHash:H,launchContractHash:H,healthCommandHash:H,processes:array(ref('ProcessIdentityV2'),1,256),...clocks},time),3,3),...clocks},
 v=>{time(v);for(const rows of [v.identities,v.mainProcesses,v.healthCoverage])named(rows,NONROOT_DATA_COMPONENTS);for(const m of v.mainProcesses)for(const k of ['pid','startTimeTicks','executableDigest','entrypointIdentityHash'])need(m.preMain[k]===m.postMain[k]);});
define('TargetPostAuditV1',{version:literal(1),kind:literal('same-target-after-root-audit'),preTargetHash:H,target:ref('TargetBindingV1'),identityRecheck:ref('TargetIdentityRecheckV1'),routingRecheck:ref('TargetRoutingEvidenceV1'),rawObservations:JSON_REF,...clocks},
 v=>{time(v);need(v.preTargetHash===v.identityRecheck.preTargetHash&&v.identityRecheck.targetBindingHash===nonrootHash(v.target)&&v.routingRecheck.targetBindingHash===nonrootHash(v.target));});
schemas.AuditTargetJoinV1=union(object({kind:literal('not-applicable')}),object({kind:literal('same-target-window'),targetEvidence:ref('TargetPreReadinessV1'),postAuditObservation:ref('TargetPostAuditV1')}));
define('OldRootAuditV2',{version:literal(2),kind:literal('old-root-readonly-audit'),phase:oneOf('predeployment','postdeployment-preservation'),root:ref('RootBindingV1'),...refs('predecessorParameter oldMaterial oldCertificate taskObservation runtimeState extensionMaintenance schedulerState credentialBindings writerCensus ownershipFence'),carrierBuild:ref('CarrierBuildV1'),preauditPermit:ref('PreauditPermitV1'),carrierIdentity:ref('RuntimeIdentityV2'),targetJoin:ref('AuditTargetJoinV1'),...clocks,databaseObservedMs:MS,cloudObservedMs:MS,cleanupComplete:literal(true)},
 v=>{time(v);need(v.databaseObservedMs>=v.startedMs&&v.databaseObservedMs<=v.completedMs);need((v.phase==='predeployment')===(v.targetJoin.kind==='not-applicable'));});
define('RuntimeReadinessV2',{version:literal(2),kind:literal('nonroot-target-readiness'),...hashes('descriptorHash proofHash deploymentSourceHash resolvedTaskPlanHash'),...refs('backend bootstrap operators workerCertification serviceReconciliation'),dependencyAndRoutingChecks:ref('TargetRoutingEvidenceV1'),postdeployRootAudit:ref('OldRootAuditV2'),...clocks,result:literal('pass')},v=>{time(v);need(v.postdeployRootAudit.phase==='postdeployment-preservation');});
define('FreshAdmissionV1',{version:literal(1),kind:literal('same-binding-admission-refresh'),proofHash:H,descriptorHash:H,phase:oneOf('preconfigure','presst','preupdate','prereadiness'),parameterVersion:P,...refs('rootAudit serviceObservation'),sourceEvidenceHash:H,permissionBindingsHash:H,observedMs:MS,expiresMs:MS},v=>need(v.expiresMs>v.observedMs&&v.expiresMs-v.observedMs<=300000));
const presence=union(object({present:literal(false)}),object({present:literal(true),value:()=>{}}));
// This is the one unresolved image value permitted in the pre-build CONTROL
// plan. Provenance verification replaces it with the exact authenticated build
// image; DATA, the preaudit carrier and retained/legacy routes cannot use it.
const deployedControlImageSlot=object({version:literal(1),kind:literal('deployed-control-image'),buildContractKey:literal('deployed-bootstrap')});
const controlImageTargets=Object.freeze({bootstrap:'Mem9Bootstrap',control:'ControlMem9Bootstrap',promotion:'PromoteMem9Bootstrap',provision:'ProdMem9Bootstrap',transition:'TransitionMem9Bootstrap'});
define('FieldChangeV2',{taskKey:KEY,surface:oneOf('container','response','service'),selector:S,field:oneOf('user','linuxParameters.capabilities','entryPoint','command','healthCheck.command','image','requiresAttributes','compatibilities','deploymentCircuitBreaker.rollback'),before:presence,after:presence,cause:oneOf('fixed-user','drop-all','fixed-data-nnp','fixed-health-nnp','guarded-control','carrier-image','retained-data-image','ecs-derived','disable-root-rollback'),observationHash:H},
 v=>{need(v.after.present);const x=v.after.value;if(v.field==='user')need(x==='1000:1000');else if(v.field==='linuxParameters.capabilities')equal(x,{drop:['ALL']});else if(v.field==='deploymentCircuitBreaker.rollback')need(x===false);else if(['entryPoint','command','healthCheck.command'].includes(v.field))ARGV(x);else if(v.field==='image'){
  if(typeof x==='string')text()(x);
  else{
   need(v.surface==='container'&&v.cause==='guarded-control'&&Object.hasOwn(controlImageTargets,v.taskKey)&&v.selector===controlImageTargets[v.taskKey]&&v.before.present);
   text()(v.before.value);deployedControlImageSlot(x);
  }
 }else {array(text(256),0,100)(x);unique(x);}});
schemas.TaskEntryV2=union(
 object({taskKey:KEY,disposition:literal('update'),containerNames:array(S,1,3),phase:oneOf('deploy','continuation','registration-only'),invocation:oneOf('service','runtime-verify','control','worker-planner','worker-executor','promote','deny'),...refs('beforeDefinition targetRegistration imageBindings baselineEvidence')}),
 object({taskKey:literal('preaudit'),disposition:literal('carrier'),containerNames:v=>equal(v,['ControlMem9Bootstrap']),phase:literal('preaudit'),invocation:literal('readonly-root'),beforeDefinition:JSON_REF,targetRegistration:JSON_REF,carrierBuildHash:H,baselineEvidence:JSON_REF}),
 object({taskKey:literal('fallback'),disposition:literal('retain'),containerNames:v=>{array(COMPONENT,3,3)(v);equal([...v].sort(),NONROOT_DATA_COMPONENTS);},phase:literal('retained'),invocation:literal('deny'),beforeDefinition:JSON_REF,unchangedBindingHash:H}));
define('TaskPlanV2',{version:literal(2),kind:literal('exact-nnp-task-plan'),policy:ref('HardeningPolicyV2'),tasks:array(ref('TaskEntryV2'),10,10),fieldChanges:array(ref('FieldChangeV2'),0,96),dataLaunches:array(ref('FixedDataLaunchV1'),5,5),controlLaunches:array(ref('ControlLaunchTemplateV1'),1,10),previewLaunches:ref('PreviewLaunchInventoryV1'),carrierBuild:ref('CarrierBuildV1'),permissions:ref('PermissionsDossierV1'),overlap:ref('HealthyOverlapPlanV1'),beforeProjection:JSON_REF,targetProjection:JSON_REF,deployedControlBuildContract:ref('ControlBuildContractV1'),previewEvidence:JSON_REF},v=>named(v.tasks,NONROOT_TASK_KEYS));
define('NonrootImageProofV2',{version:literal(2),kind:literal('ecs-nonroot-image-upgrade-proof'),limits:ref('NonrootLimitsV2'),predecessorParameter:JSON_REF,legacyBootstrapProof:JSON_REF,root:ref('RootBindingV1'),dataOrigin:ref('DataOriginV1'),historicalCopy:ref('HistoricalCopyV1'),artifactReverification:union(ref('ArtifactReverificationV1'),ref('ArtifactReverificationV2')),deploymentControl:ref('SourceIdentityV1'),protectedInputs:JSON_REF,taskPlan:ref('TaskPlanV2'),predeploymentAudit:ref('OldRootAuditV2'),...refs('artifactSecurity policySources designReview'),observedMs:MS},v=>{need(v.predeploymentAudit.phase==='predeployment');equal(v.root,v.predeploymentAudit.root);});
define('NonrootTransitionV2',{version:literal(2),kind:literal(NONROOT_TRANSITION_KIND),proofHash:H,predecessorHash:H,limitsHash:literal(NONROOT_LIMITS_HASH)});
const descriptorFields={version:literal(3),stage:literal('prod'),account:A,region:R,controlSourceTree:G,dataRevision:G,dataSourceTree:G,dataSourceTag:pattern(/^mem9-[a-f0-9]{7}$/),images:object(Object.fromEntries(NONROOT_DATA_COMPONENTS.map(n=>[n,object({rootDigest:D,arm64Digest:D},v=>need(v.rootDigest!==v.arm64Digest))]))),...hashes('parentProofHash backendBindingHash generation targetsHash schemaDigest operatorDigest buildInputsHash securityEvidenceHash policyHash'),runtimeNonce:N,authorizationId:N,issuedMs:MS,expiresMs:MS,transition:ref('NonrootTransitionV2')};
define('DataDescriptorV3',descriptorFields,v=>need(v.dataSourceTag==='mem9-'+v.dataRevision.slice(0,7)&&v.expiresMs>v.issuedMs&&v.expiresMs-v.issuedMs<=86400000));
define('FinalReviewV2',{version:literal(2),kind:literal('nonroot-deployment-policy-review'),decision:literal('pass-for-deployment'),...hashes('proofHash designReviewHash sourceEvidenceHash dataOriginSourceEvidenceHash copyAdoptionHash artifactReverificationHash taskPlanHash carrierBuildHash permissionsHash availabilityRehearsalHash policySourcesHash artifactSecurityHash oldRootAuditHash predecessorHash'),controlSourceTree:G,reviewedMs:MS,expiresMs:MS},v=>need(v.expiresMs>v.reviewedMs&&v.expiresMs-v.reviewedMs<=86400000));
define('ParameterCaptureV1',{Name:literal('/mem9-on-aws/prod/consolidation-runtime/data-release'),Type:literal('SecureString'),ARN,Version:P,Value:text(4096)},v=>need(v.ARN.endsWith(':parameter'+v.Name)));
define('NonrootExpectedV2',{account:A,region:R,controlRevision:G,controlSourceTree:G,...hashes('sourceEvidenceHash proofHash taskPlanHash carrierBuildHash permissionsHash availabilityRehearsalHash rootBindingHash oldRootAuditHash artifactReverificationHash artifactSecurityHash writerBoundaryHash lineageHash'),parameterProtection:object({KeyId:S,Tier:literal('Standard'),DataType:literal('text')})});
define('NonrootOperationV2',{version:literal(2),kind:literal('image-security-nonroot-transition'),operation:object({owner:N,expected:object({revision:G,newValue:text(8192)}),prior:object({value:text(4096)})}),predecessor:ref('ParameterCaptureV1'),authorization:object({data:ref('DataDescriptorV3'),hash:H,review:ref('FinalReviewV2')}),expected:ref('NonrootExpectedV2'),lineage:JSON_REF,evidenceManifest:JSON_REF},v=>{need(v.authorization.hash===nonrootHash(v.authorization.data)&&v.operation.owner===v.authorization.data.authorizationId&&v.authorization.data.policyHash===nonrootHash(v.authorization.review)&&v.operation.prior.value===v.predecessor.Value);});
const release=object({sourceTree:G,coordinatorDigest:H,sourceTag:pattern(/^mem9-[a-f0-9]{7}$/),workerImage:S,schemaDigest:H,operatorDigest:H,runtimeNonce:N});
define('CompatibilityCertificateV5',{version:literal(5),dataReleaseHash:H,parentProofHash:H,generation:H,targetsHash:H,previous:object({release,backendBindingHash:H}),current:object({release,backendBinding:object({taskArn:TASK,taskDefinitionArn:TD,containers:array(object({name:COMPONENT,imageDigest:D}),3,3)},v=>named(v.containers,NONROOT_DATA_COMPONENTS))}),images:object(Object.fromEntries(['worker',...NONROOT_DATA_COMPONENTS].map(n=>[n,object({previousRoot:D,currentRoot:D,previousChild:D,currentChild:D})]))),material:object(Object.fromEntries(['planner','executor','backend','network','authority','credentials'].map(n=>[n,object({previous:H,current:H})]))),transition:object({version:literal(2),kind:literal(NONROOT_TRANSITION_KIND),proofHash:H,predecessorHash:H,limitsHash:literal(NONROOT_LIMITS_HASH),...hashes('projectionHash runtimeEvidenceHash operatorEvidenceHash deploymentSourceHash')})},
 v=>{for(const k of ['schemaDigest','operatorDigest','runtimeNonce'])need(v.previous.release[k]===v.current.release[k]);for(const k of ['network','credentials'])need(v.material[k].previous===v.material[k].current);equal(v.images.worker,v.images['llm-proxy']);});
define('ContinuationWitnessV2',{version:literal(2),parentProofHash:H,certificateHash:H,sourceTree:G,fixture:object({hash:H,runId:pattern(/^[1-9][0-9]*$/),runAttempt:P}),readinessHash:H,descriptorHash:H});
define('ArchiveFileV1',{name:S,purpose:oneOf('protocol','source','image-graph','image-blob','filesystem','scan','vendor','policy','copy-journal','recovery','root-audit','runtime-identity','task-definition','iam-boundary','preview','build','lineage','carrier','availability'),ref:union(JSON_REF,BYTE_REF),encoding:oneOf('json','bytes')},
 v=>{need(!v.name.includes('/')&&!v.name.includes('\\')&&!['.','..'].includes(v.name));need(v.encoding==='json'?Object.hasOwn(v.ref,'canonicalHash'):Object.hasOwn(v.ref,'sha256'));});
define('ArchiveManifestV2',{version:literal(2),kind:literal('nonroot-proof-archive'),owner:N,files:array(ref('ArchiveFileV1'),1,20000)},v=>unique(v.files,f=>f.name));
Object.freeze(schemas);
export const NONROOT_RECORD_TYPES=Object.freeze(Object.keys(schemas));

/** Structural and intrinsic equality validation only. "pass" fields are claims. */
export function inspectNonrootRecord(type,value) {
  need(typeof type==='string'&&Object.hasOwn(schemas,type));
  const maxBytes=type==='DataDescriptorV3'?NONROOT_LIMITS.maxDescriptorBytes:
    type==='CompatibilityCertificateV5'?NONROOT_LIMITS.maxCertificateBytes:
    ['RuntimeIdentityV2','TargetIdentityRecheckV1'].includes(type)?NONROOT_LIMITS.maxRuntimeRecordBytes:NONROOT_LIMITS.maxProofBytes;
  const data=typeof value==='string'?parseNonrootJson(value,{maxBytes}):copyJson(value,maxBytes);
  schemas[type](data);return freeze(data);
}
export const inspectNonrootDescriptor=value=>inspectNonrootRecord('DataDescriptorV3',value);
export const inspectNonrootTransition=value=>inspectNonrootRecord('NonrootTransitionV2',value);
export const inspectNonrootCertificate=value=>inspectNonrootRecord('CompatibilityCertificateV5',value);
export const inspectCarrierRunTaskRequest=value=>inspectNonrootRecord('CarrierRunTaskRequestV1',value);
export const inspectPreauditPermit=value=>inspectNonrootRecord('PreauditPermitV1',value);
export const inspectEnvironmentGate=value=>inspectNonrootRecord('EnvironmentGateV1',value);
export const inspectRuntimeIdentity=value=>inspectNonrootRecord('RuntimeIdentityV2',value);
export const inspectTargetIdentityRecheck=value=>inspectNonrootRecord('TargetIdentityRecheckV1',value);
