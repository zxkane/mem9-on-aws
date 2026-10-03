import {execFileSync} from 'node:child_process';
import {DATA_COMPONENTS,requireActiveDataRelease} from '../scripts/lib/production-data-release.mjs';

/**
 * Shared helper for composing OUT-OF-BAND ECR image URIs.
 *
 * All mem9-on-aws container images live in ECR repos owned out-of-band by
 * infra/cloudformation/ecr-repositories.yaml (DeletionPolicy: Retain), NOT by
 * SST — so `sst remove` can never wipe image history. SST stacks only REFERENCE
 * the images by URI. Every reference is
 * `<account>.dkr.ecr.<region>.amazonaws.com/<namespace>:<tag>` where the account
 * comes from the caller identity (never hardcoded) and region = the app region.
 *
 * Centralized here so ecs.ts (mnemo-server, qwen3-embed, and llm-proxy) and
 * bootstrap.ts share one composition and the active provider region.
 */

let regionOut: Output<string> | undefined;
export function applicationRegion(): Output<string> {
  if (!regionOut) {
    regionOut = aws.getRegionOutput().name;
  }
  return regionOut;
}

// Cache the caller-identity Output so repeated ecrImage()/accountId() calls don't
// each create a new getCallerIdentityOutput invoke. Exported so ecs.ts can build
// the Bedrock Mantle project ARN with the same deploy-time-resolved account id.
let accountIdOut: Output<string> | undefined;
export function accountId(): Output<string> {
  if (!accountIdOut) accountIdOut = aws.getCallerIdentityOutput().accountId;
  return accountIdOut;
}

type DataReleaseSelection=ReturnType<typeof requireActiveDataRelease>;
let retainedSelection:Output<DataReleaseSelection>|undefined;
let retainedInput:string|undefined;

/** The configure/predeploy verifier supplies this protected-record snapshot. */
export function selectedDataRelease():Output<DataReleaseSelection>|undefined {
  const raw=process.env.MEM9_RETAINED_DATA_RELEASE;
  const expectedHash=process.env.MEM9_RETAINED_DATA_RELEASE_HASH;
  if(!raw||raw==='none'){
    if(expectedHash&&expectedHash!=='none'||retainedInput)throw Error('DataReleaseSelectionChanged');
    return;
  }
  if(($app.stage!=='prod'&&!/^pr-[1-9][0-9]*$/.test($app.stage))||process.env.MEM9_PRODUCTION_RUNTIME_MODE!=='active'||
    !/^[a-f0-9]{64}$/.test(expectedHash??''))throw Error('VerifiedDataReleaseRequired');
  const binding=$app.stage+'\0'+raw+'\0'+expectedHash;
  if(retainedInput&&retainedInput!==binding)throw Error('DataReleaseSelectionChanged');
  retainedInput=binding;
  if(!retainedSelection){
    execFileSync('git',['diff','--quiet'],{timeout:10000});
    execFileSync('git',['diff','--cached','--quiet'],{timeout:10000});
    const controlSourceTree=execFileSync('git',['rev-parse','HEAD^{tree}'],{encoding:'utf8',timeout:10000}).trim();
    retainedSelection=accountId().apply(account=>applicationRegion().apply(region=>{
      const name=`/mem9-on-aws/${$app.stage}/consolidation-runtime/data-release`;
      return aws.ssm.getParameterOutput({name,region,withDecryption:true}).apply(parameter=>{
        if(parameter.name!==name||parameter.arn!==`arn:aws:ssm:${region}:${account}:parameter${name}`||
          parameter.type!=='SecureString'||!Number.isSafeInteger(parameter.version)||parameter.version<1)throw Error('ProtectedDataReleaseRequired');
        const context={stage:$app.stage,account,region,controlSourceTree};
        const selection=requireActiveDataRelease(parameter.value,context);
        if(selection.hash!==expectedHash||requireActiveDataRelease(raw,context).hash!==selection.hash)throw Error('DataReleaseSelectionChanged');
        return selection;
      });
    }));
  }
  return retainedSelection;
}

export function selectedDataSourceTag(controlTag:string):string|Output<string>{
  const retained=selectedDataRelease();return retained?retained.apply(selection=>selection.data.dataSourceTag):controlTag;
}

/**
 * Compose an ECR image URI for `<namespace>:<tag>` in the app account+region.
 * @param namespace e.g. "mem9-on-aws/mnemo-server" (the ECR RepositoryName)
 * @param tag e.g. "mem9-abc1234" or "latest"
 */
export function ecrImage(namespace: string, tag: string): Output<string> {
  return $interpolate`${accountId()}.dkr.ecr.${applicationRegion()}.amazonaws.com/${namespace}:${tag}`;
}

export function workloadImage(name: string, tag: string): Output<string> {
  const namespace = process.env.MEM9_ECR_NAMESPACE || "mem9-on-aws";
  if ($app.stage === "prod" && namespace !== "mem9-on-aws") {
    throw new Error("production workload images must use mem9-on-aws");
  }
  if (
    /^pr-[1-9][0-9]*$/u.test($app.stage) &&
    !["mem9-on-aws", "mem9-on-aws/preview"].includes(namespace)
  ) {
    throw new Error("preview workload image namespace is invalid");
  }
  if(DATA_COMPONENTS.includes(name)){
    const retained=selectedDataRelease();if(retained)return retained.apply(selection=>selection.images[name]);
  }
  return ecrImage(`${namespace}/${name}`, tag);
}

export function pinnedProductionImage(name:'bootstrap'|'llm-proxy',tag:string):Output<string>{
  if($app.stage!=='prod'||!/^mem9-[a-f0-9]{7}$/.test(tag)||(process.env.MEM9_ECR_NAMESPACE&&process.env.MEM9_ECR_NAMESPACE!=='mem9-on-aws'))throw Error('ProductionImageRevisionRequired');
  if(name==='llm-proxy'){
    const retained=selectedDataRelease();if(retained)return retained.apply(selection=>selection.images['llm-proxy']);
  }
  const repositoryName='mem9-on-aws/'+name;
  const image=aws.ecr.getImageOutput({repositoryName,imageTag:tag,registryId:accountId(),region:applicationRegion()});
  return image.imageDigest.apply(digest=>{
    if(!/^sha256:[a-f0-9]{64}$/.test(digest))throw Error('ProductionImageDigestRequired');
    return $interpolate`${accountId()}.dkr.ecr.${applicationRegion()}.amazonaws.com/${repositoryName}@${digest}`;
  });
}
