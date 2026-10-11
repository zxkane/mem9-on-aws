/** Deterministic addresses only. The original owner/CI allocation must
 * authenticate this config and pay all operations before using these keys. */
import {inspectFutureAcquisitionConfig} from './ci-smoke-future-config.mjs';

export function describeProductionControlCompositionLocations(value){
 const c=inspectFutureAcquisitionConfig(value),prefix='data-authorizations/ci-composition/'+c.startup.grantSetId;
 return Object.freeze({account:c.account,region:c.region,bucket:c.storage.bucket,kmsKeyArn:c.storage.kmsKeyArn,prefix,
  tools:prefix+'/tools.tar',source:prefix+'/source.tar',capture:'decisions/prod/ci-composition/'+c.startup.grantSetId+'/capture.json',
  roleArn:'arn:aws:iam::'+c.account+':role/github-actions-mem9-on-aws-prod'});
}
