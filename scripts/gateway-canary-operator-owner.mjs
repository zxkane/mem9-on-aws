#!/usr/bin/env node
// Owner checks for scripts/deploy-gateway-canary-operator-role.sh, from the
// same library the broker uses:
//   check-owner <owner-role-arn>                     exit 2 for a refused owner role
//   check-template <template-file>                   exit 1 unless the file is exactly the
//     compiler's rendering
//   verify-owner <account> <region> <owner-role-arn>  exit 1 unless the SCP/RCP
//     acknowledgement is set, no readable SCP or RCP keys on the principal, and
//     the owner's own
//     identity policies and boundary allow every action/resource pair that the
//     operator's own policy allows (iam:SimulateCustomPolicy for both, through
//     the aws CLI on PATH)

import {accessSync,constants,readFileSync,realpathSync,statSync} from 'node:fs';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {delimiter,isAbsolute,join} from 'node:path';
import {renderGatewayCanaryOperatorRoleTemplate,gatewayCanaryOwnerRoleRefusal,verifyGatewayCanaryOwnerHoldsOperator,gatewayCanaryOrganizationPoliciesAcknowledged,checkGatewayCanaryOrganizationPolicies,
  GATEWAY_CANARY_ORG_POLICIES_ACK} from './lib/gateway-canary-operator-role.mjs';
import {createGatewaySourceBrokerAwsCli,gatewaySourceBrokerOwnerEnvironment,gatewaySourceBrokerAwsDetail} from './lib/gateway-runtime-source-broker.mjs';

const aws=()=>{
  for(const directory of (process.env.PATH??'').split(delimiter)){
    if(!isAbsolute(directory))continue;
    try{const candidate=join(directory,'aws');accessSync(candidate,constants.X_OK);if(statSync(candidate).isFile())return realpathSync(candidate);}catch{}
  }
  throw Error('aws CLI not found');
};
const [command,...args]=process.argv.slice(2);
try{
  if(command==='check-owner'&&args.length===1){
    const refusal=gatewayCanaryOwnerRoleRefusal(args[0]);
    if(refusal){process.stderr.write(`refused owner role (${refusal})\n`);process.exit(2);}
  }else if(command==='check-template'&&args.length===1){
    if(readFileSync(args[0],'utf8')!==await renderGatewayCanaryOperatorRoleTemplate()){process.stderr.write('operator role template differs from the compiler output; regenerate it\n');process.exit(1);}
  }else if(command==='verify-owner'&&args.length===3){
    const [accountId,applicationRegion,ownerRoleArn]=args;
    if(!gatewayCanaryOrganizationPoliciesAcknowledged(process.env)){process.stderr.write(`${GATEWAY_CANARY_ORG_POLICIES_ACK}=true is required\n`);process.exit(2);}
    const directory=await mkdtemp(join(tmpdir(),'gateway-owner-'));
    try{
      const call=createGatewaySourceBrokerAwsCli({awsExecutable:aws(),region:applicationRegion}),environment=gatewaySourceBrokerOwnerEnvironment(process.env);
      const organization=await checkGatewayCanaryOrganizationPolicies({organizations:(operation,body)=>call(environment,'organizations',operation,body,{directory}),accountId});
      process.stdout.write(organization.status==='unreadable'
        ?`organization policies are not fully readable; relying on ${GATEWAY_CANARY_ORG_POLICIES_ACK}=true\n`
        :`organization policies: ${organization.status} (${organization.policies} scanned)\n`);
      const result=await verifyGatewayCanaryOwnerHoldsOperator({iam:(operation,body)=>call(environment,'iam',operation,body,{directory}),accountId,applicationRegion,ownerRoleArn});
      process.stdout.write(`owner holds every operator permission (${result.operatorPairs} operator pairs in ${result.simulations} cases, over ${result.policies} owner policies${result.boundary?' and its boundary':''})\n`);
    }finally{await rm(directory,{recursive:true,force:true});}
  }else{
    process.stderr.write('usage: gateway-canary-operator-owner.mjs check-owner|verify-owner ...\n');process.exit(2);
  }
}catch(error){
  const detail=gatewaySourceBrokerAwsDetail(error);
  process.stderr.write(`${/^Gateway(CanaryOperator|SourceBroker)[A-Za-z]+$/.test(error?.message??'')?error.message:'owner check failed'}${detail?' ('+detail+')':''}\n`);process.exit(1);
}
