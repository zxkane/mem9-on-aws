import {productionRecurringEnvironment} from '../lib/production-scheduler-context.mjs';
const account='123456789012',region='ap-northeast-1',now=1800000000000,h=c=>c.repeat(64);
export function productionRecurringFixture(){
  const clusterArn=`arn:aws:ecs:${region}:${account}:cluster/mem9-on-aws-prod-Test`,roleArn=`arn:aws:iam::${account}:role/mem9-on-aws-prod-Mem9ConsolidationSchedulerRole-role`;
  const target={account,region,kind:'planner',clusterArn,roleArn,groupName:'mem9-on-aws-prod-consolidation-test',template:{Name:'mem9-on-aws-prod-planner-test'},generation:h('a'),
    containerName:'Mem9ConsolidationPlanner',taskDefinitionArn:`arn:aws:ecs:${region}:${account}:task-definition/mem9-on-aws-prod-Test-Planner:1`,
    taskRoleArn:`arn:aws:iam::${account}:role/task`,executionRoleArn:`arn:aws:iam::${account}:role/exec`,image:`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/llm-proxy@sha256:${h('b')}`,subnets:['subnet-abcd'],securityGroup:'sg-abcd'};
  const role={Arn:roleArn,RoleId:'AROAABCDEFGHIJKLMNOPQ',PermissionsBoundary:{PermissionsBoundaryArn:`arn:aws:iam::${account}:policy/mem9-on-aws-workload-boundary`},
    AssumeRolePolicyDocument:{Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'sts:AssumeRole',Principal:{Service:'scheduler.amazonaws.com'},Condition:{StringEquals:{'aws:SourceAccount':account,'aws:SourceArn':`arn:aws:scheduler:${region}:${account}:schedule-group/${target.groupName}`}}}]}};
  const admission=h('c'),scheduleArn=`arn:aws:scheduler:${region}:${account}:schedule/${target.groupName}/${target.template.Name}`;
  const env=productionRecurringEnvironment(target.generation,admission).map(e=>({...e,value:({MEM9_SCHEDULER_ARN:scheduleArn,MEM9_SCHEDULER_TIME:new Date(now-60000).toISOString(),MEM9_SCHEDULER_EXECUTION:'d32c5kddcf5bb8c3',MEM9_SCHEDULER_ATTEMPT:'1'})[e.name]??e.value}));
  const definition={taskDefinitionArn:target.taskDefinitionArn,networkMode:'awsvpc',runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'},taskRoleArn:target.taskRoleArn,executionRoleArn:target.executionRoleArn,containerDefinitions:[{name:target.containerName,image:target.image}]};
  const task={taskArn:clusterArn.replace(':cluster/',':task/')+'/'+'d'.repeat(32),taskDefinitionArn:target.taskDefinitionArn,clusterArn,lastStatus:'STOPPED',launchType:'FARGATE',startedBy:'chronos-schedule/example',
    startedAt:new Date(now-50000),stoppedAt:new Date(now-10000),attributes:[{name:'ecs.cpu-architecture',value:'arm64'}],containers:[{name:target.containerName,image:target.image,imageDigest:'sha256:'+h('e'),exitCode:0}],overrides:{containerOverrides:[{name:target.containerName,environment:env}]}};
  const event={eventID:'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',eventSource:'ecs.amazonaws.com',eventName:'RunTask',eventType:'AwsApiCall',eventTime:new Date(now-59000).toISOString(),awsRegion:region,recipientAccountId:account,
    userIdentity:{type:'AssumedRole',accountId:account,principalId:role.RoleId+':session',arn:`arn:aws:sts::${account}:assumed-role/${roleArn.split('/').at(-1)}/session`,sessionContext:{sessionIssuer:{arn:roleArn,principalId:role.RoleId}}},
    requestParameters:{cluster:clusterArn,taskDefinition:target.taskDefinitionArn,count:1,launchType:'FARGATE',startedBy:task.startedBy,overrides:{containerOverrides:[{name:target.containerName,environment:'HIDDEN_DUE_TO_SECURITY_REASONS'}]},networkConfiguration:{awsvpcConfiguration:{assignPublicIp:'DISABLED',subnets:target.subnets,securityGroups:[target.securityGroup]}}},
    responseElements:{tasks:[{taskArn:task.taskArn,clusterArn,taskDefinitionArn:target.taskDefinitionArn}],failures:[]}};
  const record={event:'consolidation_worker',stage:'prod',kind:'planner',outcome:'complete',slices:1,classified:0,changedRows:0,failedSlices:0,startedMs:now-49000,finishedMs:now-11000};
  return {input:{task,definition,record,event,role},target,options:{admission,artifact:{rootDigest:'sha256:'+h('b'),arm64Digest:'sha256:'+h('e')},afterMs:now-120000,now}};
}
