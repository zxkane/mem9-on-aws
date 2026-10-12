import {observerSessionPurposes,observerProviderPurpose} from './production-nonroot-observer-sessions.mjs';
/** Pure original policy reconstruction after full plan recompilation.
 * Returns DATA only, with no STS operation or source-credential read. */
/** Dedicated observer session attenuation. No grants to P/COPY, ambient role,
 * secrets, Exec or new infrastructure. The fixed provider still checks the
 * exact request and owned response; IAM prefixes are not completion authority.
 * Actions were derived from the provider Autopilot inventory and narrowed
 * against the current ECS service authorization reference. */
import {need,hash} from './production-nonroot-engineering-json.mjs';

export function compileArchivedObserverSessionPolicy(p,purpose){
 const s=p.scope;
 need(observerSessionPurposes(p).includes(purpose),'ObserverSessionPurpose');
 need(s.taskRoleArns.every(a=>a.startsWith('arn:aws:iam::'+s.account+':role/')&&/^[A-Za-z0-9_+=,.@/-]+$/.test(a.split(':role/')[1])),'ObserverPassRoleScope');
 need(s.logGroupArns.every(a=>a.startsWith('arn:aws:logs:'+s.region+':'+s.account+':log-group:')&&/^[A-Za-z0-9_./#-]{1,512}$/.test(a.split(':log-group:')[1])),'ObserverLogPolicyScope');
 need(s.discoveryServiceArns.every(a=>a.startsWith('arn:aws:servicediscovery:'+s.region+':'+s.account+':service/')&&/^srv-[A-Za-z0-9]+$/.test(a.split(':service/')[1])),'ObserverDiscoveryPolicyScope');
 const arn='arn:aws:ecs:'+s.region+':'+s.account+':',cluster=s.clusterArn.slice((arn+'cluster/').length);
 need(/^[A-Za-z0-9_-]{1,255}$/.test(cluster),'ObserverClusterName');
 const prefix='mem9-observe-'+p.owner.slice(0,12)+'-';
 need(p.cases.every(c=>c.serviceName===prefix+(p.geometry.control?c.stage+'-':'')+c.name&&c.family===c.serviceName),'ObserverPolicyScope');
 const service=arn+'service/'+cluster+'/'+prefix+'*',definition=arn+'task-definition/'+prefix+'*:*',task=arn+'task/'+cluster+'/*';
 const statements=[],allow=(Action,Resource,Condition)=>statements.push({Effect:'Allow',Action,Resource,...(Condition?{Condition}:{})});
 const clusterCondition={ArnEquals:{'ecs:cluster':s.clusterArn}};
 const ownerTag={'aws:ResourceTag/observer-owner':p.owner,'aws:ResourceTag/observer-operation':p.operation};
 const requestTag={'aws:RequestTag/observer-owner':p.owner,'aws:RequestTag/observer-operation':p.operation};
 const roles=()=>allow('iam:PassRole',s.taskRoleArns,{StringEquals:{'iam:PassedToService':'ecs-tasks.amazonaws.com'}});
 const read=()=>{
  allow('ecs:DescribeServices',service,clusterCondition);
  // DescribeTaskDefinition has no resource-level authorization. The fixed
  // reader checks the exact previously registered ARN before dispatch.
  allow('ecs:DescribeTaskDefinition','*');
  allow('ecs:ListTasks','*',clusterCondition);
  allow('ecs:DescribeTasks',task,clusterCondition);
 };
 if(purpose==='read'){
  read();allow('ssm:GetParameter',s.rootParameterArn);
  allow(p.geometry.topology===1?['servicediscovery:GetService','servicediscovery:ListInstances']:'servicediscovery:GetService',s.discoveryServiceArns);
  if(p.version!==3)allow('logs:FilterLogEvents',s.logGroupArns.map(a=>a+':*'));
  if(p.version===3){
   allow('servicequotas:GetServiceQuota','arn:aws:servicequotas:'+s.region+':'+s.account+':fargate/L-3032A538');
   // This read action has no resource/namespace IAM condition support.
   // The fixed provider admits only the source-bound Fargate usage request.
   allow('cloudwatch:GetMetricStatistics','*',{StringEquals:{'aws:RequestedRegion':s.region}});
  }
 }else if(purpose==='logs'){
  allow('logs:FilterLogEvents',s.logGroupArns.map(a=>a+':*'));
 }else if(purpose==='setup'){
  allow('ecs:RegisterTaskDefinition',definition,{StringEquals:requestTag,Bool:{'ecs:privileged':'false'}});
  if(p.version!==3)allow('ecs:CreateService',service,{...clusterCondition,StringEquals:requestTag,Bool:{'ecs:enable-execute-command':'false','ecs:auto-assign-public-ip':'false'}});
  allow('ecs:TagResource',p.version===3?[definition]:[definition,service],{StringEquals:{...requestTag,'ecs:CreateAction':['RegisterTaskDefinition','CreateService']}});
  roles();
 }else if(purpose==='service'){
  allow('ecs:CreateService',service,{...clusterCondition,StringEquals:requestTag,Bool:{'ecs:enable-execute-command':'false','ecs:auto-assign-public-ip':'false'}});
  allow('ecs:TagResource',[service],{StringEquals:{...requestTag,'ecs:CreateAction':['RegisterTaskDefinition','CreateService']}});roles();
 }else if(purpose==='launch'){
  allow('ecs:RunTask',definition,{...clusterCondition,StringEquals:requestTag,Bool:{'ecs:enable-execute-command':'false'}});
  allow('ecs:TagResource',task,{StringEquals:{...requestTag,'ecs:CreateAction':'RunTask'}});roles();
 }else if(purpose==='update'){
  allow('ecs:UpdateService',service,{...clusterCondition,StringEquals:ownerTag,ArnLike:{'ecs:task-definition':definition},Bool:{'ecs:enable-execute-command':'false'}});
  // Tags are propagated from the owner-tagged definition by the fixed setup.
  allow('ecs:StopTask',task,{...clusterCondition,StringEquals:ownerTag});roles();
 }else if(purpose==='cleanup-read'){
  read();if(p.geometry.topology===1)allow('servicediscovery:ListInstances',s.discoveryServiceArns);
 }else{
  if(p.version!==3){read();if(p.geometry.topology===1)allow('servicediscovery:ListInstances',s.discoveryServiceArns);}allow('ecs:DeleteService',service,{...clusterCondition,StringEquals:ownerTag});
  // DeregisterTaskDefinition has no resource-level/condition-key support.
  // Exact original ARN authorization stays at validateObserverRequest.
  allow('ecs:DeregisterTaskDefinition','*');
  allow('ecs:DeleteTaskDefinitions',definition,{StringEquals:ownerTag});
  if(p.geometry.control)allow('ecs:StopTask',task,{...clusterCondition,StringEquals:ownerTag});
 }
 const policy={Version:'2012-10-17',Statement:statements},policyJson=JSON.stringify(policy);
 need(policyJson.length<=2048,'ObserverSessionPolicySize');
 return {version:1,kind:'original-observer-session-policy',authority:false,purpose,policy,policyJson,policyHash:hash(policy)};
}
