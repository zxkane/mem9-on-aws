/** Pure schema decoding, bundled with the project's locked SDK dependencies. */
import {JsonCodec2} from '@aws-sdk/core/protocols';
import {RunTaskCommand,RegisterTaskDefinitionCommand,CreateServiceCommand,DescribeServicesCommand,ListTasksCommand,DescribeTasksCommand,DescribeTaskDefinitionCommand,UpdateServiceCommand,StopTaskCommand,DeleteServiceCommand,DeregisterTaskDefinitionCommand,DeleteTaskDefinitionsCommand} from '@aws-sdk/client-ecs';
import {GetParameterCommand} from '@aws-sdk/client-ssm';
import {GetServiceCommand} from '@aws-sdk/client-servicediscovery';
import {FilterLogEventsCommand} from '@aws-sdk/client-cloudwatch-logs';
import {GetMetricStatisticsCommand} from '@aws-sdk/client-cloudwatch';
import {GetServiceQuotaCommand} from '@aws-sdk/client-service-quotas';

const commands=new Map(Object.entries({RunTask:RunTaskCommand,RegisterTaskDefinition:RegisterTaskDefinitionCommand,
 CreateService:CreateServiceCommand,DescribeServices:DescribeServicesCommand,ListTasks:ListTasksCommand,
 DescribeTasks:DescribeTasksCommand,DescribeTaskDefinition:DescribeTaskDefinitionCommand,UpdateService:UpdateServiceCommand,
 StopTask:StopTaskCommand,DeleteService:DeleteServiceCommand,DeregisterTaskDefinition:DeregisterTaskDefinitionCommand,
 DeleteTaskDefinitions:DeleteTaskDefinitionsCommand,GetParameter:GetParameterCommand,GetService:GetServiceCommand,
 FilterLogEvents:FilterLogEventsCommand,GetMetricStatistics:GetMetricStatisticsCommand,
 GetServiceQuota:GetServiceQuotaCommand}));

export const hasObserverSdkAction=action=>commands.has(action);
export function decodeObserverSdkResponse(action,text){
 if(!commands.has(action))throw Error('ObserverArchivedCodecInput');
 const schema=new (commands.get(action))({}).schema;
 if(!Array.isArray(schema)||schema[0]!==9||schema[2]!==action||schema.length!==6)throw Error('ObserverArchivedSdkOperationSchema');
 const decoder=new JsonCodec2({timestampFormat:{useTrait:true,default:7},jsonName:false}).createDeserializer();
 if(decoder.constructor.name!=='JsonShapeDeserializer2'||decoder.read.constructor.name!=='AsyncFunction')throw Error('ObserverArchivedSdkJsonCodec');
 return decoder.read(schema[5],text);
}
