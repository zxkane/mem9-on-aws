/** Original purposes, selected only by the source plan version. */
export function observerSessionPurposes(plan){
 return ['read','setup',...(plan.version===3?['service']:[]),'update','cleanup',...(plan.geometry.control?['launch']:[]),...(plan.version===3?['logs','cleanup-read']:[])];
}
export const observerCleanupPurpose=purpose=>purpose==='cleanup'||purpose==='cleanup-read';
export function observerProviderPurpose(plan,row){
 if(row.cleanup)return plan.version===3&&['DescribeServices','DescribeTaskDefinition','ListTasks','DescribeTasks','ListInstances'].includes(row.action)?'cleanup-read':'cleanup';
 if(row.action==='FilterLogEvents'&&plan.version===3)return 'logs';
 if(row.action==='RunTask')return 'launch';
 if(row.action==='CreateService'&&plan.version===3)return 'service';
 if(['RegisterTaskDefinition','CreateService'].includes(row.action))return 'setup';
 if(['UpdateService','StopTask'].includes(row.action))return 'update';
 return 'read';
}
