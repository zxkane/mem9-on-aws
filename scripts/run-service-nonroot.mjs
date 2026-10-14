import assert from 'node:assert/strict';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {dirname,resolve} from 'node:path';
import {setTimeout as wait} from 'node:timers/promises';
import {buildServiceNonrootPlan,applyServiceNonrootPlan,inspectServiceNonrootOperation} from './lib/service-nonroot-operation.mjs';
import {createServiceNonrootAws,currentSource,readPrivateJson,writePrivateJson} from './lib/service-nonroot-aws.mjs';
import {verifyServiceRuntime} from './lib/service-nonroot-runtime.mjs';
import {runServiceNonrootAudit} from './lib/service-nonroot-audit.mjs';
import {serviceNonrootHash as hash} from './lib/service-nonroot.mjs';
import {validateServiceEvidence} from './lib/service-nonroot-evidence.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const evidenceKeys=['review','images','local','preview','fences','maintenance'];
function exact(value,keys){assert(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===keys.slice().sort().join(),'OperatorConfigurationFields');}
async function loadConfig(path){
 const config=await readPrivateJson(path);
 exact(config,['version','scope','operationId','directory','authMode','evidence']);assert.equal(config.version,1);
 exact(config.scope,['account','region','cluster','service','bucket','lockKey']);exact(config.evidence,evidenceKeys);
 assert(['managed','oidc'].includes(config.authMode));assert(/^[a-f0-9]{32}$/.test(config.operationId));
 assert(resolve(config.directory)===config.directory);
 return config;
}
async function evidenceValues(config){
 const values={};
 for(const key of evidenceKeys){
  const ref=config.evidence[key];exact(ref,['path','hash']);assert(resolve(ref.path)===ref.path&&/^[a-f0-9]{64}$/.test(ref.hash));
  const value=await readPrivateJson(ref.path);assert.equal(hash(value),ref.hash,'EvidenceChanged');values[key]=value;
 }
 return values;
}
async function assertEvidenceBindings(plan,config,values){
 assert.deepEqual(plan.evidence,Object.fromEntries(evidenceKeys.map(k=>[k,config.evidence[k].hash])));
 assert.deepEqual(values.review.source,plan.source,'ReviewedSourceChanged');
 assert.equal(values.review.targetHash,hash(plan.target),'ReviewedTargetChanged');
 assert(Array.isArray(values.review.reviewers)&&values.review.reviewers.length>=2&&values.review.reviewers.every(r=>typeof r.identity==='string'&&r.verdict==='PASS'),'IndependentReviewRequired');
 const images=Object.fromEntries(plan.target.containerDefinitions.map(c=>[c.name,c.image]));
 assert.deepEqual(values.images.images,images,'ImageEvidenceChanged');
 await validateServiceEvidence(plan,values,{root});
 assert.equal(values.fences.bucket,config.scope.bucket);assert.equal(values.fences.lockKey,config.scope.lockKey);
 assert.equal(values.fences.sourceTree,plan.source.tree,'FenceCoverageSourceChanged');
 assert(values.maintenance.audit?.projectionHash&&values.maintenance.metadata,'MaintenanceAuditRequired');
}

export async function main(args=process.argv.slice(2)){
 assert(['plan','apply','inspect'].includes(args[0])&&args.length===(args[0]==='plan'?3:4),'Usage: plan CONFIG OUTPUT | apply CONFIG PLAN HASH | inspect CONFIG PLAN HASH');
 const [mode,configPath,planPath,expectedHash]=args,config=await loadConfig(resolve(configPath));
 const aws=await createServiceNonrootAws({...config,root});
 try{
  if(mode==='plan'){
   const service=await aws.readService(),definition=await aws.readDefinition(service.taskDefinition),source=await currentSource(root);
   const plan=buildServiceNonrootPlan({scope:aws.scope,source,service,definition,owner:config.operationId,evidence:Object.fromEntries(evidenceKeys.map(k=>[k,config.evidence[k].hash]))});
   const values=await evidenceValues(config);await assertEvidenceBindings(plan,config,values);
   assert.deepEqual(await aws.pausedSnapshot(),values.maintenance.metadata,'MaintenanceMetadataChanged');
   assert(Date.now()-values.maintenance.audit.observedMs<300000,'FreshMaintenanceAuditRequired');
   await writePrivateJson(resolve(planPath),plan);return {status:'prepared',planHash:plan.hash,expiresAt:plan.expiresAt};
  }
  const plan=await readPrivateJson(resolve(planPath));
  if(mode==='inspect'){
   const result=await inspectServiceNonrootOperation(plan,{expectedHash,io:aws});
   const output=resolve(config.directory,'inspection-'+Date.now()+'.json');await writePrivateJson(output,result);
   return {status:result.status,evidence:output};
  }
  let values;
  const io={...aws,wait,
   assertEvidence:async p=>{values=await evidenceValues(config);await assertEvidenceBindings(p,config,values);},
   acquireFences:async p=>{
    await aws.acquireFences(p);
    const audit=await runServiceNonrootAudit({scope:config.scope,phase:'before',operationId:config.operationId,persistOnce:aws.persistOnce,readRecord:aws.readRecord,assertCurrent:aws.assertFences,expectedProjection:values.maintenance.audit.projection});
    assert.equal(audit.projectionHash,values.maintenance.audit.projectionHash,'HistoricalMaintenanceStateChanged');
    await aws.persistOnce('pre-remediation-audit.json',audit);
   },
   assertPaused:async()=>{assert.deepEqual(await aws.pausedSnapshot(),values.maintenance.metadata,'MaintenanceMetadataChanged');},
   verifyRuntime:async(arn,{plan:p,deadline})=>{
    const receipt=await verifyServiceRuntime(arn,{plan:p,deadline,aws,scope:config.scope,authMode:config.authMode});
    const audit=await runServiceNonrootAudit({scope:config.scope,phase:'after',operationId:config.operationId,persistOnce:aws.persistOnce,readRecord:aws.readRecord,assertCurrent:aws.assertFences,expectedProjection:values.maintenance.audit.projection});
    assert.equal(audit.projectionHash,values.maintenance.audit.projectionHash,'HistoricalMaintenanceStateChanged');
    await aws.persistOnce('post-remediation-audit.json',audit);return receipt;
   },
  };
  return await applyServiceNonrootPlan(plan,{expectedHash,source:()=>currentSource(root),io});
 }finally{aws.close();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 main().then(value=>console.log(JSON.stringify(value))).catch(error=>{
  // Provider messages, responses and memory contents are intentionally omitted.
  const code=/^service-nonroot:[a-z-]+$/.test(error.message)?error.message:error.code??error.name;
  console.error(JSON.stringify({status:'held',code,reconciliationRequired:true}));process.exitCode=1;
 });
}
