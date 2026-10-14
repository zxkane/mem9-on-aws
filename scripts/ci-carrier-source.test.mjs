import {it,expect} from 'vitest';
import {CARRIER_JOB,verifyCarrierWorkerSource} from './lib/ci-carrier-source.mjs';
import {carrierFixture} from './ci-carrier.fixture.mjs';

it('binds the compiled carrier job, actual dispatch/checkout and independent preview role',()=>{
 const f=carrierFixture();const binding=verifyCarrierWorkerSource(f.sourceInput);
 expect(binding).toMatchObject({kind:'carrier-actual-run-binding',jobId:73,runId:71,runAttempt:1});
 expect(binding.source.jobKey).toBe(CARRIER_JOB.key);
});
it.each(['jobKey','jobName','workflowPath'])('rejects a structurally valid but uncompiled %s',key=>{
 const f=carrierFixture();f.plan.template.source[key]=key==='workflowPath'?'.github/workflows/foreign.yml':'foreign';
 expect(()=>verifyCarrierWorkerSource(f.sourceInput)).toThrow();
});
it.each(['GITHUB_JOB','GITHUB_SHA','GITHUB_WORKFLOW_SHA','GITHUB_WORKFLOW_REF','GITHUB_EVENT_NAME','GITHUB_REF','AWS_PREVIEW_ROLE_ARN'])('checks independent %s before any acquisition',key=>{
 const f=carrierFixture();f.sourceInput.env[key]='other';
 expect(()=>verifyCarrierWorkerSource(f.sourceInput)).toThrow('CarrierWorker');
});
it('rejects a same-account role substituted in otherwise valid funding data',()=>{
 const f=carrierFixture();f.plan.template.scope.previewRoleArn='arn:aws:iam::123456789012:role/other-preview';
 expect(()=>verifyCarrierWorkerSource(f.sourceInput)).toThrow('CarrierWorkerPreviewRole');
});
it.each(['checkout','commit','job','run','pullRequest'])('does not treat matching environment as authenticated %s',key=>{
 const f=carrierFixture();if(key==='checkout')f.sourceInput.checkout.tree='f'.repeat(40);
 else f.sourceInput.observations[key]={};
 expect(()=>verifyCarrierWorkerSource(f.sourceInput)).toThrow();
});
