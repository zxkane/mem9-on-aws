import {createHash} from 'node:crypto';
import {nonrootDeploymentFixture} from './production-nonroot-provenance.fixture.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {createNonrootEvidenceArchive} from './lib/production-nonroot-archive.mjs';
import {futureRootScope} from './lib/ci-smoke-owner-delivery.mjs';
const sha=raw=>createHash('sha256').update(raw).digest('hex');

/** Synthetic producer-shaped records. Deliberate newlines distinguish raw
 * commitments from semantic JSON equality; no execution authority is made. */
export async function rootOriginalsFixture(){
 const d=await nonrootDeploymentFixture({now:Date.now()}),deploymentSource=structuredClone(d.record),source=d.source,rows=[];
 const add=(value,purpose)=>{const bytes=Buffer.from(JSON.stringify(value)+'\n'),ref={bytesHash:sha(bytes),canonicalHash:hash(value),bytesLength:bytes.length};rows.push({purpose,ref,bytes});return ref;};
 const originalRefs=[d.record.resolvedTaskPlan,d.record.actualMain.authenticatedSource,...d.record.deployedControlBuild.resolvedLaunches.map(l=>l.registrationBody)];
 const sourceRef=add(source,'build');deploymentSource.actualMain.authenticatedSource=sourceRef;
 const build=deploymentSource.deployedControlBuild;build.actualMain.authenticatedSource=sourceRef;build.source.sourceEvidence=sourceRef;
 for(const launch of build.resolvedLaunches)launch.registrationBody=add(d.controlBodies.get(launch.taskKey),'task-definition');
 const resolved=structuredClone(d.resolved);resolved.deployedControlBuildHash=hash(build);resolved.controlLaunches=build.resolvedLaunches;
 for(const task of resolved.tasks){const launch=build.resolvedLaunches.find(l=>l.taskKey===task.taskKey);if(launch)task.registrationBody=launch.registrationBody;}
 deploymentSource.resolvedTaskPlan=add(resolved,'build');
 const oldKeys=new Set(originalRefs.map(hash)),manifest=d.a.manifest();manifest.files=manifest.files.filter(row=>!oldKeys.has(hash(row.ref)));
 const objects=new Map(d.a.objects);for(const row of rows){const name='sha256-'+row.ref.bytesHash+'.json';manifest.files.push({name,purpose:row.purpose,encoding:'json',ref:row.ref});objects.set(name,row.bytes);}
 const reads=[],archive=createNonrootEvidenceArchive(JSON.stringify(manifest),{expectedManifestHash:hash(manifest),readObject:async name=>{reads.push(name);return objects.get(name);}});
 const scope=futureRootScope('deploy-prod/23'),now=Date.now(),binding={source:{repository:source.repository,runId:source.run.id,runAttempt:source.run.attempt,mainRevision:source.checkout.sha,mainTree:source.checkout.tree}};
 const config={account:d.build.image.account,region:d.build.image.region,ownerRoot:{runtimeNonce:'c'.repeat(32),authorizationId:'d'.repeat(32)},storage:{bucket:'example-artifacts',kmsKeyArn:`arn:aws:kms:${d.build.image.region}:${d.build.image.account}:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee`,bucketKeyEnabled:true},target:{parameterVersion:2},startup:{grantSetId:'a'.repeat(64),proofHash:deploymentSource.proofHash,descriptorHash:deploymentSource.descriptorHash,notAfter:now+300000,ownerGithubActorId:42}};
 const startupReceipt={nonce:'b'.repeat(64),artifactId:78},input={config,scope,binding,startupReceipt,parameter:{Version:2},source,deploymentSource,targetObservation:{serviceObservation:{descriptorHash:deploymentSource.descriptorHash,parameterVersion:2}},requestedMs:now};
 return {d,archive,rows,manifest,objects,reads,input,expected:{config,scope,binding,startupReceipt,now}};
}
