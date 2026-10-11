/** Complete reviewed CI harness. Callers cannot replace its commands,
 * permissions, environment, cleanup or image-selection steps via a hash. */
export function ciSmokeJobDefinition(){
 const role="${{ github.event_name == 'pull_request' && secrets.AWS_PREVIEW_ROLE_ARN || secrets.AWS_PROD_ROLE_ARN }}";
 return {
  name:'Mnemo nonroot smoke',
  'runs-on':"${{ vars.RUNNER_LABEL && fromJSON(vars.RUNNER_LABEL) || 'ubuntu-latest' }}",
  environment:"${{ github.event_name == 'pull_request' && 'preview-ci' || 'prod' }}",
  needs:['application-region','build-and-push-image'],
  if:"!cancelled() && needs.application-region.result == 'success' && needs.build-and-push-image.result == 'success' && needs.build-and-push-image.outputs.mnemo_digest != '' && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)",
  'timeout-minutes':15,
  permissions:{'id-token':'write',contents:'read',actions:'read'},
  env:{
   AWS_REGION:'${{ needs.application-region.outputs.region }}',
   STAGE:"${{ github.event_name == 'pull_request' && format('pr-{0}', github.event.pull_request.number) || 'prod' }}",
   MEM9_DEPLOY_ROLE_ARN:role,
   MNEMO_DIGEST:'${{ needs.build-and-push-image.outputs.mnemo_digest }}',
   MEM9_CI_EVIDENCE_KMS_KEY_ARN:'${{ secrets.MEM9_CI_EVIDENCE_KMS_KEY_ARN }}',
   MEM9_CI_SMOKE_LINEAGE:'${{ secrets.MEM9_CI_SMOKE_LINEAGE }}',
  },
  outputs:{commitment:'${{ steps.publish.outputs.commitment }}'},
  steps:[
   {name:'Deployment maintenance gate',shell:'bash',env:{PAUSED:'${{ vars.DEPLOYMENT_MAINTENANCE_PAUSED }}',BOUNDARY:'${{ vars.WORKLOAD_BOUNDARY_PROD_ENABLED }}'},
    run:'test "$PAUSED" != true && test "$BOUNDARY" = true'},
   {uses:'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',with:{'fetch-depth':0}},
   {uses:'actions/setup-node@820762786026740c76f36085b0efc47a31fe5020',with:{'node-version':24}},
   {name:'Install smoke verification dependencies',run:'npm ci'},
   {name:'Prepare isolated smoke Docker',run:'node scripts/verify-smoke-docker.mjs prepare'},
   {name:'Set up isolated smoke Docker',uses:'docker/setup-docker-action@2bf61fb9464cc67f0cbdeabed6aa0380accd1c70',with:{version:'v29.9.0',context:'setup-docker-action','set-host':true,'runtime-basedir':'${{ runner.temp }}/mem9-smoke-docker','daemon-config':'{"debug":false,"log-level":"info","features":{"containerd-snapshotter":true}}'}},
   {name:'Verify isolated smoke Docker',run:'node scripts/verify-smoke-docker.mjs verify'},
   {name:'Authenticate smoke build and source',env:{GH_TOKEN:'${{ github.token }}'},run:'node scripts/verify-ci-smoke-isolation.mjs prepare-smoke'},
   {name:'Set up QEMU',uses:'docker/setup-qemu-action@99012661954931238ded8c8b007157a8430204e1',with:{platforms:'arm64'}},
   {name:'Configure smoke registry credentials',id:'smoke_credentials',uses:'aws-actions/configure-aws-credentials@e1253824e5c10ff9df46874f81ed3ec929e19cfd',
    with:{'role-to-assume':role,'aws-region':'${{ env.AWS_REGION }}','mask-aws-account-id':true,'output-credentials':true}},
   {name:'Log in to Amazon ECR',uses:'aws-actions/amazon-ecr-login@03f1aad4c6c7ffd436567f42f9384779290529bd'},
   {name:'Acquire exact smoke image digests',run:'node scripts/verify-ci-smoke-isolation.mjs acquire-smoke'},
   {name:'Run isolated fourteen-check smoke',run:'bash scripts/run-mnemo-nonroot-smoke.sh --input "$RUNNER_TEMP/mem9-ci-smoke-input.json" --output-dir "$RUNNER_TEMP/mem9-ci-smoke-evidence"'},
   {name:'Verify and preserve private smoke evidence',id:'publish',env:{GH_TOKEN:'${{ github.token }}',MEM9_CI_CREDENTIALS_EXPIRES:'${{ steps.smoke_credentials.outputs.aws-expiration }}'},run:'node scripts/verify-ci-smoke-isolation.mjs publish-smoke'},
   {name:'Remove owned smoke evidence',if:'always()',run:'node scripts/verify-ci-smoke-isolation.mjs cleanup-smoke'},
  ],
 };
}

/** CONTROL evidence crosses jobs only through the existing private bucket.
 * The job output contains the bounded public commitment, never the capsule. */
export function controlBuildCaptureSteps(){
 const source={STAGE:'prod',GH_TOKEN:'${{ github.token }}'};
 return {
  prepare:{name:'Verify CONTROL build context',env:source,run:'node scripts/record-nonroot-control-build.mjs prepare'},
  capture:{name:'Record actual CONTROL build action',env:{...source,MEM9_CONTROL_BUILD_METADATA:'${{ steps.bootstrap.outputs.metadata }}',MEM9_EXPECTED_BOOTSTRAP_DIGEST:'${{ steps.bootstrap.outputs.digest }}'},run:'node scripts/record-nonroot-control-build.mjs capture'},
  publish:{name:'Preserve private CONTROL build capture',id:'publish_control_capture',env:{...source,MEM9_DEPLOY_ROLE_ARN:'${{ secrets.AWS_PROD_ROLE_ARN }}',MEM9_DECISION_ARTIFACT_BUCKET:'${{ vars.MEM9_DECISION_ARTIFACT_BUCKET }}',MEM9_CI_EVIDENCE_KMS_KEY_ARN:'${{ secrets.MEM9_CI_EVIDENCE_KMS_KEY_ARN }}',MEM9_CI_CREDENTIALS_EXPIRES:'${{ steps.control_credentials.outputs.aws-expiration }}'},run:'node scripts/record-nonroot-control-build.mjs publish'},
  cleanup:{name:'Remove owned CONTROL build capture',if:'always()',run:'node scripts/record-nonroot-control-build.mjs cleanup'},
 };
}
