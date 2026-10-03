import {readFileSync} from 'node:fs';
import {parse} from 'yaml';
import {it,expect} from 'vitest';
const workflow=parse(readFileSync(new URL('../.github/workflows/infra-ci.yml',import.meta.url),'utf8'));
it('builds fixture images only for preview and derives the runner from the exact bootstrap digest',()=>{
 const build=workflow.jobs['build-and-push-image'];
 expect(build.outputs.fixture_runner_digest).toBe('${{ steps.canary-runner.outputs.digest }}');
 expect(build.outputs.fixture_database_digest).toBe('${{ steps.canary-database.outputs.digest }}');
 for(const id of ['canary-runner','canary-database']){
  const step=build.steps.find(s=>s.id===id);expect(step.if).toContain("github.event_name == 'pull_request'");
  expect(step.with.platforms).toBe('linux/arm64');expect(step.with.tags).toContain('/bootstrap:');
 }
 expect(build.steps.find(s=>s.id==='canary-runner').with['build-args']).toContain('bootstrap@${{ steps.bootstrap.outputs.digest }}');
});
it('requires the real preview task before the release fixture can be accepted',()=>{
 const steps=workflow.jobs['deploy-preview'].steps,step=steps.find(s=>s.name==='Canary continuation fixture (preview, hard)');
 expect(step.run).toBe('node scripts/canary-fixture-e2e.mjs');
 expect(step['continue-on-error']).not.toBe(true);
 expect(step.env.EXPECTED_FIXTURE_RUNNER_DIGEST).toBe('${{ needs.build-and-push-image.outputs.fixture_runner_digest }}');
 expect(step.env.MEM9_FIXTURE_SOURCE_COMMIT).toBe('${{ github.event.pull_request.head.sha }}');
 expect(workflow.jobs['deploy-prod'].steps.some(s=>s.run?.includes('canary-fixture-e2e'))).toBe(false);
});
