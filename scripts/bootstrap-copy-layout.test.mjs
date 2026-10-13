import {it,expect} from 'vitest';
import {readFileSync,mkdtempSync,mkdirSync,copyFileSync,rmSync} from 'node:fs';
import {posix,join,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {dataCopySources} from './lib/production-data-build-inputs.mjs';
import {FUTURE_CONTROL_CAPACITY,verifyFutureControlGraphCapacity} from './lib/production-control-capacity.mjs';

const expectedCopies = {
  "2": {
    "/bootstrap/": [
      "docker/bootstrap/schema.sql",
      "docker/bootstrap/runtime-contract.sql",
      "docker/bootstrap/schema-digest.sh"
    ],
    "/bootstrap/migrations/": [
      "docker/bootstrap/migrations/"
    ],
    "/bootstrap/operator/docker/bootstrap/": [
      "docker/bootstrap/schema-digest.sh"
    ]
  },
  "3": {
    "/bootstrap/": [
      "docker/bootstrap/entrypoint.sh"
    ],
    "/bootstrap/operator/": [
      "docker/bootstrap/operator-entrypoint.mjs",
      "package.json",
      "package-lock.json"
    ],
    "/bootstrap/operator/scripts/lib/": [
      "scripts/lib/memory-namespace.mjs",
      "scripts/lib/memory-ingest-cancellation.mjs",
      "scripts/lib/production-canary-continuation.mjs",
      "scripts/lib/production-canary-compatibility.mjs",
      "scripts/lib/production-canary-transition.mjs",
      "scripts/lib/production-image-transition.mjs",
      "scripts/lib/production-canary-snapshot.mjs",
      "scripts/lib/production-canary-paused-audit.mjs",
      "scripts/lib/production-nonroot-contracts.mjs",
      "scripts/lib/production-nonroot-runtime.mjs",
      "scripts/lib/production-nonroot-control-current.mjs",
      "scripts/lib/production-nonroot-launch.mjs",
      "scripts/lib/nonroot-preview-source.mjs",
      "scripts/lib/production-canary-verification.mjs",
      "scripts/lib/production-canary-performance.mjs",
      "scripts/lib/production-canary-report.mjs",
      "scripts/lib/canary-benchmark.mjs",
      "scripts/lib/production-artifacts.mjs",
      "scripts/lib/production-runtime-config.mjs",
      "scripts/lib/production-runtime-state.mjs",
      "scripts/lib/production-runtime-credentials.mjs",
      "scripts/lib/production-runtime-ownership.mjs",
      "scripts/lib/production-runtime-rehearsal.mjs",
      "scripts/lib/production-runtime-cancellation.mjs",
      "scripts/lib/runtime-extension-catalog.mjs",
      "scripts/lib/runtime-admin-probe-config.mjs",
      "scripts/lib/runtime-credentials.mjs",
      "scripts/lib/consolidation-preview-config.mjs",
      "scripts/lib/post-runtime-preview-authority.mjs",
      "scripts/lib/post-runtime-preview-route.mjs",
      "scripts/lib/consolidation-preview-secrets.mjs"
    ],
    "/bootstrap/operator/scripts/": [
      "scripts/manage-memory-access.mjs",
      "scripts/manage-memory-services.mjs",
      "scripts/migrate-memory-namespaces.mjs",
      "scripts/benchmark-memory-namespaces.mjs",
      "scripts/observe-memory-namespace-connections.mjs",
      "scripts/prepare-preview-memory-namespaces.mjs",
      "scripts/consolidation-preview-fixture.mjs",
      "scripts/runtime-bootstrap.mjs",
      "scripts/runtime-admin-probe.mjs",
      "scripts/production-runtime-operator.mjs",
      "scripts/production-consolidation-operator.mjs",
      "scripts/seed-tenant.mjs",
      "scripts/reconcile-memory-namespaces.mjs"
    ],
    "/bootstrap/operator/infra/gateway/": [
      "infra/gateway/service-auth.mjs"
    ],
    "/bootstrap/operator/docker/bootstrap/migrations/": [
      "docker/bootstrap/migrations/003_enforce_memory_namespaces.sql"
    ]
  },
  "5": {
    "/bootstrap/": [
      "docker/bootstrap/nonroot-dispatch.mjs",
      "docker/bootstrap/nonroot-files.mjs",
      "docker/bootstrap/nonroot-identity.mjs"
    ],
    "/bootstrap/operator/scripts/": [
      "scripts/production-continuation-inspection.mjs",
      "scripts/validate-emf-event.mjs"
    ],
    "/bootstrap/operator/scripts/lib/": [
      "scripts/lib/production-continuation-inspection.mjs",
      "scripts/lib/production-continuation-root.mjs",
      "scripts/lib/production-continuation-publication.mjs",
      "scripts/lib/production-continuation-absence.mjs",
      "scripts/lib/production-nonroot-local-work.mjs",
      "scripts/lib/production-nonroot-archive-capacity.mjs",
      "scripts/lib/ci-smoke-acquisition-format.mjs",
      "scripts/lib/ci-smoke-evidence.mjs",
      "scripts/lib/production-nonroot-budget-revision.mjs",
      "scripts/lib/production-nonroot-observer-control-context.mjs",
      "scripts/lib/production-nonroot-observer-delivery.mjs",
      "scripts/lib/production-nonroot-observer-peer-inventory.mjs",
      "scripts/lib/production-nonroot-observer-timeline.mjs",
      "scripts/lib/production-nonroot-observer-route-attribution.mjs",
      "scripts/lib/production-nonroot-observer-topology.mjs",
      "scripts/lib/production-nonroot-engineering-json.mjs",
      "scripts/lib/production-nonroot-observer-route-probe.mjs",
      "scripts/lib/production-nonroot-observer-runtime-provider.mjs",
      "scripts/lib/production-nonroot-observer-route-protocol.mjs",
      "scripts/lib/production-nonroot-observer-finalization-work.mjs"
    ],
    "/bootstrap/operator/infra/gateway/": [
      "infra/gateway/namespace-auth.mjs"
    ],
    "/usr/local/lib/mem9/": [
      "scripts/build-nonroot-manifest.mjs"
    ]
  }
};

const source=()=>readFileSync(new URL('../docker/bootstrap/Dockerfile',import.meta.url),'utf8');
function copies(text){
 // Use the existing strict recipe parser before examining destinations.
 dataCopySources(text);let runs=0;const rows=[];
 for(const raw of text.split(/\r?\n/)){
  const line=raw.trim();if(line.startsWith('RUN '))runs++;
  if(!line.startsWith('COPY '))continue;
  const words=line.split(/\s+/).slice(1),target=words.pop();
  for(const input of words){
   expect(input).not.toMatch(/[?*]/);
   expect(target.startsWith('/')).toBe(true);
   rows.push({runs,input,target:target.endsWith('/')?target+(input.endsWith('/')?'':posix.basename(input)):target});
  }
 }
 return rows;
}
const expectedRows=()=>Object.entries(expectedCopies).flatMap(([runs,dirs])=>Object.entries(dirs).flatMap(([target,inputs])=>inputs.map(input=>({runs:Number(runs),input,target:target+(input.endsWith('/')?'':posix.basename(input))}))));
const ordered=rows=>rows.toSorted((a,b)=>a.runs-b.runs||a.target.localeCompare(b.target)||a.input.localeCompare(b.input));
it('preserves every explicit bootstrap source/destination at its original RUN boundary',()=>{
 const actual=copies(source());expect(ordered(actual)).toEqual(ordered(expectedRows()));
 expect(new Set(actual.map(r=>r.target)).size).toBe(actual.length);
 expect(dataCopySources(source())).toEqual([...new Set(expectedRows().map(r=>r.input))].sort());
});
it('keeps dependency installation, permissions, manifest generation and nonroot launch ordered',()=>{
 const text=source(),schema=text.indexOf('RUN sh /bootstrap/schema-digest.sh'),npm=text.indexOf('RUN cd /bootstrap/operator && npm ci --omit=dev'),chmod=text.indexOf('RUN chmod +x /bootstrap/entrypoint.sh'),manifest=text.indexOf('RUN chmod -R a+rX,go-w /bootstrap'),user=text.indexOf('USER node'),imports=text.indexOf('RUN --network=none /usr/local/bin/node');
 expect(schema).toBeGreaterThan(0);expect(npm).toBeGreaterThan(schema);expect(chmod).toBeGreaterThan(npm);expect(manifest).toBeGreaterThan(chmod);expect(user).toBeGreaterThan(manifest);expect(imports).toBeGreaterThan(user);
 expect(text).toContain('&& node /usr/local/lib/mem9/build-nonroot-manifest.mjs');
 expect(text).toMatch(/^FROM node:24-alpine3\.24 AS runtime$/m);
 expect(text).toMatch(/^ENTRYPOINT \["\/bootstrap\/entrypoint\.sh"\]$/m);
 expect(text.match(/^RUN /gm)).toHaveLength(7);
});
function graph(layerCount){
 const nodes=[],add=(mediaType,n)=>{for(let i=0;i<n;i++)nodes.push({digest:'sha256:'+(nodes.length+1).toString(16).padStart(64,'0'),size:1,mediaType});};
 add('application/vnd.oci.image.index.v1+json',1);add('application/vnd.oci.image.manifest.v1+json',2);add('application/vnd.oci.image.config.v1+json',2);
 add('application/vnd.in-toto+json',1);add('application/vnd.oci.image.layer.v1.tar+gzip',layerCount-1);return nodes;
}
it('leaves at least ten layer slots even with a synthetic sixteen-layer base/attestation allowance',()=>{
 const text=source();dataCopySources(text);
 // Static regression allowance, not a measurement of the rebuilt image.
 // Native acquisition must still verify its complete actual descriptor graph.
 const recipeLayers=(text.match(/^(?:COPY|RUN) /gm)??[]).length,nonRecipeAllowance=16;
 expect(FUTURE_CONTROL_CAPACITY.layerNodes).toBe(64);
 expect(recipeLayers+nonRecipeAllowance).toBeLessThanOrEqual(FUTURE_CONTROL_CAPACITY.layerNodes-10);
 const result=verifyFutureControlGraphCapacity(graph(recipeLayers+nonRecipeAllowance),FUTURE_CONTROL_CAPACITY);
 expect(result.layerNodes).toBe(recipeLayers+nonRecipeAllowance);expect(result.capacityVerified).toBe(false);
 expect(()=>verifyFutureControlGraphCapacity(graph(FUTURE_CONTROL_CAPACITY.layerNodes+1),FUTURE_CONTROL_CAPACITY)).toThrow('FutureControlGraphCapacity');
});
it('detects a missing operand, wrong destination or COPY moved across npm',()=>{
 const text=source(),expected=ordered(expectedRows()),input='scripts/benchmark-memory-namespaces.mjs';
 for(const changed of [text.replace(input,''),text.replace('/bootstrap/operator/scripts/','/bootstrap/other/'),text.replace(/^COPY package.json package-lock.json \/bootstrap\/operator\/\n/m,'').replace('RUN cd /bootstrap/operator && npm ci --omit=dev','RUN cd /bootstrap/operator && npm ci --omit=dev\nCOPY package.json package-lock.json /bootstrap/operator/')]){
  expect(()=>expect(ordered(copies(changed))).toEqual(expected)).toThrow();
 }
});
it('imports observer CONTROL from only the Docker COPY files and rejects either missing dependency',()=>{
 const directory=mkdtempSync(join(tmpdir(),'bootstrap-control-copy-'));
 const root=fileURLToPath(new URL('..',import.meta.url));
 try{
  for(const omitted of [null,'production-nonroot-observer-topology.mjs','production-nonroot-engineering-json.mjs',
    'production-nonroot-observer-peer-inventory.mjs','production-nonroot-observer-timeline.mjs','production-nonroot-observer-route-attribution.mjs']){
   const target=join(directory,omitted??'complete');
   for(const row of copies(source())){
    if(!row.target.startsWith('/bootstrap/operator/scripts/')||!row.input.endsWith('.mjs')||posix.basename(row.input)===omitted)continue;
    const file=join(target,row.target);mkdirSync(dirname(file),{recursive:true});copyFileSync(join(root,row.input),file);
   }
   const modules=['production-nonroot-observer-delivery.mjs','production-nonroot-observer-route-protocol.mjs'];
   const urls=modules.map(name=>pathToFileURL(join(target,'/bootstrap/operator/scripts/lib/',name)).href);
   const child=spawnSync(process.execPath,['--input-type=module','--eval',`for(const url of ${JSON.stringify(urls)}) await import(url);`],{
    cwd:target,env:{PATH:process.env.PATH},encoding:'utf8',timeout:15000,maxBuffer:1024*1024,
   });
   expect(child.error).toBeUndefined();
   if(omitted){expect(child.status).toBe(1);expect(child.stderr).toContain('ERR_MODULE_NOT_FOUND');expect(child.stderr).toContain(omitted);}
   else expect(child.status,child.stderr).toBe(0);
  }
 }finally{rmSync(directory,{recursive:true,force:true});}
},20000);
