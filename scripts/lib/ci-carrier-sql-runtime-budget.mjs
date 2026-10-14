/** Pure SQL fixture accounting. These are parts of the original payment, not
 * another allocation. PG package transfer/import is accounted separately. */
import {copyNonrootJson} from './production-nonroot-contracts.mjs';
import {zero,addCounters} from './ci-smoke-acquisition-format.mjs';

export const CARRIER_SQL_FIXTURE_LIMITS=Object.freeze({
 maxDockerCalls:224,maxReadyAttempts:80,readyPollMs:250,maxConnections:64,maxConcurrentConnections:16,
 maxRelayBytes:8388608,relayBufferBytes:8388608,maxDockerOutputBytes:2097152,maxDockerMetadataBytes:65536,
 maxQueryMs:15000,maxSetupMs:90000,cleanupMs:30000,tmpDataBytes:100663296,tmpSocketBytes:1048576,tmpfsBytes:101711872,tmpfsEntries:16384,
 maxSupervisorBytes:32768,maxDockerArgumentBytes:16384,maxDockerProofBytes:4096,maxIntentBytes:16384,
 maxCaseInputBytes:32768,maxCaseEnvironmentBytes:32768,maxFixtureCaBytes:16384,maxManifestBytes:1048576,
 maxCaseProcessEvidenceBytes:139264,
 maxSchemaBytes:8388608,maxSchemaFiles:100,maxSeederSourceBytes:1048576,cases:8,
 packageDockerCalls:5,packageCleanupCalls:2,fixtureCleanupCalls:4,caseCleanupCalls:2,
 maxCarrierLoadCalls:6,maxCarrierLoadOutputBytes:1048576,maxCarrierLoadMetadataBytes:32768,
});
const L=CARRIER_SQL_FIXTURE_LIMITS,need=(ok,code)=>{if(!ok)throw Error(code);};
const logical=n=>({...zero(),logicalBytes:n});
const total=parts=>Object.values(parts).reduce(addCounters,zero());
const variableInputs=Object.freeze(['runtimeFilesBytes','originalSourceBytes','nodeBytes','setprivBytes','carrierGraphBytes','carrierGraphNodes','carrierUncompressedBytes','carrierEntries']);
export function carrierSqlCaseSecurityBytes({runtimeFilesBytes,originalSourceBytes,nodeBytes,setprivBytes}){
 const n=2*(runtimeFilesBytes+nodeBytes+setprivBytes)+originalSourceBytes;
 need(Number.isSafeInteger(n)&&n>0,'CarrierSqlRuntimeBudgetBounds');return n;
}
export function carrierSqlDockerOutputLimit(args){
 return args[0]==='container'&&args[1]==='start'&&args.includes('--attach')?L.maxDockerOutputBytes:L.maxDockerMetadataBytes;
}
export function carrierSqlDockerCommandBudget(outputBytes=L.maxDockerMetadataBytes){
 need([L.maxDockerMetadataBytes,L.maxDockerOutputBytes].includes(outputBytes),'CarrierSqlDockerOutputLimit');
 return L.maxSupervisorBytes+2*L.maxDockerArgumentBytes+L.maxDockerProofBytes+L.maxIntentBytes+outputBytes;
}
/** Complete fixed part, including bounded readiness, teardown, schema/seeder
 * materialization and output handling. Native security reads and the carrier
 * graph import require independent byte bounds; use the full helper below. */
export function carrierSqlRuntimeFixedBudget(){
 const runtimeCalls=L.maxDockerCalls-L.packageDockerCalls,cleanupCalls=L.fixtureCleanupCalls+L.cases*L.caseCleanupCalls;
 const overlayBytes=L.maxFixtureCaBytes+L.maxManifestBytes,overlayTarBytes=overlayBytes+3072;
 const parts={
  fixtureStorage:{...logical(L.tmpfsBytes),uncompressedBytes:L.tmpfsBytes,processedEntries:L.tmpfsEntries},
  relay:logical(L.maxRelayBytes+L.relayBufferBytes),
  dockerControl:{...logical(runtimeCalls*carrierSqlDockerCommandBudget()+L.cases*(L.maxDockerOutputBytes-L.maxDockerMetadataBytes)),processedEntries:L.maxDockerCalls},
  dockerCleanup:{...logical(cleanupCalls*carrierSqlDockerCommandBudget()),processedEntries:cleanupCalls+L.packageCleanupCalls},
  caseInputOutput:{...logical(L.cases*(L.maxCaseEnvironmentBytes+2*L.maxCaseInputBytes+L.maxManifestBytes+L.maxCaseProcessEvidenceBytes+L.maxDockerOutputBytes)),processedEntries:L.cases},
  overlay:{...logical(L.maxManifestBytes+3*overlayBytes+2*(L.cases-1)*overlayBytes+2*overlayTarBytes),processedEntries:2},
  schemaAndSeeder:{...logical(10*L.maxSchemaBytes+2*L.maxSeederSourceBytes),processedEntries:L.maxSchemaFiles},
  // Five bounded execFile stdout+stderr pairs and one combined stdin-load
  // output; the existing loader owns and reaps these six fixed commands.
  carrierLoadControl:logical((2*(L.maxCarrierLoadCalls-1)+1)*L.maxCarrierLoadOutputBytes+2*L.maxCarrierLoadCalls*L.maxDockerArgumentBytes+L.maxSupervisorBytes+L.maxDockerProofBytes),
 };
 return copyNonrootJson({parts,total:total(parts),caseSecurityReadPasses:2*L.cases,additionalUnknownBytes:0});
}
export function carrierSqlFixtureFixedRuntimeBudget(){
 return copyNonrootJson({charge:carrierSqlRuntimeFixedBudget().total,variableInputs});
}
/** Inputs are independently authenticated upper bounds, never authority.
 * The runtime derives the same fields from its genuine graph/FS handles.
 * This excludes the PG package, carrier build, result publication, and issuer. */
export function carrierSqlRuntimeBudget(value){
 const b=copyNonrootJson(value),keys=[...variableInputs];
 need(b&&Object.keys(b).sort().join()===keys.sort().join(),'CarrierSqlRuntimeBudgetFields');
 need(Object.values(b).every(v=>Number.isSafeInteger(v)&&v>0)&&b.originalSourceBytes<=b.runtimeFilesBytes&&b.carrierGraphNodes<=8192&&b.carrierEntries<=1000000,'CarrierSqlRuntimeBudgetBounds');
 const fixed=carrierSqlRuntimeFixedBudget(),archiveBytes=b.carrierGraphBytes+1536*b.carrierGraphNodes+32768;
 const parts={...fixed.parts,
  caseSecurityReads:logical(L.cases*carrierSqlCaseSecurityBytes(b)),
  carrierLoadFiles:{...logical(b.carrierGraphBytes+archiveBytes+L.maxCarrierLoadMetadataBytes),processedEntries:2},
  carrierColdImport:{...logical(2*archiveBytes+b.carrierUncompressedBytes),uncompressedBytes:b.carrierUncompressedBytes,processedEntries:b.carrierEntries},
 };
 return copyNonrootJson({parts,total:total(parts),carrierArchiveBytes:archiveBytes,additionalUnknownBytes:0});
}
