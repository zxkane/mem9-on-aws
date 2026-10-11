import {it,expect} from 'vitest';
import {CARRIER_SQL_FIXTURE_LIMITS as L,carrierSqlDockerOutputLimit,carrierSqlFixtureFixedRuntimeBudget,carrierSqlRuntimeFixedBudget,carrierSqlRuntimeBudget} from './lib/ci-carrier-sql-runtime-budget.mjs';
import {carrierSqlFixtureFixedRuntimeBudget as fixtureBudget} from './lib/ci-carrier-sql-fixture.mjs';

it('exports the same complete fixed counter to owner planning and runtime without package/issuer fees',()=>{
 const fixed=carrierSqlFixtureFixedRuntimeBudget();expect(fixtureBudget()).toEqual(fixed);
 expect(fixed.charge).toEqual({ecrRequests:0,logicalBytes:317069312,httpBodyBytes:0,uncompressedBytes:101711872,processedEntries:16740});
 expect(fixed.variableInputs).toEqual(['runtimeFilesBytes','originalSourceBytes','nodeBytes','setprivBytes','carrierGraphBytes','carrierGraphNodes','carrierUncompressedBytes','carrierEntries']);
 expect(Object.isFrozen(fixed.charge)).toBe(true);
 const parts=carrierSqlRuntimeFixedBudget().parts;expect(parts.relay.logicalBytes).toBe(16777216);expect(parts.fixtureStorage.logicalBytes).toBe(L.tmpDataBytes+L.tmpSocketBytes);
 expect(Object.keys(parts)).toEqual(['fixtureStorage','relay','dockerControl','dockerCleanup','caseInputOutput','overlay','schemaAndSeeder','carrierLoadControl']);
});
it.each([['exec','owned','pg_isready'],['container','create'],['container','inspect'],['container','logs'],['container','start','owned'],['image','load','--input','owned'],['network','create']])('bounds metadata output for the closed operation %j',(...args)=>{
 expect(carrierSqlDockerOutputLimit(args)).toBe(65536);
});
it('retains the complete case output allowance and all 16 native/module read passes',()=>{
 expect(carrierSqlDockerOutputLimit(['container','start','--attach','owned'])).toBe(2097152);
 const input={runtimeFilesBytes:1000,originalSourceBytes:500,nodeBytes:2000,setprivBytes:3000,carrierGraphBytes:4000,carrierGraphNodes:5,carrierUncompressedBytes:6000,carrierEntries:7},b=carrierSqlRuntimeBudget(input);
 expect(b.parts.caseSecurityReads.logicalBytes).toBe(100000);expect(b.carrierArchiveBytes).toBe(44448);
 expect(b.parts.carrierLoadFiles.logicalBytes).toBe(81216);expect(b.parts.carrierColdImport).toEqual({ecrRequests:0,logicalBytes:94896,httpBodyBytes:0,uncompressedBytes:6000,processedEntries:7});
 expect(b.total.logicalBytes).toBe(317345424);expect(b.additionalUnknownBytes).toBe(0);
 expect(()=>carrierSqlRuntimeBudget({...input,nodeBytes:0})).toThrow('CarrierSqlRuntimeBudgetBounds');
 expect(()=>carrierSqlRuntimeBudget({...input,nodeBytes:Number.MAX_SAFE_INTEGER})).toThrow();
 expect(()=>carrierSqlRuntimeBudget({...input,authority:true})).toThrow('CarrierSqlRuntimeBudgetFields');
 const missing={...input};delete missing.nodeBytes;expect(()=>carrierSqlRuntimeBudget(missing)).toThrow('CarrierSqlRuntimeBudgetFields');
});
