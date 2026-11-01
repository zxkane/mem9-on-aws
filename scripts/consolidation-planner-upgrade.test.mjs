import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {describe,it,expect,vi} from 'vitest';
import {runtimeSchemaDigest} from './lib/runtime-credentials.mjs';
import {productionOperatorDigest} from './production-runtime-operator.mjs';
import {LEGACY_PLANNER_UPGRADE_HASH} from './lib/consolidation-planner-upgrade.mjs';
import {productionCoordinatorDigest} from './run-production-runtime.mjs';

const provenanceRead=vi.hoisted(()=>({changed:false}));
vi.mock('node:fs/promises',async importOriginal=>{
  const actual=await importOriginal();
  return {...actual,readFile:async(...args)=>{
    const content=await actual.readFile(...args);
    return provenanceRead.changed&&String(args[0]).endsWith('/scripts/lib/consolidation-provenance.mjs')
      ?Buffer.concat([Buffer.from(content),Buffer.from('\n// Synthetic provenance change\n')]):content;
  }};
});

describe('sealed planner bootstrap contract',()=>{
  it('PROV-007 binds provenance implementation bytes into release evidence',async()=>{
    const original=await productionCoordinatorDigest();provenanceRead.changed=true;
    try{expect(await productionCoordinatorDigest()).not.toBe(original);}
    finally{provenanceRead.changed=false;}
  });
  it('PLAN-030 preserves the installed first-release SQL digest',()=>{
    expect(LEGACY_PLANNER_UPGRADE_HASH).toBe('e9ab6cf18e45102621b14d56f7303b350509bf98752aed7919376c1937b8d51c');
  });
  it('PLAN-023 preserves the base SQL used by completed credential cutovers',()=>{
    const sql=readFileSync(new URL('../docker/bootstrap/migrations/006_consolidation_planner.sql',import.meta.url));
    expect(createHash('sha256').update(sql).digest('hex')).toBe('207e3868f40964103f7da708aa498c1256fdf752f58d1ceebef31b6826add774');
  });
  it('preserves both sealed credential-cutover artifact digests',async()=>{
    expect(await runtimeSchemaDigest(new URL('../docker/bootstrap',import.meta.url).pathname))
      .toBe('a3c910042ed7541f34f44b5da9a01743dd45962174aefad4f00b77cccdf34e78');
    expect(await productionOperatorDigest()).toBe('cc2c304168e6c276c24d50b9c67ea22965a0009fc680e4899469cdbbbf3a827f');
  });
});
