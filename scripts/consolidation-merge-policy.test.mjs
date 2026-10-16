import {readFileSync} from 'node:fs';
import {it,expect} from 'vitest';
import {MERGE_POLICY_SQL,MERGE_POLICY_VERSION} from './lib/consolidation-merge-policy.mjs';

const migration=readFileSync(new URL('../docker/bootstrap/migrations/005_consolidation_execution.sql',import.meta.url),'utf8');
const start=migration.indexOf('CREATE OR REPLACE FUNCTION mem9_maintenance.queue_classification('),end=migration.indexOf('END $$;',start)+'END $$;'.length;
const sealed=migration.slice(start,end);

it('changes migration 005 queueing only in the reviewed cross-context hunks',()=>{
  expect(MERGE_POLICY_VERSION).toBe(2);
  expect(MERGE_POLICY_SQL.startsWith('CREATE OR REPLACE FUNCTION mem9_maintenance.queue_classification(')).toBe(true);
  // Undo each documented change; the remainder must be the sealed function.
  const reverted=MERGE_POLICY_SQL
    .replace(' merged_tags JSONB;','')
    .replace(`(row_value->'app_id') IS DISTINCT FROM (first_row->'app_id') OR
        (coalesce(`,`(row_value->'app_id') IS DISTINCT FROM (first_row->'app_id') OR
        (row_value->'source') IS DISTINCT FROM (first_row->'source') OR (row_value->'agent_id') IS DISTINCT FROM (first_row->'agent_id') OR
        coalesce(nullif(row_value->'tags','null'),'[]') IS DISTINCT FROM coalesce(nullif(first_row->'tags','null'),'[]') OR
        (coalesce(`)
    .replace(/    -- Members may come from different agents[\s\S]*?'output_bound'\); END IF;\n/,'')
    .replace(`'tags',merged_tags,`,`'tags',coalesce(nullif(first_row->'tags','null'),'[]'),`)
    .replace(` OR
        merged_tags IS DISTINCT FROM coalesce(nullif(first_row->'tags','null'),'[]') THEN 1`,` THEN 1`);
  expect(reverted).toBe(sealed);
  for(const kept of ["'protected_member'","'invalid_context'","'operator_suppressed'","(row_value->'app_id') IS DISTINCT FROM",
    "-ARRAY['source_turns','source_seqs','consolidation']) IS DISTINCT FROM"])expect(MERGE_POLICY_SQL).toContain(kept);
});
