// Versioned owner-installed maintenance functions. The base bootstrap SQL is sealed.
import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';

export const PLANNER_UPGRADE_VERSION=2;
// Keep the first release byte-for-byte: its immutable receipt already exists
// in deployed databases and is checked before any later replacement.
export const legacyPlannerUpgradeDefinitions=[
  {signature:"mem9_maintenance.claim_planner_work(text)",previousHash:null,planner:true,argNames:["p_namespace"],result:"jsonb",settings:["search_path=pg_catalog, pg_temp"],sql:String.raw`CREATE OR REPLACE FUNCTION mem9_maintenance.claim_planner_work(p_namespace TEXT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE w RECORD;
BEGIN
  PERFORM mem9_maintenance.planner_guard(p_namespace);
  SELECT * INTO w FROM mem9_maintenance.claim_work(p_namespace,1,300);
  IF NOT FOUND THEN RETURN jsonb_build_object('status','idle'); END IF;
  RETURN jsonb_build_object('status','claimed','anchor_id',w.memory_id,'lease_generation',w.lease_generation);
END $$;`},
  {signature:"mem9_maintenance.read_neighborhood(text,text,bigint)",previousHash:null,planner:true,argNames:["p_namespace","p_anchor","p_lease"],result:"jsonb",settings:["search_path=pg_catalog, pg_temp","TimeZone=UTC"],sql:String.raw`CREATE OR REPLACE FUNCTION mem9_maintenance.read_neighborhood(p_namespace TEXT,p_anchor TEXT,p_lease BIGINT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE w RECORD; a public.memories; progress mem9_maintenance.planner_progress; policy mem9_maintenance.planner_policies;
  chosen TEXT[]; observed_ids TEXT[]; candidate RECORD; members JSONB; cached JSONB; phase TEXT:='exact'; next_phase TEXT;
  last_id TEXT; last_distance DOUBLE PRECISION; ranked_distances DOUBLE PRECISION[]:=ARRAY[NULL::double precision];
  count_neighbors INTEGER:=0; prompt_bytes BIGINT; result JSONB; forced_result TEXT;
BEGIN
  PERFORM mem9_maintenance.planner_guard(p_namespace);
  SELECT * INTO policy FROM mem9_maintenance.planner_policies WHERE namespace_id=p_namespace;
  SELECT * INTO w FROM mem9_maintenance.work WHERE namespace_id=p_namespace AND memory_id=p_anchor FOR UPDATE;
  IF NOT FOUND OR p_lease IS NULL OR w.lease_generation<>p_lease OR w.lease_until IS NULL
    OR w.lease_until<=clock_timestamp() OR w.claimed_generation<=w.completed_generation THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='invalid planner lease'; END IF;
  IF w.desired_generation<>w.claimed_generation THEN
    PERFORM mem9_maintenance.defer_neighborhood(p_namespace,p_anchor,p_lease,'inputs_changed');
    RETURN jsonb_build_object('status','retry');
  END IF;
  SELECT * INTO progress FROM mem9_maintenance.planner_progress WHERE namespace_id=p_namespace AND memory_id=w.memory_id;
  IF FOUND AND progress.expected_generation=w.claimed_generation THEN phase:=progress.phase;
  ELSE
    IF FOUND THEN
      INSERT INTO mem9_maintenance.planner_deferrals AS d(namespace_id,memory_id,reason,resets) VALUES(p_namespace,w.memory_id,'generation_reset',1)
        ON CONFLICT(namespace_id,memory_id) DO UPDATE SET resets=d.resets+1;
    END IF;
    progress.after_id:=NULL; progress.after_distance:=NULL;
    DELETE FROM mem9_maintenance.planner_progress WHERE namespace_id=p_namespace AND memory_id=w.memory_id;
  END IF;
  SELECT * INTO a FROM public.memories WHERE namespace_id=p_namespace AND id=w.memory_id AND state='active' AND memory_type<>'session';
  chosen:=ARRAY[w.memory_id::text];
  observed_ids:=chosen;
  IF FOUND THEN
    IF phase='exact' THEN
      FOR candidate IN SELECT m.id FROM public.memories m WHERE m.namespace_id=p_namespace AND m.state='active' AND m.memory_type<>'session'
        AND md5(m.content)=md5(a.content) AND m.content=a.content AND m.id<>a.id AND (progress.after_id IS NULL OR m.id>progress.after_id)
        AND mem9_maintenance.material_context(to_jsonb(m)-'embedding')=mem9_maintenance.material_context(to_jsonb(a)-'embedding')
        ORDER BY m.id LIMIT 10 LOOP
        observed_ids:=array_append(observed_ids,candidate.id);
        count_neighbors:=count_neighbors+1;
        IF count_neighbors<=9 THEN chosen:=array_append(chosen,candidate.id); last_id:=candidate.id; END IF;
      END LOOP;
      IF count_neighbors>9 THEN next_phase:='exact';
      ELSIF count_neighbors>0 OR progress.after_id IS NOT NULL THEN next_phase:='vector'; last_id:=NULL;
      ELSE phase:='vector'; END IF;
    END IF;
    IF phase='vector' AND a.embedding IS NOT NULL THEN
      count_neighbors:=0;
      FOR candidate IN WITH scoped AS MATERIALIZED (
        SELECT m.id,m.embedding FROM public.memories m WHERE m.namespace_id=p_namespace AND m.state='active' AND m.memory_type<>'session'
          AND m.id<>a.id AND (m.content<>a.content OR mem9_maintenance.material_context(to_jsonb(m)-'embedding')<>mem9_maintenance.material_context(to_jsonb(a)-'embedding')) AND m.embedding IS NOT NULL
      ), distances AS (SELECT id,embedding OPERATOR(public.<=>) a.embedding AS distance FROM scoped)
      SELECT id,distance FROM distances WHERE distance<=1-(policy.policy->>'similarity')::float8
        AND (progress.after_id IS NULL OR (distance,id)>(progress.after_distance,progress.after_id)) ORDER BY distance,id LIMIT 10 LOOP
        observed_ids:=array_append(observed_ids,candidate.id);
        count_neighbors:=count_neighbors+1;
        IF count_neighbors<=9 THEN
          chosen:=array_append(chosen,candidate.id); ranked_distances:=array_append(ranked_distances,candidate.distance);
          last_id:=candidate.id; last_distance:=candidate.distance;
        END IF;
      END LOOP;
      IF count_neighbors>9 THEN next_phase:='vector'; END IF;
    END IF;
  END IF;
  -- Publish reverse dependencies before hydration, including the lookahead and
  -- candidates later dropped for size. They survive blocked/retry outcomes.
  INSERT INTO mem9_maintenance.planner_dependencies(namespace_id,memory_id,anchor_id)
    SELECT p_namespace,id,w.memory_id FROM unnest(observed_ids) id ON CONFLICT DO NOTHING;
  LOOP
  BEGIN
    SELECT coalesce(jsonb_agg(jsonb_build_object('id',memory_id,'version',version,'fingerprint',fingerprint,'memory',memory-'embedding') ORDER BY memory_id),'[]')
      INTO members FROM mem9_maintenance.read_memories(p_namespace,chosen);
    EXIT;
  EXCEPTION WHEN program_limit_exceeded THEN
    IF cardinality(chosen)>2 THEN
      chosen:=chosen[1:cardinality(chosen)-1]; next_phase:=phase; last_id:=chosen[cardinality(chosen)];
      IF phase='vector' THEN last_distance:=ranked_distances[cardinality(chosen)]; END IF;
      CONTINUE;
    END IF;
    UPDATE mem9_maintenance.work SET lease_until=NULL,attempts=3,reason='lease_exhausted' WHERE namespace_id=p_namespace AND memory_id=w.memory_id;
    INSERT INTO mem9_maintenance.planner_deferrals(namespace_id,memory_id,reason) VALUES(p_namespace,w.memory_id,'input_bound')
      ON CONFLICT(namespace_id,memory_id) DO UPDATE SET reason='input_bound';
    RETURN jsonb_build_object('status','blocked');
  END;
  END LOOP;
  IF a.id IS NOT NULL AND (jsonb_array_length(members)<>cardinality(chosen) OR NOT EXISTS(
    SELECT FROM jsonb_array_elements(members) m WHERE m->>'id'=a.id
      AND m->>'fingerprint'=encode(sha256(convert_to(to_jsonb(a)::text,'UTF8')),'hex')) OR
    (phase='vector' AND EXISTS(SELECT FROM public.memories m WHERE m.namespace_id=p_namespace AND m.id=ANY(chosen) AND m.id<>a.id
      AND (m.embedding OPERATOR(public.<=>) a.embedding) IS DISTINCT FROM ranked_distances[array_position(chosen,m.id::text)]))) THEN
    -- A delete/update between ranking and hydration cannot advance a cursor
    -- built from a different anchor or a missing last neighbor.
    UPDATE mem9_maintenance.work SET lease_until=NULL,attempts=greatest(0,attempts-1),due_at=clock_timestamp()+interval '1 second'
      WHERE namespace_id=p_namespace AND memory_id=w.memory_id;
    RETURN jsonb_build_object('status','retry');
  END IF;
  -- Leave room for source-preserving output before classifying an exact group.
  -- This splits discovery only; the existing queue still computes the actual
  -- immutable action/output bounds, including a pair larger than this target.
  WHILE octet_length(members::text)>256000 AND cardinality(chosen)>2 LOOP
    chosen:=chosen[1:cardinality(chosen)-1]; next_phase:=phase; last_id:=chosen[cardinality(chosen)];
    SELECT coalesce(jsonb_agg(jsonb_build_object('id',memory_id,'version',version,'fingerprint',fingerprint,'memory',memory-'embedding') ORDER BY memory_id),'[]')
      INTO members FROM mem9_maintenance.read_memories(p_namespace,chosen);
    IF phase='vector' THEN last_distance:=ranked_distances[cardinality(chosen)]; END IF;
  END LOOP;
  prompt_bytes:=mem9_maintenance.model_request_bytes(members);
  -- The provider limit cannot block deterministic KEEP/exact MERGE work. For
  -- model windows, shrink discovery (before any proposal) and keep the cursor
  -- at the last included neighbor. An oversized pair becomes explicit review,
  -- never a truncated prompt or a permanent obstacle to subsequent neighbors.
  WHILE prompt_bytes>32768 AND jsonb_array_length(members)>2 AND
    (SELECT count(DISTINCT value->'memory'->>'content') FROM jsonb_array_elements(members))>1 LOOP
    chosen:=chosen[1:cardinality(chosen)-1];
    SELECT coalesce(jsonb_agg(jsonb_build_object('id',memory_id,'version',version,'fingerprint',fingerprint,'memory',memory-'embedding') ORDER BY memory_id),'[]')
      INTO members FROM mem9_maintenance.read_memories(p_namespace,chosen);
    next_phase:=phase; last_id:=chosen[cardinality(chosen)];
    IF phase='vector' THEN last_distance:=ranked_distances[cardinality(chosen)]; END IF;
    prompt_bytes:=mem9_maintenance.model_request_bytes(members);
  END LOOP;
  IF prompt_bytes>32768 AND jsonb_array_length(members)>1 AND
    (SELECT count(DISTINCT value->'memory'->>'content') FROM jsonb_array_elements(members))>1 THEN forced_result:='REVIEW'; END IF;
  IF octet_length(members::text)>1048576 OR (jsonb_array_length(members)>0 AND NOT members @> jsonb_build_array(jsonb_build_object('id',w.memory_id))) THEN
    UPDATE mem9_maintenance.work SET lease_until=NULL,attempts=3,reason='lease_exhausted' WHERE namespace_id=p_namespace AND memory_id=w.memory_id;
    INSERT INTO mem9_maintenance.planner_deferrals(namespace_id,memory_id,reason) VALUES(p_namespace,w.memory_id,'input_bound')
      ON CONFLICT(namespace_id,memory_id) DO UPDATE SET reason='input_bound';
    RETURN jsonb_build_object('status','blocked'); END IF;
  -- Reuse the already SHARE-locked snapshots, preserving the legacy cache's
  -- missing-member check. Keep the exact cached payload/validity at publication.
  IF jsonb_array_length(members)=cardinality(chosen) OR (jsonb_array_length(members)=0 AND cardinality(chosen)=1) THEN
    SELECT jsonb_build_object('classification_id',c.classification_id,'payload',c.payload) INTO cached
      FROM mem9_maintenance.classifications c WHERE c.namespace_id=p_namespace AND c.valid_until>clock_timestamp()
        AND c.input_hash=mem9_maintenance.input_fingerprint(policy.context_hash,
          (SELECT coalesce(jsonb_agg(value-'memory' ORDER BY value->>'id'),'[]') FROM jsonb_array_elements(members)),w.memory_id)
      ORDER BY c.valid_until DESC LIMIT 1;
  END IF;
  IF cached IS NOT NULL THEN forced_result:=NULL; END IF;
  INSERT INTO mem9_maintenance.neighborhoods(namespace_id,memory_id,lease_generation,claimed_generation,context_hash,phase,members,cached,forced_result,next_phase,after_id,after_distance)
    VALUES(p_namespace,w.memory_id,w.lease_generation,w.claimed_generation,policy.context_hash,phase,members,cached,forced_result,next_phase,last_id,last_distance);
  result:=jsonb_build_object('status','leased','anchor_id',w.memory_id,'lease_generation',w.lease_generation,
    'phase',phase,'members',members,'cached',cached,'forced_result',forced_result,'lease_until',w.lease_until,'context_hash',policy.context_hash,'model_contract',policy.policy->'model');
  RETURN result;
END $$;`},
  {signature:"mem9_maintenance.claim_neighborhood(text)",previousHash:"47ec49fb3209038061f6c1e154c9825b685c8244e5b67c3ca8fbda1bdb14830e",planner:true,argNames:["p_namespace"],result:"jsonb",settings:["search_path=pg_catalog, pg_temp"],sql:String.raw`CREATE OR REPLACE FUNCTION mem9_maintenance.claim_neighborhood(p_namespace TEXT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  PERFORM mem9_maintenance.planner_guard(p_namespace);
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='split planner claim required';
END $$;`},
  {signature:"mem9_maintenance.dirty_planner_input(text,text,timestamptz,text)",previousHash:"f9c1df683c04a036c29bfbeb27f5f084ba51b857c32304de1eec5e84efd421d5",planner:false,argNames:["p_namespace","p_anchor","p_seen","p_reason"],result:"void",settings:["search_path=pg_catalog, pg_temp"],sql:String.raw`CREATE OR REPLACE FUNCTION mem9_maintenance.dirty_planner_input(p_namespace TEXT,p_anchor TEXT,p_seen TIMESTAMPTZ,p_reason TEXT) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  PERFORM mem9_maintenance.dirty(p_namespace,p_anchor,p_seen,p_reason);
  -- Only an observed input change (or changed audit fingerprint), not expiry or
  -- retry, can reopen a page blocked by this planner. Keep its unresolved age.
  -- Crashed claimants may never have written a deferral. A real input change
  -- must also reopen those exhausted generations, preserving unresolved age.
  UPDATE mem9_maintenance.work w SET attempts=0,reason=p_reason WHERE w.namespace_id=p_namespace AND w.memory_id=p_anchor AND w.attempts=3;
END $$;`},
  {signature:"mem9_maintenance.defer_neighborhood(text,text,bigint,text)",previousHash:"b25f52cf28e1e5cdb378e4231f188a8f19f20cd1c6b5e96374efa0fe1c9559c1",planner:true,argNames:["p_namespace","p_anchor","p_lease","p_reason"],result:"void",settings:["search_path=pg_catalog, pg_temp"],sql:String.raw`CREATE OR REPLACE FUNCTION mem9_maintenance.defer_neighborhood(p_namespace TEXT,p_anchor TEXT,p_lease BIGINT,p_reason TEXT) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE w mem9_maintenance.work; a mem9_maintenance.model_attempts; free_attempt BOOLEAN; scope_name TEXT;
BEGIN
  PERFORM mem9_maintenance.planner_guard(p_namespace);
  IF p_reason IS NULL OR p_reason NOT IN ('budget_wait','capacity_wait','uncertainty_wait','model_disabled','policy_wait','deadline','model_failed','invalid_result','inputs_changed','existing','scan_failed') THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid planner deferral'; END IF;
  SELECT * INTO w FROM mem9_maintenance.work WHERE namespace_id=p_namespace AND memory_id=p_anchor FOR UPDATE;
  IF NOT FOUND OR w.lease_generation<>p_lease OR w.lease_until IS NULL THEN RETURN; END IF;
  SELECT * INTO a FROM mem9_maintenance.model_attempts WHERE namespace_id=p_namespace AND memory_id=p_anchor AND lease_generation=p_lease;
  IF FOUND AND a.status='reserved' THEN
    FOREACH scope_name IN ARRAY ARRAY['stage',p_namespace] LOOP
      UPDATE mem9_maintenance.model_windows SET reserved=mem9_maintenance.model_units(reserved,a.reserved,-1) WHERE scope=scope_name AND day=a.day;
    END LOOP;
    UPDATE mem9_maintenance.model_attempts SET status='resolved' WHERE attempt_id=a.attempt_id;
  END IF;
  free_attempt:=p_reason IN ('budget_wait','capacity_wait','uncertainty_wait','model_disabled','policy_wait','deadline','inputs_changed')
    AND (a.attempt_id IS NULL OR a.status='reserved' OR (a.status='resolved' AND a.charged->'requests'='0'));
  UPDATE mem9_maintenance.work SET lease_until=NULL,attempts=greatest(0,attempts-CASE WHEN free_attempt THEN 1 ELSE 0 END),
    reason=CASE WHEN attempts>=3 AND NOT free_attempt THEN 'lease_exhausted' ELSE reason END,
    due_at=clock_timestamp()+make_interval(secs=>CASE WHEN p_reason IN ('budget_wait','model_disabled','policy_wait','uncertainty_wait') THEN 900 ELSE 30 END)
    WHERE namespace_id=p_namespace AND memory_id=p_anchor;
  INSERT INTO mem9_maintenance.planner_deferrals(namespace_id,memory_id,reason) VALUES(p_namespace,p_anchor,p_reason)
    ON CONFLICT(namespace_id,memory_id) DO UPDATE SET reason=EXCLUDED.reason;
END $$;`},
];
const hash=value=>createHash('sha256').update(value).digest('hex');
const body=sql=>sql.slice(sql.indexOf('AS $$')+5,sql.lastIndexOf('$$'));
// Keep the complete SQL visible to the scoped-query inventory and review.
const snapshotReviewSql=String.raw`CREATE OR REPLACE FUNCTION mem9_maintenance.read_neighborhood(p_namespace TEXT,p_anchor TEXT,p_lease BIGINT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE w RECORD; a public.memories; progress mem9_maintenance.planner_progress; policy mem9_maintenance.planner_policies;
  chosen TEXT[]; observed_ids TEXT[]; candidate RECORD; members JSONB; cached JSONB; phase TEXT:='exact'; next_phase TEXT;
  last_id TEXT; last_distance DOUBLE PRECISION; ranked_distances DOUBLE PRECISION[]:=ARRAY[NULL::double precision];
  limit_message TEXT; count_neighbors INTEGER:=0; prompt_bytes BIGINT; result JSONB; forced_result TEXT;
BEGIN
  PERFORM mem9_maintenance.planner_guard(p_namespace);
  SELECT * INTO policy FROM mem9_maintenance.planner_policies WHERE namespace_id=p_namespace;
  SELECT * INTO w FROM mem9_maintenance.work WHERE namespace_id=p_namespace AND memory_id=p_anchor FOR UPDATE;
  IF NOT FOUND OR p_lease IS NULL OR w.lease_generation<>p_lease OR w.lease_until IS NULL
    OR w.lease_until<=clock_timestamp() OR w.claimed_generation<=w.completed_generation THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='invalid planner lease'; END IF;
  IF w.desired_generation<>w.claimed_generation THEN
    PERFORM mem9_maintenance.defer_neighborhood(p_namespace,p_anchor,p_lease,'inputs_changed');
    RETURN jsonb_build_object('status','retry');
  END IF;
  SELECT * INTO progress FROM mem9_maintenance.planner_progress WHERE namespace_id=p_namespace AND memory_id=w.memory_id;
  IF FOUND AND progress.expected_generation=w.claimed_generation THEN phase:=progress.phase;
  ELSE
    IF FOUND THEN
      INSERT INTO mem9_maintenance.planner_deferrals AS d(namespace_id,memory_id,reason,resets) VALUES(p_namespace,w.memory_id,'generation_reset',1)
        ON CONFLICT(namespace_id,memory_id) DO UPDATE SET resets=d.resets+1;
    END IF;
    progress.after_id:=NULL; progress.after_distance:=NULL;
    DELETE FROM mem9_maintenance.planner_progress WHERE namespace_id=p_namespace AND memory_id=w.memory_id;
  END IF;
  SELECT * INTO a FROM public.memories WHERE namespace_id=p_namespace AND id=w.memory_id AND state='active' AND memory_type<>'session';
  chosen:=ARRAY[w.memory_id::text];
  observed_ids:=chosen;
  IF FOUND THEN
    IF phase='exact' THEN
      FOR candidate IN SELECT m.id FROM public.memories m WHERE m.namespace_id=p_namespace AND m.state='active' AND m.memory_type<>'session'
        AND md5(m.content)=md5(a.content) AND m.content=a.content AND m.id<>a.id AND (progress.after_id IS NULL OR m.id>progress.after_id)
        AND mem9_maintenance.material_context(to_jsonb(m)-'embedding')=mem9_maintenance.material_context(to_jsonb(a)-'embedding')
        ORDER BY m.id LIMIT 10 LOOP
        observed_ids:=array_append(observed_ids,candidate.id);
        count_neighbors:=count_neighbors+1;
        IF count_neighbors<=9 THEN chosen:=array_append(chosen,candidate.id); last_id:=candidate.id; END IF;
      END LOOP;
      IF count_neighbors>9 THEN next_phase:='exact';
      ELSIF count_neighbors>0 OR progress.after_id IS NOT NULL THEN next_phase:='vector'; last_id:=NULL;
      ELSE phase:='vector'; END IF;
    END IF;
    IF phase='vector' AND a.embedding IS NOT NULL THEN
      count_neighbors:=0;
      FOR candidate IN WITH scoped AS MATERIALIZED (
        SELECT m.id,m.embedding FROM public.memories m WHERE m.namespace_id=p_namespace AND m.state='active' AND m.memory_type<>'session'
          AND m.id<>a.id AND (m.content<>a.content OR mem9_maintenance.material_context(to_jsonb(m)-'embedding')<>mem9_maintenance.material_context(to_jsonb(a)-'embedding')) AND m.embedding IS NOT NULL
      ), distances AS (SELECT id,embedding OPERATOR(public.<=>) a.embedding AS distance FROM scoped)
      SELECT id,distance FROM distances WHERE distance<=1-(policy.policy->>'similarity')::float8
        AND (progress.after_id IS NULL OR (distance,id)>(progress.after_distance,progress.after_id)) ORDER BY distance,id LIMIT 10 LOOP
        observed_ids:=array_append(observed_ids,candidate.id);
        count_neighbors:=count_neighbors+1;
        IF count_neighbors<=9 THEN
          chosen:=array_append(chosen,candidate.id); ranked_distances:=array_append(ranked_distances,candidate.distance);
          last_id:=candidate.id; last_distance:=candidate.distance;
        END IF;
      END LOOP;
      IF count_neighbors>9 THEN next_phase:='vector'; END IF;
    END IF;
  END IF;
  -- Publish reverse dependencies before hydration, including the lookahead and
  -- candidates later dropped for size. They survive blocked/retry outcomes.
  INSERT INTO mem9_maintenance.planner_dependencies(namespace_id,memory_id,anchor_id)
    SELECT p_namespace,id,w.memory_id FROM unnest(observed_ids) id ON CONFLICT DO NOTHING;
  LOOP
  BEGIN
    SELECT coalesce(jsonb_agg(jsonb_build_object('id',memory_id,'version',version,'fingerprint',fingerprint,'memory',memory-'embedding') ORDER BY memory_id),'[]')
      INTO members FROM mem9_maintenance.read_memories(p_namespace,chosen);
    IF octet_length(members::text)>1048576 THEN
      RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='maintenance input too large'; END IF;
    EXIT;
  EXCEPTION WHEN program_limit_exceeded THEN
    GET STACKED DIAGNOSTICS limit_message=MESSAGE_TEXT;
    IF limit_message<>'maintenance input too large' THEN RAISE; END IF;
    IF cardinality(chosen)>2 THEN
      chosen:=chosen[1:cardinality(chosen)-1]; next_phase:=phase; last_id:=chosen[cardinality(chosen)];
      IF phase='vector' THEN last_distance:=ranked_distances[cardinality(chosen)]; END IF;
      CONTINUE;
    END IF;
    -- A minimal oversized window is reviewable through immutable references.
    -- Hash complete rows under the same ordered SHARE locks; no source content
    -- is truncated, transported to the worker, or submitted to a model.
    SELECT coalesce(jsonb_agg(jsonb_build_object('id',m.id,'version',m.version,
      'fingerprint',encode(sha256(convert_to(to_jsonb(m)::text,'UTF8')),'hex'),
      'memory',NULL) ORDER BY m.id),'[]') INTO members
      FROM (SELECT r.* FROM public.memories r WHERE r.namespace_id=p_namespace AND r.id=ANY(chosen)
        AND r.state='active' AND r.memory_type<>'session' ORDER BY r.id FOR SHARE) m;
    forced_result:='REVIEW';
    EXIT;
  END;
  END LOOP;
  IF a.id IS NOT NULL AND (jsonb_array_length(members)<>cardinality(chosen) OR NOT EXISTS(
    SELECT FROM jsonb_array_elements(members) m WHERE m->>'id'=a.id
      AND m->>'fingerprint'=encode(sha256(convert_to(to_jsonb(a)::text,'UTF8')),'hex')) OR
    (phase='vector' AND EXISTS(SELECT FROM public.memories m WHERE m.namespace_id=p_namespace AND m.id=ANY(chosen) AND m.id<>a.id
      AND (m.embedding OPERATOR(public.<=>) a.embedding) IS DISTINCT FROM ranked_distances[array_position(chosen,m.id::text)]))) THEN
    -- A delete/update between ranking and hydration cannot advance a cursor
    -- built from a different anchor or a missing last neighbor.
    UPDATE mem9_maintenance.work SET lease_until=NULL,attempts=greatest(0,attempts-1),due_at=clock_timestamp()+interval '1 second'
      WHERE namespace_id=p_namespace AND memory_id=w.memory_id;
    RETURN jsonb_build_object('status','retry');
  END IF;
  -- Leave room for source-preserving output before classifying an exact group.
  -- This splits discovery only; the existing queue still computes the actual
  -- immutable action/output bounds, including a pair larger than this target.
  WHILE octet_length(members::text)>256000 AND cardinality(chosen)>2 LOOP
    chosen:=chosen[1:cardinality(chosen)-1]; next_phase:=phase; last_id:=chosen[cardinality(chosen)];
    SELECT coalesce(jsonb_agg(jsonb_build_object('id',memory_id,'version',version,'fingerprint',fingerprint,'memory',memory-'embedding') ORDER BY memory_id),'[]')
      INTO members FROM mem9_maintenance.read_memories(p_namespace,chosen);
    IF phase='vector' THEN last_distance:=ranked_distances[cardinality(chosen)]; END IF;
  END LOOP;
  prompt_bytes:=mem9_maintenance.model_request_bytes(members);
  -- The provider limit cannot block deterministic KEEP/exact MERGE work. For
  -- model windows, shrink discovery (before any proposal) and keep the cursor
  -- at the last included neighbor. An oversized pair becomes explicit review,
  -- never a truncated prompt or a permanent obstacle to subsequent neighbors.
  WHILE prompt_bytes>32768 AND jsonb_array_length(members)>2 AND
    (SELECT count(DISTINCT value->'memory'->>'content') FROM jsonb_array_elements(members))>1 LOOP
    chosen:=chosen[1:cardinality(chosen)-1];
    SELECT coalesce(jsonb_agg(jsonb_build_object('id',memory_id,'version',version,'fingerprint',fingerprint,'memory',memory-'embedding') ORDER BY memory_id),'[]')
      INTO members FROM mem9_maintenance.read_memories(p_namespace,chosen);
    next_phase:=phase; last_id:=chosen[cardinality(chosen)];
    IF phase='vector' THEN last_distance:=ranked_distances[cardinality(chosen)]; END IF;
    prompt_bytes:=mem9_maintenance.model_request_bytes(members);
  END LOOP;
  IF prompt_bytes>32768 AND jsonb_array_length(members)>1 AND
    (SELECT count(DISTINCT value->'memory'->>'content') FROM jsonb_array_elements(members))>1 THEN forced_result:='REVIEW'; END IF;
  IF octet_length(members::text)>1048576 OR (jsonb_array_length(members)>0 AND NOT members @> jsonb_build_array(jsonb_build_object('id',w.memory_id))) THEN
    UPDATE mem9_maintenance.work SET lease_until=NULL,attempts=3,reason='lease_exhausted' WHERE namespace_id=p_namespace AND memory_id=w.memory_id;
    INSERT INTO mem9_maintenance.planner_deferrals(namespace_id,memory_id,reason) VALUES(p_namespace,w.memory_id,'input_bound')
      ON CONFLICT(namespace_id,memory_id) DO UPDATE SET reason='input_bound';
    RETURN jsonb_build_object('status','blocked'); END IF;
  -- Reuse the already SHARE-locked snapshots, preserving the legacy cache's
  -- missing-member check. Keep the exact cached payload/validity at publication.
  IF jsonb_array_length(members)=cardinality(chosen) OR (jsonb_array_length(members)=0 AND cardinality(chosen)=1) THEN
    SELECT jsonb_build_object('classification_id',c.classification_id,'payload',c.payload) INTO cached
      FROM mem9_maintenance.classifications c WHERE c.namespace_id=p_namespace AND c.valid_until>clock_timestamp()
        AND c.input_hash=mem9_maintenance.input_fingerprint(policy.context_hash,
          (SELECT coalesce(jsonb_agg(value-'memory' ORDER BY value->>'id'),'[]') FROM jsonb_array_elements(members)),w.memory_id)
      ORDER BY c.valid_until DESC LIMIT 1;
  END IF;
  IF cached IS NOT NULL AND NOT EXISTS(SELECT FROM jsonb_array_elements(members) m WHERE m->'memory'='null'::jsonb) THEN
    forced_result:=NULL; END IF;
  INSERT INTO mem9_maintenance.neighborhoods(namespace_id,memory_id,lease_generation,claimed_generation,context_hash,phase,members,cached,forced_result,next_phase,after_id,after_distance)
    VALUES(p_namespace,w.memory_id,w.lease_generation,w.claimed_generation,policy.context_hash,phase,members,cached,forced_result,next_phase,last_id,last_distance);
  result:=jsonb_build_object('status','leased','anchor_id',w.memory_id,'lease_generation',w.lease_generation,
    'phase',phase,'members',members,'cached',cached,'forced_result',forced_result,'lease_until',w.lease_until,'context_hash',policy.context_hash,'model_contract',policy.policy->'model');
  RETURN result;
END $$;`;

export const plannerUpgradeDefinitions=legacyPlannerUpgradeDefinitions.map(definition=>
  definition.signature==='mem9_maintenance.read_neighborhood(text,text,bigint)'
    ?{...definition,sql:snapshotReviewSql}:definition);
plannerUpgradeDefinitions.push({signature:"mem9_maintenance.finish_neighborhood(text,text,bigint,text)",previousHash:"5e93ea544d3fa8fa83a7a5ec357e52a6dd67e14f2d579868768115b9da76a680",planner:true,argNames:["p_namespace","p_anchor","p_lease","p_result"],result:"jsonb",settings:["search_path=pg_catalog, pg_temp","TimeZone=UTC"],sql:String.raw`CREATE OR REPLACE FUNCTION mem9_maintenance.finish_neighborhood(p_namespace TEXT,p_anchor TEXT,p_lease BIGINT,p_result TEXT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE n mem9_maintenance.neighborhoods; w mem9_maintenance.work; payload JSONB; members JSONB; id TEXT; result JSONB; pending_change TIMESTAMPTZ; snapshot_review BOOLEAN;
BEGIN
  PERFORM mem9_maintenance.planner_guard(p_namespace);
  IF p_result IS NULL OR p_result NOT IN ('MERGE','KEEP','REVIEW') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid planner result'; END IF;
  SELECT f.result INTO result FROM mem9_maintenance.planner_finishes f WHERE namespace_id=p_namespace AND memory_id=p_anchor AND lease_generation=p_lease;
  IF FOUND THEN RETURN result; END IF;
  SELECT * INTO n FROM mem9_maintenance.neighborhoods WHERE namespace_id=p_namespace AND memory_id=p_anchor AND lease_generation=p_lease;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='missing neighborhood'; END IF;
  snapshot_review:=coalesce(n.forced_result='REVIEW',FALSE) AND
    EXISTS(SELECT FROM jsonb_array_elements(n.members) m WHERE m->'memory'='null'::jsonb);
  IF n.forced_result IS NOT NULL AND p_result<>n.forced_result THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='bounded neighborhood requires review'; END IF;
  -- No time/sequence watermark: an earlier transaction may have committed late.
  -- If consumption already ran, it advanced desired_generation through these
  -- same dependencies. Otherwise keep the pending event and invalidate progress
  -- here. Later commits remain linked and re-dirty the anchor on consumption.
  SELECT min(c.observed_at) INTO pending_change FROM mem9_maintenance.changes c
    JOIN mem9_maintenance.planner_dependencies d USING(namespace_id,memory_id)
    WHERE c.namespace_id=p_namespace AND d.anchor_id=p_anchor;
  IF pending_change IS NOT NULL THEN PERFORM mem9_maintenance.dirty_planner_input(p_namespace,p_anchor,pending_change,'changed'); END IF;
  SELECT * INTO w FROM mem9_maintenance.work WHERE namespace_id=p_namespace AND memory_id=p_anchor FOR UPDATE;
  SELECT coalesce(jsonb_agg(value-'memory' ORDER BY value->>'id'),'[]') INTO members FROM jsonb_array_elements(n.members);
  payload:=jsonb_build_object('context_hash',n.context_hash,'members',members,'result',p_result,
    'valid_until',clock_timestamp()+interval '23 hours','details',jsonb_build_object('planner','neighborhood-v1','reason',CASE WHEN snapshot_review THEN 'snapshot_input_bound' WHEN n.forced_result IS NOT NULL THEN 'model_input_bound' ELSE 'classified' END));
  IF n.cached IS NOT NULL THEN
    payload:=n.cached->'payload';
    -- Keep the prior immutable verdict and its publication key. A current
    -- snapshot-size override is recorded separately as review, never queued.
    IF payload->>'result' IS DISTINCT FROM p_result AND NOT snapshot_review THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='cache verdict mismatch'; END IF;
  END IF;
  id:=mem9_maintenance.publish_classification(p_namespace,p_anchor,p_lease,payload);
  IF snapshot_review THEN result:=mem9_maintenance.review_execution(p_namespace,id,'snapshot_input_bound');
  ELSIF p_result='MERGE' THEN result:=mem9_maintenance.queue_classification(p_namespace,id);
  ELSE result:=jsonb_build_object('status',lower(p_result)); END IF;
  IF w.desired_generation=w.claimed_generation AND n.next_phase IS NOT NULL THEN
    UPDATE mem9_maintenance.work SET desired_generation=desired_generation+1,first_seen_at=w.first_seen_at,due_at=clock_timestamp()
      WHERE namespace_id=p_namespace AND memory_id=p_anchor;
    INSERT INTO mem9_maintenance.planner_progress(namespace_id,memory_id,expected_generation,phase,after_id,after_distance)
      VALUES(p_namespace,p_anchor,w.claimed_generation+1,n.next_phase,n.after_id,n.after_distance)
      ON CONFLICT(namespace_id,memory_id) DO UPDATE SET expected_generation=EXCLUDED.expected_generation,phase=EXCLUDED.phase,after_id=EXCLUDED.after_id,after_distance=EXCLUDED.after_distance;
  ELSE DELETE FROM mem9_maintenance.planner_progress WHERE namespace_id=p_namespace AND memory_id=p_anchor;
  END IF;
  INSERT INTO mem9_maintenance.planner_finishes VALUES(p_namespace,p_anchor,p_lease,result);
  RETURN result;
END $$;
`});
export const LEGACY_PLANNER_UPGRADE_HASH=hash(legacyPlannerUpgradeDefinitions.map(d=>d.sql).join('\n'));
export const PLANNER_UPGRADE_HASH=hash(plannerUpgradeDefinitions.map(d=>d.sql).join('\n'));
const releases=[{version:1,definitions:legacyPlannerUpgradeDefinitions,hash:LEGACY_PLANNER_UPGRADE_HASH},
  {version:2,definitions:plannerUpgradeDefinitions,hash:PLANNER_UPGRADE_HASH}];
const fail=()=>{throw Error('PlannerUpgradeCatalogMismatch');};
const scalar=async(db,sql,args=[])=>(await db.query(sql,args)).rows[0]?.result;

async function catalog(db,definition){
  return (await db.query(`SELECT p.prosrc AS body,p.proowner=session_user::regrole::oid AS owned,
    p.prosecdef,p.proisstrict,p.proleakproof,p.proretset,p.provolatile,p.proparallel,p.prokind,
    p.proconfig AS settings,p.proargnames AS args,p.prorettype::regtype::text AS result,l.lanname AS language,
    ARRAY(SELECT CASE WHEN a.grantee=p.proowner THEN 'owner' ELSE coalesce(r.rolname::text,'PUBLIC') END
      FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a LEFT JOIN pg_roles r ON r.oid=a.grantee
      WHERE a.privilege_type='EXECUTE' AND NOT a.is_grantable AND a.grantor=p.proowner
      ORDER BY 1) AS grants,
    (SELECT count(*)::int FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner)))) AS grant_count
    FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure($1)`,[definition.signature])).rows[0];
}

function functionState(row,definition){
  if(!row){if(definition.previousHash)fail();return 'absent';}
  const current=body(definition.sql)===row.body;
  if(!current&&(!definition.previousHash||hash(row.body)!==definition.previousHash))fail();
  const settings=!current&&definition.signature==='mem9_maintenance.claim_neighborhood(text)'
    ?['search_path=pg_catalog, pg_temp','TimeZone=UTC']:definition.settings;
  const grants=definition.planner?['mem9_maintenance_planner','owner']:['owner'];
  if(!row.owned||!row.prosecdef||row.proisstrict||row.proleakproof||row.proretset||row.provolatile!=='v'||
    row.proparallel!=='u'||row.prokind!=='f'||row.language!=='plpgsql'||row.result!==definition.result||
    !isDeepStrictEqual(row.settings,settings)||!isDeepStrictEqual(row.args,definition.argNames)||
    !isDeepStrictEqual(row.grants,grants)||row.grant_count!==grants.length)fail();
  return current?'current':'previous';
}

async function history(db){
  const relation=await scalar(db,"SELECT to_regclass('mem9_maintenance.planner_upgrade_history')::text AS result");
  if(!relation)return null;
  const valid=await scalar(db,`SELECT c.relowner=session_user::regrole::oid AND c.relkind='r' AND NOT c.relrowsecurity
    AND NOT EXISTS(SELECT FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
      WHERE a.grantee<>c.relowner OR a.grantor<>c.relowner OR a.is_grantable)
    AND (SELECT array_agg(a.attname||':'||a.atttypid::regtype::text||':'||a.attnotnull::text ORDER BY a.attnum)
      FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped)
      =ARRAY['version:integer:true','sql_hash:text:true','invocation:text:true','installed_at:timestamp with time zone:true']
    AND NOT EXISTS(SELECT FROM pg_attribute a, LATERAL aclexplode(a.attacl) x
      WHERE a.attrelid=c.oid AND a.attnum>0)
    AND (SELECT count(*) FROM pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal)=1
    AND EXISTS(SELECT FROM pg_trigger t WHERE t.tgrelid=c.oid AND t.tgname='planner_upgrade_history_immutable'
      AND t.tgfoid='mem9_maintenance.immutable()'::regprocedure AND t.tgtype=27 AND t.tgenabled='O'
      AND t.tgqual IS NULL AND t.tgnargs=0 AND t.tgattr::text='' AND octet_length(t.tgargs)=0) AS result
    FROM pg_class c WHERE c.oid='mem9_maintenance.planner_upgrade_history'::regclass`);
  if(!valid)fail();
  const rows=(await db.query('SELECT version,sql_hash,invocation FROM mem9_maintenance.planner_upgrade_history ORDER BY version LIMIT 3')).rows;
  if(!rows.length||rows.length>releases.length||rows.some((row,index)=>row.version!==releases[index].version||
    row.sql_hash!==releases[index].hash||!/^[a-f0-9]{32}$/.test(row.invocation)))fail();
  return rows;
}

/** Read back both the immutable receipt and live functions; a receipt alone is insufficient. */
export async function verifyPlannerUpgrade(db){
  if((await history(db))?.length!==releases.length)fail();
  for(const definition of plannerUpgradeDefinitions)
    if(functionState(await catalog(db,definition),definition)!=='current')fail();
  return {version:PLANNER_UPGRADE_VERSION,sqlHash:PLANNER_UPGRADE_HASH};
}

/** Caller owns the transaction and production authorization. Never accept SQL from a request. */
export async function installPlannerUpgrade(db,{invocation}){
  if(!/^[a-f0-9]{32}$/.test(invocation??''))throw Error('PlannerUpgradeInvocationRequired');
  // SAVEPOINT also rejects use outside a transaction. Existing worker lock order
  // is execution control, model control, namespace queue, then work rows.
  await db.query('SAVEPOINT planner_upgrade');
  try{
    await db.query('SELECT mem9_maintenance.lock_model()');
    await db.query('LOCK TABLE mem9_maintenance.work IN SHARE ROW EXCLUSIVE MODE');
    const receipts=await history(db);
    if(receipts?.length===releases.length){
      await verifyPlannerUpgrade(db);
      await db.query('RELEASE SAVEPOINT planner_upgrade');
      return {changed:false,version:PLANNER_UPGRADE_VERSION,sqlHash:PLANNER_UPGRADE_HASH};
    }
    for(const release of releases.slice(receipts?.length??0)){
      const previous=releases[release.version-2]?.definitions??[];
      // Validate the entire installed prefix and every newly replaced base
      // routine before changing any function. Each receipt remains immutable.
      for(const definition of release.definitions){
        const prior=previous.find(d=>d.signature===definition.signature);
        const expected=prior?'current':definition.previousHash?'previous':'absent';
        if(functionState(await catalog(db,definition),prior??definition)!==expected)fail();
      }
      for(const definition of release.definitions){
        const prior=previous.find(d=>d.signature===definition.signature);
        if(prior?.sql===definition.sql)continue;
        await db.query(definition.sql);
        if(!prior&&!definition.previousHash){
          // Signatures are fixed source constants, never request fields.
          await db.query(`REVOKE ALL ON FUNCTION ${definition.signature} FROM PUBLIC`);
          await db.query(`GRANT EXECUTE ON FUNCTION ${definition.signature} TO mem9_maintenance_planner`);
        }
      }
      if(release.version===1)await db.query(`CREATE TABLE mem9_maintenance.planner_upgrade_history(
      version INTEGER PRIMARY KEY CHECK(version>0),sql_hash TEXT NOT NULL CHECK(sql_hash~'^[a-f0-9]{64}$'),
      invocation TEXT NOT NULL CHECK(invocation~'^[a-f0-9]{32}$'),installed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp());
      REVOKE ALL ON mem9_maintenance.planner_upgrade_history FROM PUBLIC,mem9_maintenance_backend,
        mem9_maintenance_planner,mem9_maintenance_executor,mem9_maintenance_operator;
      CREATE TRIGGER planner_upgrade_history_immutable BEFORE UPDATE OR DELETE ON mem9_maintenance.planner_upgrade_history
        FOR EACH ROW EXECUTE FUNCTION mem9_maintenance.immutable();`);
      await db.query('INSERT INTO mem9_maintenance.planner_upgrade_history(version,sql_hash,invocation) VALUES($1,$2,$3)',
        [release.version,release.hash,invocation]);
    }
    await verifyPlannerUpgrade(db);
    await db.query('RELEASE SAVEPOINT planner_upgrade');
    return {changed:true,version:PLANNER_UPGRADE_VERSION,sqlHash:PLANNER_UPGRADE_HASH};
  }catch(error){await db.query('ROLLBACK TO SAVEPOINT planner_upgrade').catch(()=>{});throw error;}
}
