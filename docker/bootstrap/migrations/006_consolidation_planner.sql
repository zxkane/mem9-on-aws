-- Incremental planner. Installation creates no enabled policy, login or budget.
BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='30s';
SELECT pg_advisory_xact_lock(hashtext('mem9-maintenance-schema-v1'));

CREATE TABLE IF NOT EXISTS mem9_maintenance.planner_policies(
  namespace_id VARCHAR(36) PRIMARY KEY REFERENCES public.memory_namespaces(namespace_id),
  revision BIGINT NOT NULL DEFAULT 1,
  context_hash TEXT NOT NULL,
  policy JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.planner_policy_history(
  namespace_id VARCHAR(36) NOT NULL REFERENCES public.memory_namespaces(namespace_id),
  revision BIGINT NOT NULL,
  policy JSONB NOT NULL,
  changed_by OID NOT NULL,
  changed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,revision)
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.planner_progress(
  namespace_id VARCHAR(36) NOT NULL,
  memory_id VARCHAR(36) NOT NULL,
  expected_generation BIGINT NOT NULL,
  phase TEXT NOT NULL CHECK(phase IN ('exact','vector')),
  after_id TEXT,
  after_distance DOUBLE PRECISION,
  PRIMARY KEY(namespace_id,memory_id),
  FOREIGN KEY(namespace_id,memory_id) REFERENCES mem9_maintenance.work(namespace_id,memory_id)
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.neighborhoods(
  namespace_id VARCHAR(36) NOT NULL,
  memory_id VARCHAR(36) NOT NULL,
  lease_generation BIGINT NOT NULL,
  claimed_generation BIGINT NOT NULL,
  context_hash TEXT NOT NULL,
  phase TEXT NOT NULL,
  members JSONB NOT NULL,
  cached JSONB,
  forced_result TEXT CHECK(forced_result IS NULL OR forced_result='REVIEW'),
  next_phase TEXT,
  after_id TEXT,
  after_distance DOUBLE PRECISION,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,memory_id,lease_generation),
  FOREIGN KEY(namespace_id,memory_id) REFERENCES mem9_maintenance.work(namespace_id,memory_id),
  CHECK(octet_length(members::text)<=1048576)
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.planner_finishes(
  namespace_id VARCHAR(36) NOT NULL,
  memory_id VARCHAR(36) NOT NULL,
  lease_generation BIGINT NOT NULL,
  result JSONB NOT NULL,
  PRIMARY KEY(namespace_id,memory_id,lease_generation),
  FOREIGN KEY(namespace_id,memory_id,lease_generation) REFERENCES mem9_maintenance.neighborhoods(namespace_id,memory_id,lease_generation)
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.planner_deferrals(
  namespace_id VARCHAR(36) NOT NULL,
  memory_id VARCHAR(36) NOT NULL,
  reason TEXT NOT NULL,
  resets BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY(namespace_id,memory_id),
  FOREIGN KEY(namespace_id,memory_id) REFERENCES mem9_maintenance.work(namespace_id,memory_id)
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.planner_dependencies(
  namespace_id VARCHAR(36) NOT NULL,
  memory_id VARCHAR(36) NOT NULL,
  anchor_id VARCHAR(36) NOT NULL,
  PRIMARY KEY(namespace_id,memory_id,anchor_id),
  FOREIGN KEY(namespace_id,anchor_id) REFERENCES mem9_maintenance.work(namespace_id,memory_id)
  -- Observed neighbor IDs are historical; never reference live memory rows.
);
CREATE INDEX IF NOT EXISTS maintenance_anchor_dependencies ON mem9_maintenance.planner_dependencies(namespace_id,anchor_id,memory_id);
CREATE TABLE IF NOT EXISTS mem9_maintenance.change_progress(
  namespace_id VARCHAR(36) NOT NULL,
  event_id BIGINT NOT NULL,
  after_anchor TEXT,
  PRIMARY KEY(namespace_id,event_id),
  FOREIGN KEY(namespace_id,event_id) REFERENCES mem9_maintenance.changes(namespace_id,event_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.planner_coverage(
  namespace_id VARCHAR(36) NOT NULL REFERENCES public.memory_namespaces(namespace_id),
  memory_id VARCHAR(36) NOT NULL,
  fingerprint TEXT NOT NULL,
  PRIMARY KEY(namespace_id,memory_id)
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.planner_audits(
  namespace_id VARCHAR(36) PRIMARY KEY REFERENCES public.memory_namespaces(namespace_id),
  after_id TEXT,
  missing BOOLEAN NOT NULL DEFAULT FALSE,
  next_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS maintenance_exact_content ON public.memories(namespace_id,md5(content),id)
  WHERE state='active' AND memory_type<>'session';
CREATE INDEX IF NOT EXISTS maintenance_publication_dependents ON mem9_maintenance.publications(namespace_id,classification_id,memory_id);

CREATE TABLE IF NOT EXISTS mem9_maintenance.model_control(
  singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),
  slots INTEGER NOT NULL DEFAULT 1 CHECK(slots BETWEEN 1 AND 4),
  unknown_limit INTEGER NOT NULL DEFAULT 1 CHECK(unknown_limit BETWEEN 1 AND 4),
  paused BOOLEAN NOT NULL DEFAULT FALSE,
  revision BIGINT NOT NULL DEFAULT 1
);
INSERT INTO mem9_maintenance.model_control(singleton) VALUES(TRUE) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS mem9_maintenance.model_policies(
  scope TEXT PRIMARY KEY,
  namespace_id VARCHAR(36) UNIQUE REFERENCES public.memory_namespaces(namespace_id),
  revision BIGINT NOT NULL DEFAULT 1,
  limits JSONB NOT NULL,
  CHECK((scope='stage' AND namespace_id IS NULL) OR scope=namespace_id)
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.model_policy_history(
  scope TEXT NOT NULL,
  revision BIGINT NOT NULL,
  policy JSONB NOT NULL,
  changed_by OID NOT NULL,
  changed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(scope,revision)
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.model_windows(
  scope TEXT NOT NULL REFERENCES mem9_maintenance.model_policies(scope),
  day DATE NOT NULL,
  used JSONB NOT NULL DEFAULT '{"requests":0,"input":0,"output":0}',
  reserved JSONB NOT NULL DEFAULT '{"requests":0,"input":0,"output":0}',
  PRIMARY KEY(scope,day)
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.model_attempts(
  attempt_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  namespace_id VARCHAR(36) NOT NULL,
  memory_id VARCHAR(36) NOT NULL,
  lease_generation BIGINT NOT NULL,
  caller OID NOT NULL,
  day DATE NOT NULL,
  contract JSONB NOT NULL,
  stage_revision BIGINT NOT NULL,
  namespace_revision BIGINT NOT NULL,
  control_revision BIGINT NOT NULL,
  status TEXT NOT NULL DEFAULT 'reserved' CHECK(status IN ('reserved','dispatched','settled','unknown','resolved')),
  reserved JSONB NOT NULL,
  charged JSONB NOT NULL DEFAULT '{"requests":0,"input":0,"output":0}',
  expires_at TIMESTAMPTZ NOT NULL,
  UNIQUE(namespace_id,memory_id,lease_generation),
  FOREIGN KEY(namespace_id,memory_id,lease_generation) REFERENCES mem9_maintenance.neighborhoods(namespace_id,memory_id,lease_generation)
);
CREATE INDEX IF NOT EXISTS maintenance_model_outstanding ON mem9_maintenance.model_attempts(status,expires_at)
  WHERE status IN ('reserved','dispatched','unknown');
CREATE TABLE IF NOT EXISTS mem9_maintenance.model_resolutions(
  resolution_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  attempt_id UUID REFERENCES mem9_maintenance.model_attempts(attempt_id),
  changed_by OID NOT NULL,
  reason TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- Foreground capture only appends new outbox rows, never locks queue/work.
-- Mixed paths: authorization -> execution control -> model control -> queue ->
-- work/input -> sorted memory rows. Settlement: login lookup (no row lock) ->
-- controls -> windows/attempt. No transaction spans inference.
CREATE OR REPLACE FUNCTION mem9_maintenance.lock_model() RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  PERFORM singleton FROM mem9_maintenance.execution_control WHERE singleton FOR UPDATE;
  PERFORM singleton FROM mem9_maintenance.model_control WHERE singleton FOR UPDATE;
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.planner_guard(p_namespace TEXT) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  PERFORM mem9_maintenance.authorize(p_namespace,'planner');
  PERFORM mem9_maintenance.lock_model();
  PERFORM mem9_maintenance.lock_queue(p_namespace);
  IF NOT EXISTS(SELECT FROM mem9_maintenance.planner_policies p JOIN mem9_maintenance.namespace_state s USING(namespace_id)
    WHERE p.namespace_id=p_namespace AND p.policy->'enabled'='true' AND p.context_hash=s.context_hash
      AND p.context_hash=mem9_maintenance.planner_context(p.policy)) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='incremental planner disabled'; END IF;
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.planner_context(p_policy JSONB) RETURNS TEXT
LANGUAGE SQL STABLE SET search_path=pg_catalog,pg_temp AS $$
  SELECT encode(sha256(convert_to('planner-neighborhood-v1/'||embedding_model||'/'||(p_policy-'enabled')::text,'UTF8')),'hex')
    FROM mem9_maintenance.execution_control WHERE singleton
$$;
CREATE OR REPLACE FUNCTION mem9_maintenance.valid_model_contract(c JSONB) RETURNS BOOLEAN
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  IF c='null'::jsonb THEN RETURN TRUE; END IF;
  RETURN coalesce(jsonb_typeof(c)='object' AND (SELECT count(*) FROM jsonb_object_keys(c))=10
    AND c ?& ARRAY['adapter','model','region','project','max_input_tokens','max_output_tokens','proof','reasoning','input_bound','output_bound']
    AND c->>'adapter' IN ('mantle-chat-total-v1','mantle-responses-total-v1')
    AND c->>'model' ~ '^[a-zA-Z0-9][a-zA-Z0-9.:-]{0,127}$'
    AND c->>'region' ~ '^[a-z]{2}-[a-z]+-[0-9]$' AND length(c->>'project') BETWEEN 1 AND 128
    AND c->>'project' ~ '^[a-zA-Z0-9_-]+$' AND c->>'proof' ~ '^[0-9a-f]{64}$'
    AND c->>'reasoning' IN ('low','medium','high') AND c->>'input_bound'='context_limit' AND c->>'output_bound'='total_tokens'
    AND jsonb_typeof(c->'max_input_tokens')='number' AND jsonb_typeof(c->'max_output_tokens')='number'
    AND (c->>'max_input_tokens') ~ '^[0-9]+$' AND (c->>'max_input_tokens')::numeric BETWEEN 32768 AND 1000000
    AND (c->>'max_output_tokens') ~ '^[0-9]+$' AND (c->>'max_output_tokens')::numeric BETWEEN 1 AND 32768,FALSE);
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.configure_planner(p_namespace TEXT,p_policy JSONB) RETURNS TEXT
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE digest TEXT; rev BIGINT;
BEGIN
  IF jsonb_typeof(p_policy) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(p_policy))<>3 OR
    NOT p_policy ?& ARRAY['enabled','similarity','model'] OR jsonb_typeof(p_policy->'enabled') IS DISTINCT FROM 'boolean' OR
    jsonb_typeof(p_policy->'similarity') IS DISTINCT FROM 'number' OR (p_policy->>'similarity')::numeric NOT BETWEEN 0.5 AND 1 OR
    NOT mem9_maintenance.valid_model_contract(p_policy->'model') THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid planner policy'; END IF;
  PERFORM namespace_id FROM public.memory_namespaces WHERE namespace_id=p_namespace AND status='active' FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='planner namespace denied'; END IF;
  PERFORM mem9_maintenance.lock_model();
  digest:=mem9_maintenance.planner_context(p_policy);
  -- configure_namespace locks authorization before queue, then the memory
  -- table. It never updates namespace/principal/membership rows after queue.
  PERFORM mem9_maintenance.configure_namespace(p_namespace,digest,TRUE);
  IF EXISTS(SELECT FROM mem9_maintenance.planner_policies WHERE namespace_id=p_namespace AND policy=p_policy AND context_hash=digest) THEN RETURN digest; END IF;
  UPDATE mem9_maintenance.work SET attempts=0,reason='audit' WHERE namespace_id=p_namespace AND attempts=3;
  INSERT INTO mem9_maintenance.planner_policies AS p(namespace_id,context_hash,policy) VALUES(p_namespace,digest,p_policy)
    ON CONFLICT(namespace_id) DO UPDATE SET revision=p.revision+1,context_hash=EXCLUDED.context_hash,policy=EXCLUDED.policy RETURNING revision INTO rev;
  INSERT INTO mem9_maintenance.planner_policy_history(namespace_id,revision,policy,changed_by)
    VALUES(p_namespace,rev,p_policy,(SELECT oid FROM pg_roles WHERE rolname=session_user));
  RETURN digest;
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.material_context(m JSONB) RETURNS JSONB
LANGUAGE SQL IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
  SELECT jsonb_build_object('type',m->'memory_type','app',m->'app_id','source',m->'source','agent',m->'agent_id',
    'tags',coalesce(nullif(m->'tags','null'),'[]'),
    'metadata',coalesce(nullif(m->'metadata','null'),'{}')-ARRAY['source_turns','source_seqs','consolidation'],
    'consolidation',coalesce(nullif(m->'metadata'->'consolidation','null'),'{}')-'sources')
$$;

CREATE OR REPLACE FUNCTION mem9_maintenance.model_request_bytes(p_members JSONB) RETURNS BIGINT
LANGUAGE SQL IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
  -- The user JSON is itself a string inside the provider JSON: measure that
  -- escaped representation, not just the once-serialized memory rows. SQL's
  -- whitespace is conservative versus JSON.stringify. Tests bound the fixed
  -- system/model/route envelope by 2 KiB for both supported request shapes.
  SELECT octet_length(to_jsonb(jsonb_build_object('memories',
    (SELECT coalesce(jsonb_agg(value->'memory'),'[]') FROM jsonb_array_elements(p_members)))::text)::text)+2048
$$;

CREATE OR REPLACE FUNCTION mem9_maintenance.claim_neighborhood(p_namespace TEXT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE w RECORD; a public.memories; progress mem9_maintenance.planner_progress; policy mem9_maintenance.planner_policies;
  chosen TEXT[]; observed_ids TEXT[]; candidate RECORD; members JSONB; cached JSONB; phase TEXT:='exact'; next_phase TEXT;
  last_id TEXT; last_distance DOUBLE PRECISION; ranked_distances DOUBLE PRECISION[]:=ARRAY[NULL::double precision];
  count_neighbors INTEGER:=0; prompt_bytes BIGINT; result JSONB; forced_result TEXT;
BEGIN
  PERFORM mem9_maintenance.planner_guard(p_namespace);
  SELECT * INTO policy FROM mem9_maintenance.planner_policies WHERE namespace_id=p_namespace;
  SELECT * INTO w FROM mem9_maintenance.claim_work(p_namespace,1,300);
  IF NOT FOUND THEN RETURN jsonb_build_object('status','idle'); END IF;
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
END $$;

CREATE OR REPLACE FUNCTION mem9_maintenance.finish_neighborhood(p_namespace TEXT,p_anchor TEXT,p_lease BIGINT,p_result TEXT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE n mem9_maintenance.neighborhoods; w mem9_maintenance.work; payload JSONB; members JSONB; id TEXT; result JSONB; pending_change TIMESTAMPTZ;
BEGIN
  PERFORM mem9_maintenance.planner_guard(p_namespace);
  IF p_result IS NULL OR p_result NOT IN ('MERGE','KEEP','REVIEW') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid planner result'; END IF;
  SELECT f.result INTO result FROM mem9_maintenance.planner_finishes f WHERE namespace_id=p_namespace AND memory_id=p_anchor AND lease_generation=p_lease;
  IF FOUND THEN RETURN result; END IF;
  SELECT * INTO n FROM mem9_maintenance.neighborhoods WHERE namespace_id=p_namespace AND memory_id=p_anchor AND lease_generation=p_lease;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='missing neighborhood'; END IF;
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
    'valid_until',clock_timestamp()+interval '23 hours','details',jsonb_build_object('planner','neighborhood-v1','reason',CASE WHEN n.forced_result IS NOT NULL THEN 'model_input_bound' ELSE 'classified' END));
  IF n.cached IS NOT NULL THEN
    payload:=n.cached->'payload';
    IF payload->>'result' IS DISTINCT FROM p_result THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='cache verdict mismatch'; END IF;
  END IF;
  id:=mem9_maintenance.publish_classification(p_namespace,p_anchor,p_lease,payload);
  IF p_result='MERGE' THEN result:=mem9_maintenance.queue_classification(p_namespace,id);
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
CREATE OR REPLACE FUNCTION mem9_maintenance.planner_receipt(p_namespace TEXT,p_anchor TEXT,p_lease BIGINT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  PERFORM mem9_maintenance.authorize(p_namespace,'planner');
  RETURN (SELECT result FROM mem9_maintenance.planner_finishes WHERE namespace_id=p_namespace AND memory_id=p_anchor AND lease_generation=p_lease);
END $$;

-- Bound one event/reverse-dependency page at a time. Keep the exact event until
-- its last dependent anchor is dirtied; sequence allocation is not commit order.
CREATE OR REPLACE FUNCTION mem9_maintenance.dirty_planner_input(p_namespace TEXT,p_anchor TEXT,p_seen TIMESTAMPTZ,p_reason TEXT) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  PERFORM mem9_maintenance.dirty(p_namespace,p_anchor,p_seen,p_reason);
  -- Only an observed input change (or changed audit fingerprint), not expiry or
  -- retry, can reopen a page blocked by this planner. Keep its unresolved age.
  UPDATE mem9_maintenance.work w SET attempts=0,reason=p_reason WHERE w.namespace_id=p_namespace AND w.memory_id=p_anchor AND w.attempts=3
    AND EXISTS(SELECT FROM mem9_maintenance.planner_deferrals d WHERE d.namespace_id=p_namespace AND d.memory_id=p_anchor);
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.consume_planner_changes(p_namespace TEXT,p_limit INTEGER) RETURNS INTEGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE event mem9_maintenance.changes; cursor_anchor TEXT; item RECORD; count_anchors INTEGER; total INTEGER:=0; touched INTEGER:=0;
BEGIN
  PERFORM mem9_maintenance.planner_guard(p_namespace);
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 1000 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid planner change batch'; END IF;
  FOR event IN SELECT * FROM mem9_maintenance.changes WHERE namespace_id=p_namespace ORDER BY event_id LIMIT p_limit FOR UPDATE LOOP
    SELECT p.after_anchor INTO cursor_anchor FROM mem9_maintenance.change_progress p WHERE p.namespace_id=p_namespace AND p.event_id=event.event_id;
    IF NOT FOUND THEN
      PERFORM mem9_maintenance.dirty_planner_input(p_namespace,event.memory_id,event.observed_at,'changed');
      touched:=touched+1;
      INSERT INTO mem9_maintenance.change_progress(namespace_id,event_id) VALUES(p_namespace,event.event_id);
    END IF;
    count_anchors:=0;
    FOR item IN SELECT anchor_id AS memory_id FROM (
      SELECT p.memory_id AS anchor_id FROM mem9_maintenance.publications p JOIN mem9_maintenance.classification_members m USING(namespace_id,classification_id)
        WHERE p.namespace_id=p_namespace AND m.memory_id=event.memory_id AND p.memory_id<>event.memory_id
      UNION SELECT d.anchor_id FROM mem9_maintenance.planner_dependencies d WHERE d.namespace_id=p_namespace AND d.memory_id=event.memory_id AND d.anchor_id<>event.memory_id
    ) anchors WHERE cursor_anchor IS NULL OR anchor_id>cursor_anchor ORDER BY anchor_id LIMIT 100 LOOP
      PERFORM mem9_maintenance.dirty_planner_input(p_namespace,item.memory_id,event.observed_at,'changed');
      cursor_anchor:=item.memory_id; count_anchors:=count_anchors+1; touched:=touched+1;
    END LOOP;
    IF count_anchors=100 THEN
      UPDATE mem9_maintenance.change_progress SET after_anchor=cursor_anchor WHERE namespace_id=p_namespace AND event_id=event.event_id;
      EXIT;
    END IF;
    DELETE FROM mem9_maintenance.changes WHERE namespace_id=p_namespace AND event_id=event.event_id;
    total:=total+1;
    IF touched>=p_limit THEN EXIT; END IF;
  END LOOP;
  RETURN total;
END $$;

-- Preserve the foundation API without allowing it to discard dependency events
-- in namespaces that opted into the incremental planner, including while paused.
CREATE OR REPLACE FUNCTION mem9_maintenance.consume_changes(p_namespace TEXT,p_limit INTEGER) RETURNS INTEGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE event_ids BIGINT[]; item RECORD;
BEGIN
  PERFORM mem9_maintenance.authorize(p_namespace,'planner');
  PERFORM mem9_maintenance.lock_model();
  IF EXISTS(SELECT FROM mem9_maintenance.planner_policies WHERE namespace_id=p_namespace) THEN
    RETURN mem9_maintenance.consume_planner_changes(p_namespace,p_limit); END IF;
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 1000 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid change batch'; END IF;
  PERFORM mem9_maintenance.lock_queue(p_namespace);
  SELECT array_agg(event_id) INTO event_ids FROM
    (SELECT c.event_id FROM mem9_maintenance.changes c WHERE c.namespace_id=p_namespace ORDER BY c.event_id LIMIT p_limit FOR UPDATE SKIP LOCKED) claimed;
  FOR item IN SELECT c.memory_id,min(c.observed_at) AS seen FROM mem9_maintenance.changes c WHERE c.namespace_id=p_namespace
    AND c.event_id=ANY(event_ids) GROUP BY c.memory_id ORDER BY c.memory_id LOOP
    PERFORM mem9_maintenance.dirty(p_namespace,item.memory_id,item.seen,'changed');
  END LOOP;
  DELETE FROM mem9_maintenance.changes WHERE namespace_id=p_namespace AND event_id=ANY(event_ids);
  RETURN coalesce(cardinality(event_ids),0);
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.audit_planner(p_namespace TEXT,p_limit INTEGER) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE audit mem9_maintenance.planner_audits; item RECORD; seen INTEGER:=0; changed INTEGER:=0; last_id TEXT;
BEGIN
  PERFORM mem9_maintenance.planner_guard(p_namespace);
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 1000 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid planner audit batch'; END IF;
  INSERT INTO mem9_maintenance.planner_audits(namespace_id) VALUES(p_namespace) ON CONFLICT DO NOTHING;
  SELECT * INTO audit FROM mem9_maintenance.planner_audits WHERE namespace_id=p_namespace FOR UPDATE;
  IF audit.next_at>clock_timestamp() THEN RETURN jsonb_build_object('scanned',0,'changed',0); END IF;
  IF NOT audit.missing THEN
    FOR item IN SELECT m.id,encode(sha256(convert_to(to_jsonb(m)::text,'UTF8')),'hex') AS fingerprint
      FROM public.memories m WHERE m.namespace_id=p_namespace AND m.state='active' AND m.memory_type<>'session'
        AND (audit.after_id IS NULL OR m.id>audit.after_id) ORDER BY m.id LIMIT p_limit LOOP
      seen:=seen+1; last_id:=item.id;
      IF NOT EXISTS(SELECT FROM mem9_maintenance.planner_coverage WHERE namespace_id=p_namespace AND memory_id=item.id AND fingerprint=item.fingerprint) THEN
        PERFORM mem9_maintenance.dirty_planner_input(p_namespace,item.id,clock_timestamp(),'audit'); changed:=changed+1;
        INSERT INTO mem9_maintenance.planner_coverage VALUES(p_namespace,item.id,item.fingerprint)
          ON CONFLICT(namespace_id,memory_id) DO UPDATE SET fingerprint=EXCLUDED.fingerprint;
      END IF;
    END LOOP;
    UPDATE mem9_maintenance.planner_audits SET after_id=CASE WHEN seen=p_limit THEN last_id END,missing=seen<p_limit WHERE namespace_id=p_namespace;
  ELSE
    FOR item IN SELECT c.memory_id FROM mem9_maintenance.planner_coverage c WHERE c.namespace_id=p_namespace
      AND (audit.after_id IS NULL OR c.memory_id>audit.after_id) AND NOT EXISTS(SELECT FROM public.memories m WHERE m.namespace_id=p_namespace AND m.id=c.memory_id AND m.state='active' AND m.memory_type<>'session')
      ORDER BY c.memory_id LIMIT p_limit LOOP
      seen:=seen+1; last_id:=item.memory_id;
      PERFORM mem9_maintenance.dirty_planner_input(p_namespace,item.memory_id,clock_timestamp(),'audit'); changed:=changed+1;
      DELETE FROM mem9_maintenance.planner_coverage WHERE namespace_id=p_namespace AND memory_id=item.memory_id;
    END LOOP;
    UPDATE mem9_maintenance.planner_audits SET after_id=CASE WHEN seen=p_limit THEN last_id END,missing=seen=p_limit,
      next_at=CASE WHEN seen=p_limit THEN clock_timestamp() ELSE clock_timestamp()+interval '7 days' END WHERE namespace_id=p_namespace;
  END IF;
  RETURN jsonb_build_object('scanned',seen,'changed',changed);
END $$;

CREATE OR REPLACE FUNCTION mem9_maintenance.model_units(a JSONB,b JSONB,sign INTEGER DEFAULT 1) RETURNS JSONB
LANGUAGE SQL IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
  SELECT jsonb_object_agg(k,coalesce((a->>k)::bigint,0)+sign*coalesce((b->>k)::bigint,0)) FROM unnest(ARRAY['requests','input','output']) k
$$;
CREATE OR REPLACE FUNCTION mem9_maintenance.valid_model_units(value JSONB,usage BOOLEAN DEFAULT FALSE) RETURNS BOOLEAN
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE k TEXT;
BEGIN
  IF jsonb_typeof(value) IS DISTINCT FROM 'object' THEN RETURN FALSE; END IF;
  IF (SELECT count(*) FROM jsonb_object_keys(value))<>(CASE WHEN usage THEN 2 ELSE 3 END) THEN RETURN FALSE; END IF;
  FOREACH k IN ARRAY (CASE WHEN usage THEN ARRAY['input','output'] ELSE ARRAY['requests','input','output'] END) LOOP
    IF jsonb_typeof(value->k) IS DISTINCT FROM 'number' OR (value->>k)!~'^[0-9]+$' OR (value->>k)::numeric>power(2::numeric,53)-1 THEN RETURN FALSE; END IF;
  END LOOP;
  RETURN TRUE;
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.set_planner_model_budget(p_scope TEXT,p_limits JSONB,p_slots INTEGER DEFAULT NULL,p_unknown INTEGER DEFAULT NULL) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE rev BIGINT;
BEGIN
  IF p_scope IS NULL OR NOT mem9_maintenance.valid_model_units(p_limits) OR
    (p_scope='stage' AND (p_slots IS NULL OR p_slots NOT BETWEEN 1 AND 4 OR p_unknown IS NULL OR p_unknown NOT BETWEEN 1 AND p_slots)) OR
    (p_scope<>'stage' AND (p_slots IS NOT NULL OR p_unknown IS NOT NULL)) THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid model budget'; END IF;
  PERFORM mem9_maintenance.lock_model();
  INSERT INTO mem9_maintenance.model_policies AS p(scope,namespace_id,limits) VALUES(p_scope,CASE WHEN p_scope<>'stage' THEN p_scope END,p_limits)
    ON CONFLICT(scope) DO UPDATE SET revision=p.revision+1,limits=EXCLUDED.limits RETURNING revision INTO rev;
  IF p_scope='stage' THEN UPDATE mem9_maintenance.model_control SET slots=p_slots,unknown_limit=p_unknown,revision=revision+1 WHERE singleton; END IF;
  INSERT INTO mem9_maintenance.model_policy_history(scope,revision,policy,changed_by)
    VALUES(p_scope,rev,jsonb_build_object('limits',p_limits,'slots',p_slots,'unknown_limit',p_unknown),(SELECT oid FROM pg_roles WHERE rolname=session_user));
  -- Existing usage/reservations and breaker state are never reset by policy.
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.charge_model_attempt(p_id UUID,p_usage JSONB) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a mem9_maintenance.model_attempts; actual JSONB; delta JSONB; scope_name TEXT; valid BOOLEAN; violation BOOLEAN:=FALSE; next_status TEXT;
BEGIN
  SELECT * INTO a FROM mem9_maintenance.model_attempts WHERE attempt_id=p_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='model attempt not found'; END IF;
  valid:=mem9_maintenance.valid_model_units(p_usage,TRUE);
  IF a.status IN ('settled','resolved') AND (NOT valid OR
    ((p_usage->>'input')::bigint<=(a.charged->>'input')::bigint AND (p_usage->>'output')::bigint<=(a.charged->>'output')::bigint)) THEN
    RETURN jsonb_build_object('status','settled'); END IF;
  IF valid THEN
    violation:=(p_usage->>'input')::bigint>(a.reserved->>'input')::bigint OR (p_usage->>'output')::bigint>(a.reserved->>'output')::bigint;
    actual:=jsonb_build_object('requests',1,'input',greatest((p_usage->>'input')::bigint,(a.charged->>'input')::bigint,
      CASE WHEN violation THEN (a.reserved->>'input')::bigint ELSE 0 END),
      'output',greatest((p_usage->>'output')::bigint,(a.charged->>'output')::bigint,CASE WHEN violation THEN (a.reserved->>'output')::bigint ELSE 0 END));
  ELSE actual:=mem9_maintenance.model_units(a.reserved,'{}'); violation:=p_usage IS NOT NULL;
  END IF;
  -- A late unknown report can only increase the conservative floor.
  SELECT jsonb_object_agg(k,greatest((actual->>k)::bigint,(a.charged->>k)::bigint)) INTO actual FROM unnest(ARRAY['requests','input','output']) k;
  delta:=mem9_maintenance.model_units(actual,a.charged,-1);
  FOREACH scope_name IN ARRAY ARRAY['stage',a.namespace_id::text] LOOP
    UPDATE mem9_maintenance.model_windows SET used=mem9_maintenance.model_units(used,delta),
      reserved=CASE WHEN a.status IN ('reserved','dispatched') THEN mem9_maintenance.model_units(reserved,a.reserved,-1) ELSE reserved END
      WHERE scope=scope_name AND day=a.day;
  END LOOP;
  next_status:=CASE WHEN a.status='resolved' THEN 'resolved' WHEN a.status='unknown' OR NOT valid THEN 'unknown' ELSE 'settled' END;
  UPDATE mem9_maintenance.model_attempts SET charged=actual,status=next_status WHERE attempt_id=p_id;
  IF violation THEN UPDATE mem9_maintenance.model_control SET paused=TRUE WHERE singleton; END IF;
  RETURN jsonb_build_object('status',CASE WHEN violation THEN 'contract_violation' ELSE next_status END);
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.reap_model_attempts() RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE item RECORD;
BEGIN
  FOR item IN SELECT attempt_id,status FROM mem9_maintenance.model_attempts WHERE status IN ('reserved','dispatched') AND expires_at<=clock_timestamp()
    ORDER BY expires_at LIMIT 1000 LOOP
    IF item.status='reserved' THEN PERFORM mem9_maintenance.cancel_model_reservation(item.attempt_id,'reservation_expired');
    ELSE PERFORM mem9_maintenance.charge_model_attempt(item.attempt_id,NULL); END IF;
  END LOOP;
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.reserve_planner_model(p_namespace TEXT,p_anchor TEXT,p_lease BIGINT,p_remaining_ms INTEGER) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE n mem9_maintenance.neighborhoods; w mem9_maintenance.work; contract JSONB; units JSONB; ctl mem9_maintenance.model_control;
  scope_name TEXT; k TEXT; d DATE; usage mem9_maintenance.model_windows; policy mem9_maintenance.model_policies; id UUID;
BEGIN
  PERFORM mem9_maintenance.planner_guard(p_namespace);
  PERFORM mem9_maintenance.reap_model_attempts();
  SELECT * INTO n FROM mem9_maintenance.neighborhoods WHERE namespace_id=p_namespace AND memory_id=p_anchor AND lease_generation=p_lease;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='missing model neighborhood'; END IF;
  SELECT * INTO w FROM mem9_maintenance.work WHERE namespace_id=p_namespace AND memory_id=p_anchor;
  IF w.lease_generation<>p_lease OR w.lease_until IS NULL OR w.lease_until<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='stale model lease'; END IF;
  IF p_remaining_ms IS NULL OR p_remaining_ms<136000 OR w.lease_until<clock_timestamp()+interval '136 seconds' THEN RETURN jsonb_build_object('status','deadline'); END IF;
  SELECT pp.policy->'model' INTO contract FROM mem9_maintenance.planner_policies pp WHERE pp.namespace_id=p_namespace AND pp.context_hash=n.context_hash;
  IF contract IS NULL OR contract='null' THEN RETURN jsonb_build_object('status','model_disabled'); END IF;
  IF EXISTS(SELECT FROM mem9_maintenance.model_attempts WHERE namespace_id=p_namespace AND memory_id=p_anchor AND lease_generation=p_lease) THEN RETURN jsonb_build_object('status','existing'); END IF;
  SELECT * INTO ctl FROM mem9_maintenance.model_control WHERE singleton;
  IF ctl.paused THEN RETURN jsonb_build_object('status','policy_wait'); END IF;
  IF (SELECT count(*) FROM mem9_maintenance.model_attempts WHERE status='unknown')>=ctl.unknown_limit THEN RETURN jsonb_build_object('status','uncertainty_wait'); END IF;
  IF (SELECT count(*) FROM mem9_maintenance.model_attempts WHERE status IN ('reserved','dispatched','unknown'))>=ctl.slots THEN RETURN jsonb_build_object('status','capacity_wait'); END IF;
  d:=(clock_timestamp() AT TIME ZONE 'UTC')::date;
  units:=jsonb_build_object('requests',1,'input',contract->'max_input_tokens','output',contract->'max_output_tokens');
  FOREACH scope_name IN ARRAY ARRAY['stage',p_namespace] LOOP
    SELECT * INTO policy FROM mem9_maintenance.model_policies WHERE scope=scope_name;
    IF NOT FOUND THEN RETURN jsonb_build_object('status','budget_wait'); END IF;
    INSERT INTO mem9_maintenance.model_windows(scope,day) VALUES(scope_name,d) ON CONFLICT DO NOTHING;
    SELECT * INTO usage FROM mem9_maintenance.model_windows WHERE scope=scope_name AND day=d;
    FOREACH k IN ARRAY ARRAY['requests','input','output'] LOOP
      IF (usage.used->>k)::bigint+(usage.reserved->>k)::bigint+(units->>k)::bigint>(policy.limits->>k)::bigint THEN
        RETURN jsonb_build_object('status','budget_wait'); END IF;
    END LOOP;
  END LOOP;
  FOREACH scope_name IN ARRAY ARRAY['stage',p_namespace] LOOP
    UPDATE mem9_maintenance.model_windows SET reserved=mem9_maintenance.model_units(reserved,units) WHERE scope=scope_name AND day=d;
  END LOOP;
  INSERT INTO mem9_maintenance.model_attempts(namespace_id,memory_id,lease_generation,caller,day,contract,stage_revision,namespace_revision,control_revision,reserved,expires_at)
    VALUES(p_namespace,p_anchor,p_lease,(SELECT oid FROM pg_roles WHERE rolname=session_user),d,contract,
      (SELECT revision FROM mem9_maintenance.model_policies WHERE scope='stage'),(SELECT revision FROM mem9_maintenance.model_policies WHERE scope=p_namespace),ctl.revision,units,
      least(w.lease_until,clock_timestamp()+interval '125 seconds')) RETURNING attempt_id INTO id;
  RETURN jsonb_build_object('status','admitted','attempt_id',id,'contract',contract,
    'max_input_tokens',contract->'max_input_tokens','max_output_tokens',contract->'max_output_tokens');
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.dispatch_planner_model(p_namespace TEXT,p_id UUID) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a mem9_maintenance.model_attempts; w mem9_maintenance.work;
BEGIN
  PERFORM mem9_maintenance.planner_guard(p_namespace);
  SELECT * INTO a FROM mem9_maintenance.model_attempts WHERE namespace_id=p_namespace AND attempt_id=p_id FOR UPDATE;
  IF NOT FOUND OR a.caller IS DISTINCT FROM (SELECT oid FROM pg_roles WHERE rolname=session_user) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='model attempt denied'; END IF;
  SELECT * INTO w FROM mem9_maintenance.work WHERE namespace_id=p_namespace AND memory_id=a.memory_id;
  IF a.status<>'reserved' OR a.expires_at<=clock_timestamp() OR a.day<>(clock_timestamp() AT TIME ZONE 'UTC')::date OR
    w.lease_generation<>a.lease_generation OR w.lease_until IS NULL OR w.lease_until<clock_timestamp()+interval '125 seconds' OR
    NOT EXISTS(SELECT FROM mem9_maintenance.neighborhoods n JOIN mem9_maintenance.planner_policies p USING(namespace_id)
      WHERE n.namespace_id=p_namespace AND n.memory_id=a.memory_id AND n.lease_generation=a.lease_generation AND n.context_hash=p.context_hash) OR
    a.contract IS DISTINCT FROM (SELECT policy->'model' FROM mem9_maintenance.planner_policies WHERE namespace_id=p_namespace) OR
    a.stage_revision IS DISTINCT FROM (SELECT revision FROM mem9_maintenance.model_policies WHERE scope='stage') OR
    a.namespace_revision IS DISTINCT FROM (SELECT revision FROM mem9_maintenance.model_policies WHERE scope=p_namespace) OR
    EXISTS(SELECT FROM mem9_maintenance.model_control WHERE singleton AND (paused OR revision<>a.control_revision)) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='model dispatch expired or paused'; END IF;
  UPDATE mem9_maintenance.model_attempts SET status='dispatched',expires_at=least(w.lease_until,clock_timestamp()+interval '125 seconds') WHERE attempt_id=p_id;
  RETURN jsonb_build_object('status','dispatched');
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.settle_planner_model(p_namespace TEXT,p_id UUID,p_usage JSONB) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE caller_id OID;
BEGIN
  -- Revocation must not strand already incurred spend. Only the authenticated
  -- bound login that owns this attempt may submit content-free usage.
  SELECT c.role_oid INTO caller_id FROM mem9_maintenance.database_callers c JOIN pg_roles r ON r.oid=c.role_oid WHERE r.rolname=session_user AND c.capability='planner';
  IF caller_id IS NULL OR NOT EXISTS(SELECT FROM mem9_maintenance.model_attempts WHERE namespace_id=p_namespace AND attempt_id=p_id AND caller=caller_id) THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='model accounting denied'; END IF;
  PERFORM mem9_maintenance.lock_model();
  RETURN mem9_maintenance.charge_model_attempt(p_id,p_usage);
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.resolve_model_uncertainty(p_id UUID,p_reason TEXT) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  IF p_reason IS NULL OR p_reason !~ '^[a-z0-9_-]{1,64}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid resolution reason'; END IF;
  PERFORM mem9_maintenance.lock_model();
  PERFORM mem9_maintenance.reap_model_attempts();
  IF p_id IS NOT NULL THEN
    UPDATE mem9_maintenance.model_attempts SET status='resolved' WHERE attempt_id=p_id AND status='unknown';
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='model uncertainty not found'; END IF;
  ELSE
    IF EXISTS(SELECT FROM mem9_maintenance.model_attempts WHERE status IN ('reserved','dispatched','unknown')) THEN
      RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='model attempts remain outstanding'; END IF;
    UPDATE mem9_maintenance.model_control SET paused=FALSE,revision=revision+1 WHERE singleton;
  END IF;
  INSERT INTO mem9_maintenance.model_resolutions(attempt_id,changed_by,reason) VALUES(p_id,(SELECT oid FROM pg_roles WHERE rolname=session_user),p_reason);
END $$;

CREATE OR REPLACE FUNCTION mem9_maintenance.cancel_model_reservation(p_id UUID,p_reason TEXT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a mem9_maintenance.model_attempts; scope_name TEXT;
BEGIN
  SELECT * INTO a FROM mem9_maintenance.model_attempts WHERE attempt_id=p_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='model reservation missing'; END IF;
  IF a.status<>'reserved' THEN RETURN jsonb_build_object('status',a.status); END IF;
  FOREACH scope_name IN ARRAY ARRAY['stage',a.namespace_id::text] LOOP
    UPDATE mem9_maintenance.model_windows SET reserved=mem9_maintenance.model_units(reserved,a.reserved,-1) WHERE scope=scope_name AND day=a.day;
  END LOOP;
  UPDATE mem9_maintenance.model_attempts SET status='resolved' WHERE attempt_id=p_id;
  INSERT INTO mem9_maintenance.model_resolutions(attempt_id,changed_by,reason) VALUES(p_id,(SELECT oid FROM pg_roles WHERE rolname=session_user),p_reason);
  RETURN jsonb_build_object('status','cancelled');
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.cancel_planner_model(p_namespace TEXT,p_id UUID) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE caller_id OID;
BEGIN
  -- A definitive pre-dispatch rejection can be cancelled even after namespace
  -- revocation. A dispatched/unknown attempt can NEVER be refunded here.
  SELECT c.role_oid INTO caller_id FROM mem9_maintenance.database_callers c JOIN pg_roles r ON r.oid=c.role_oid WHERE r.rolname=session_user AND c.capability='planner';
  IF caller_id IS NULL OR NOT EXISTS(SELECT FROM mem9_maintenance.model_attempts WHERE namespace_id=p_namespace AND attempt_id=p_id AND caller=caller_id) THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='model cancellation denied'; END IF;
  PERFORM mem9_maintenance.lock_model();
  RETURN mem9_maintenance.cancel_model_reservation(p_id,'not_dispatched');
END $$;

CREATE OR REPLACE FUNCTION mem9_maintenance.defer_neighborhood(p_namespace TEXT,p_anchor TEXT,p_lease BIGINT,p_reason TEXT) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE w mem9_maintenance.work; a mem9_maintenance.model_attempts; free_attempt BOOLEAN; scope_name TEXT;
BEGIN
  PERFORM mem9_maintenance.planner_guard(p_namespace);
  IF p_reason IS NULL OR p_reason NOT IN ('budget_wait','capacity_wait','uncertainty_wait','model_disabled','policy_wait','deadline','model_failed','invalid_result','inputs_changed','existing') THEN
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
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.planner_status(p_namespace TEXT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  PERFORM mem9_maintenance.planner_guard(p_namespace);
  PERFORM mem9_maintenance.reap_model_attempts();
  RETURN mem9_maintenance.queue_status(p_namespace)||jsonb_build_object(
    'overflow',(SELECT count(*) FROM mem9_maintenance.planner_progress WHERE namespace_id=p_namespace),
    'delayed',(SELECT count(*) FROM mem9_maintenance.work WHERE namespace_id=p_namespace AND desired_generation>completed_generation AND due_at>clock_timestamp()),
    'review',(SELECT count(*) FROM mem9_maintenance.classifications WHERE namespace_id=p_namespace AND result='REVIEW')+
      (SELECT count(*) FROM mem9_maintenance.execution_reviews WHERE namespace_id=p_namespace),
    'queued_actions',(SELECT count(*) FROM mem9_maintenance.action_state WHERE namespace_id=p_namespace AND status='queued'),
    'generation_resets',(SELECT coalesce(sum(resets),0) FROM mem9_maintenance.planner_deferrals WHERE namespace_id=p_namespace),
    'unknown_model_attempts',(SELECT count(*) FROM mem9_maintenance.model_attempts WHERE namespace_id=p_namespace AND status='unknown'));
END $$;

DO $$ DECLARE t TEXT; BEGIN
  FOREACH t IN ARRAY ARRAY['planner_policy_history','neighborhoods','planner_finishes','model_policy_history','model_resolutions'] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS maintenance_immutable ON mem9_maintenance.%I',t);
    EXECUTE format('CREATE TRIGGER maintenance_immutable BEFORE UPDATE OR DELETE ON mem9_maintenance.%I FOR EACH ROW EXECUTE FUNCTION mem9_maintenance.immutable()',t);
  END LOOP;
END $$;
REVOKE ALL ON ALL TABLES IN SCHEMA mem9_maintenance FROM PUBLIC,mem9_maintenance_planner,mem9_maintenance_executor,mem9_maintenance_backend,mem9_maintenance_operator;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA mem9_maintenance FROM PUBLIC,mem9_maintenance_planner,mem9_maintenance_executor,mem9_maintenance_backend,mem9_maintenance_operator;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mem9_maintenance FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mem9_maintenance.claim_neighborhood(TEXT),mem9_maintenance.finish_neighborhood(TEXT,TEXT,BIGINT,TEXT),
  mem9_maintenance.planner_receipt(TEXT,TEXT,BIGINT),mem9_maintenance.consume_planner_changes(TEXT,INTEGER),mem9_maintenance.audit_planner(TEXT,INTEGER),
  mem9_maintenance.reserve_planner_model(TEXT,TEXT,BIGINT,INTEGER),mem9_maintenance.dispatch_planner_model(TEXT,UUID),
  mem9_maintenance.cancel_planner_model(TEXT,UUID),
  mem9_maintenance.settle_planner_model(TEXT,UUID,JSONB),mem9_maintenance.defer_neighborhood(TEXT,TEXT,BIGINT,TEXT),mem9_maintenance.planner_status(TEXT)
  TO mem9_maintenance_planner;
COMMIT;
