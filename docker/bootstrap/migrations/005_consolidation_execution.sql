-- Private atomic execution. All switches, policies and login bindings start
-- closed; installing this migration does not authorize production activation.
BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='30s';
SELECT pg_advisory_xact_lock(hashtext('mem9-maintenance-schema-v1'));

DO $$
DECLARE name TEXT;
BEGIN
  FOREACH name IN ARRAY ARRAY['mem9_maintenance_backend','mem9_maintenance_operator'] LOOP
    IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname=name) THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',name);
    END IF;
    IF EXISTS(SELECT FROM pg_roles WHERE rolname=name AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) THEN
      RAISE EXCEPTION 'unexpected maintenance role privileges';
    END IF;
  END LOOP;
END $$;
ALTER TABLE mem9_maintenance.database_callers DROP CONSTRAINT IF EXISTS database_callers_capability_check;
ALTER TABLE mem9_maintenance.database_callers ADD CONSTRAINT database_callers_capability_check
  CHECK(capability IN ('planner','executor','backend','operator'));
CREATE TABLE IF NOT EXISTS mem9_maintenance.operator_principals(
  role_oid OID PRIMARY KEY REFERENCES mem9_maintenance.database_callers(role_oid),
  principal_id VARCHAR(36) NOT NULL REFERENCES public.memory_principals(principal_id)
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.execution_control(
  singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),
  stage TEXT NOT NULL DEFAULT '',
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  epoch BIGINT NOT NULL DEFAULT 1 CHECK(epoch>0),
  embedding_model TEXT NOT NULL DEFAULT 'qwen3-embedding-0.6b',
  retired_roles OID[] NOT NULL DEFAULT '{}'
);
INSERT INTO mem9_maintenance.execution_control(singleton) VALUES(TRUE) ON CONFLICT DO NOTHING;
CREATE OR REPLACE FUNCTION mem9_maintenance.valid_cost(value JSONB) RETURNS BOOLEAN
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE k TEXT;
BEGIN
  IF jsonb_typeof(value) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(value))<>5 THEN RETURN FALSE; END IF;
  FOREACH k IN ARRAY ARRAY['total','rewrite','delete','archive','mark'] LOOP
    IF jsonb_typeof(value->k) IS DISTINCT FROM 'number' OR (value->>k)!~'^[0-9]+$' OR (value->>k)::numeric>1000000 THEN RETURN FALSE; END IF;
  END LOOP;
  RETURN TRUE;
END $$;
CREATE TABLE IF NOT EXISTS mem9_maintenance.budget_policies(
  scope TEXT PRIMARY KEY,
  namespace_id VARCHAR(36) UNIQUE REFERENCES public.memory_namespaces(namespace_id),
  epoch BIGINT NOT NULL DEFAULT 1,
  policy JSONB NOT NULL,
  CHECK((scope='stage' AND namespace_id IS NULL) OR scope=namespace_id)
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.budget_windows(
  scope TEXT NOT NULL REFERENCES mem9_maintenance.budget_policies(scope),
  day DATE NOT NULL,
  active_count BIGINT NOT NULL,
  limits JSONB NOT NULL,
  used JSONB NOT NULL DEFAULT '{"total":0,"rewrite":0,"delete":0,"archive":0,"mark":0}',
  reserved JSONB NOT NULL DEFAULT '{"total":0,"rewrite":0,"delete":0,"archive":0,"mark":0}',
  PRIMARY KEY(scope,day),
  CHECK(mem9_maintenance.valid_cost(limits) AND mem9_maintenance.valid_cost(used) AND mem9_maintenance.valid_cost(reserved))
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.budget_policy_history(
  scope TEXT NOT NULL REFERENCES mem9_maintenance.budget_policies(scope),
  epoch BIGINT NOT NULL,
  policy JSONB NOT NULL,
  changed_by OID NOT NULL,
  changed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(scope,epoch)
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.apply_admission(
  scope TEXT PRIMARY KEY REFERENCES mem9_maintenance.budget_policies(scope),
  tokens NUMERIC NOT NULL CHECK(tokens>=0),
  refilled_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.actions(
  namespace_id VARCHAR(36) NOT NULL,
  action_id TEXT NOT NULL CHECK(action_id ~ '^[0-9a-f]{64}$'),
  classification_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('MERGE','ARCHIVE','STALE')),
  context_hash TEXT NOT NULL,
  semantic_hash TEXT NOT NULL,
  members JSONB NOT NULL,
  output JSONB NOT NULL,
  cost JSONB NOT NULL CHECK(mem9_maintenance.valid_cost(cost)),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,action_id),
  UNIQUE(namespace_id,classification_id),
  FOREIGN KEY(namespace_id,classification_id) REFERENCES mem9_maintenance.classifications(namespace_id,classification_id),
  CHECK(octet_length(members::text)+octet_length(output::text)<=1048576)
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.action_state(
  namespace_id VARCHAR(36) NOT NULL,
  action_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','leased','preparing','ready','applied','noop','invalidated','review','policy_blocked')),
  reason TEXT NOT NULL DEFAULT '',
  generation BIGINT NOT NULL DEFAULT 0,
  attempts INTEGER NOT NULL DEFAULT 0,
  lease_until TIMESTAMPTZ,
  budget_day DATE,
  control_epoch BIGINT,
  stage_epoch BIGINT,
  namespace_epoch BIGINT,
  reservation JSONB CHECK(reservation IS NULL OR mem9_maintenance.valid_cost(reservation)),
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  next_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,action_id),
  FOREIGN KEY(namespace_id,action_id) REFERENCES mem9_maintenance.actions(namespace_id,action_id)
);
CREATE INDEX IF NOT EXISTS maintenance_actions_ready ON mem9_maintenance.action_state(namespace_id,next_at,first_seen_at)
  WHERE status='queued';
CREATE INDEX IF NOT EXISTS maintenance_actions_expiring ON mem9_maintenance.action_state(lease_until,namespace_id,action_id)
  WHERE reservation IS NOT NULL;
CREATE TABLE IF NOT EXISTS mem9_maintenance.preparations(
  namespace_id VARCHAR(36) NOT NULL,
  action_id TEXT NOT NULL,
  generation BIGINT NOT NULL,
  owner_token UUID NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('preparing','ready','abandoned')),
  content_hash TEXT NOT NULL,
  embedding_model TEXT NOT NULL,
  embedding public.vector(1024),
  PRIMARY KEY(namespace_id,action_id,generation),
  FOREIGN KEY(namespace_id,action_id) REFERENCES mem9_maintenance.actions(namespace_id,action_id)
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.receipts(
  namespace_id VARCHAR(36) NOT NULL,
  action_id TEXT NOT NULL,
  result JSONB NOT NULL,
  before_images JSONB NOT NULL,
  post_images JSONB NOT NULL,
  committed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,action_id),
  FOREIGN KEY(namespace_id,action_id) REFERENCES mem9_maintenance.actions(namespace_id,action_id),
  CHECK(octet_length(before_images::text)+octet_length(post_images::text)<=2097152)
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.undo_receipts(
  namespace_id VARCHAR(36) NOT NULL,
  action_id TEXT NOT NULL,
  operator_id VARCHAR(36) NOT NULL,
  restored_rows INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,action_id),
  FOREIGN KEY(namespace_id,action_id) REFERENCES mem9_maintenance.receipts(namespace_id,action_id)
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.suppressions(
  namespace_id VARCHAR(36) NOT NULL REFERENCES public.memory_namespaces(namespace_id),
  semantic_hash TEXT NOT NULL,
  kind TEXT NOT NULL,
  member_hashes JSONB NOT NULL,
  reason TEXT NOT NULL,
  PRIMARY KEY(namespace_id,semantic_hash)
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.execution_reviews(
  namespace_id VARCHAR(36) NOT NULL,
  classification_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,classification_id),
  FOREIGN KEY(namespace_id,classification_id) REFERENCES mem9_maintenance.classifications(namespace_id,classification_id)
);
DO $$
DECLARE name TEXT;
BEGIN
  FOREACH name IN ARRAY ARRAY['actions','receipts','undo_receipts','budget_policy_history'] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS maintenance_immutable ON mem9_maintenance.%I',name);
    EXECUTE format('CREATE TRIGGER maintenance_immutable BEFORE UPDATE OR DELETE ON mem9_maintenance.%I FOR EACH ROW EXECUTE FUNCTION mem9_maintenance.immutable()',name);
  END LOOP;
END $$;

-- The private clock has no caller override. Integration tests may replace it
-- only inside their disposable database to exercise exact UTC boundaries.
CREATE OR REPLACE FUNCTION mem9_maintenance.execution_time() RETURNS TIMESTAMPTZ
LANGUAGE SQL VOLATILE SET search_path=pg_catalog,pg_temp AS $$ SELECT clock_timestamp() $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.semantic_member_hash(value JSONB) RETURNS JSONB
LANGUAGE SQL IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
  SELECT jsonb_build_object('id',value->>'id','hash',encode(sha256(convert_to(
    (value-ARRAY['embedding','version','updated_at','updated_by','updated_by_principal_id'])::text,'UTF8')),'hex'))
$$;
CREATE OR REPLACE FUNCTION mem9_maintenance.legacy_write_allowed() RETURNS BOOLEAN
LANGUAGE SQL VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
  SELECT NOT enabled FROM mem9_maintenance.execution_control WHERE singleton FOR SHARE
$$;
CREATE OR REPLACE FUNCTION mem9_maintenance.cost_add(a JSONB,b JSONB,sign INTEGER DEFAULT 1) RETURNS JSONB
LANGUAGE SQL IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
  SELECT jsonb_object_agg(k,coalesce((a->>k)::bigint,0)+sign*coalesce((b->>k)::bigint,0))
  FROM unnest(ARRAY['total','rewrite','delete','archive','mark']) k
$$;

-- Owner-only setup. No task/model can supply a policy or retirement inventory.
CREATE OR REPLACE FUNCTION mem9_maintenance.set_execution_mode(p_stage TEXT,p_enabled BOOLEAN,p_retired OID[],p_model TEXT)
RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE old_stage TEXT;
BEGIN
  SELECT stage INTO old_stage FROM mem9_maintenance.execution_control WHERE singleton FOR UPDATE;
  IF p_stage IS NULL OR p_stage!~'^[a-zA-Z0-9][a-zA-Z0-9-]{0,63}$' OR (old_stage<>'' AND old_stage<>p_stage) OR
    p_enabled IS NULL OR p_model IS NULL OR length(p_model) NOT BETWEEN 1 AND 128 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid execution configuration'; END IF;
  IF p_enabled AND (coalesce(cardinality(p_retired),0)=0 OR array_position(p_retired,NULL) IS NOT NULL OR 0=ANY(p_retired) OR
    EXISTS(SELECT FROM pg_roles WHERE oid=ANY(p_retired) AND rolcanlogin) OR
    EXISTS(SELECT FROM pg_stat_activity WHERE usesysid=ANY(p_retired))) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='legacy credentials or sessions remain active'; END IF;
  IF p_enabled AND (NOT EXISTS(SELECT FROM mem9_maintenance.budget_policies WHERE scope='stage') OR
    NOT EXISTS(SELECT FROM mem9_maintenance.namespace_state WHERE capture_enabled) OR
    EXISTS(SELECT FROM mem9_maintenance.namespace_state n WHERE n.capture_enabled AND NOT EXISTS(SELECT FROM mem9_maintenance.budget_policies p WHERE p.scope=n.namespace_id)) OR
    (SELECT count(DISTINCT c.capability) FROM mem9_maintenance.database_callers c JOIN pg_roles r ON r.oid=c.role_oid
      WHERE c.capability IN ('backend','executor') AND r.rolcanlogin AND pg_has_role(r.oid,('mem9_maintenance_'||c.capability)::name,'USAGE'))<>2) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='execution prerequisites missing'; END IF;
  UPDATE mem9_maintenance.execution_control SET stage=p_stage,enabled=p_enabled,epoch=epoch+1,
    retired_roles=coalesce(p_retired,'{}'),embedding_model=p_model WHERE singleton;
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.set_budget_policy(p_scope TEXT,p_policy JSONB)
RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE k TEXT; ns TEXT; revision BIGINT;
BEGIN
  IF p_scope<>'stage' THEN
    SELECT namespace_id INTO ns FROM public.memory_namespaces WHERE namespace_id=p_scope AND status='active' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='budget namespace denied'; END IF;
  END IF;
  PERFORM singleton FROM mem9_maintenance.execution_control WHERE singleton FOR UPDATE;
  IF jsonb_typeof(p_policy) IS DISTINCT FROM 'object' OR NOT p_policy ?& ARRAY['limits','bps','rate','burst'] OR
    (SELECT count(*) FROM jsonb_object_keys(p_policy))<>4 OR jsonb_typeof(p_policy->'limits') IS DISTINCT FROM 'object' OR
    jsonb_typeof(p_policy->'bps') IS DISTINCT FROM 'object' THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid budget policy'; END IF;
  FOREACH k IN ARRAY ARRAY['total','rewrite','delete','archive','mark'] LOOP
    IF jsonb_typeof(p_policy->'limits'->k) IS DISTINCT FROM 'number' OR jsonb_typeof(p_policy->'bps'->k) IS DISTINCT FROM 'number' OR
      coalesce(p_policy->'limits'->>k,'')!~'^[0-9]+$' OR (p_policy->'limits'->>k)::numeric>1000000 OR
      coalesce(p_policy->'bps'->>k,'')!~'^[0-9]+$' OR (p_policy->'bps'->>k)::numeric NOT BETWEEN 1 AND 10000 THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid risk limit'; END IF;
  END LOOP;
  IF (SELECT count(*) FROM jsonb_object_keys(p_policy->'limits'))<>5 OR
    (SELECT count(*) FROM jsonb_object_keys(p_policy->'bps'))<>5 OR
    jsonb_typeof(p_policy->'rate') IS DISTINCT FROM 'number' OR jsonb_typeof(p_policy->'burst') IS DISTINCT FROM 'number' OR
    coalesce(p_policy->>'rate','')!~'^[0-9]+(\.[0-9]+)?$' OR (p_policy->>'rate')::numeric NOT BETWEEN 0.01 AND 100 OR
    coalesce(p_policy->>'burst','')!~'^[0-9]+$' OR (p_policy->>'burst')::numeric NOT BETWEEN 1 AND 1000 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid admission policy'; END IF;
  INSERT INTO mem9_maintenance.budget_policies AS p(scope,namespace_id,policy) VALUES(p_scope,ns,p_policy)
    ON CONFLICT(scope) DO UPDATE SET policy=EXCLUDED.policy,epoch=p.epoch+1 RETURNING epoch INTO revision;
  INSERT INTO mem9_maintenance.budget_policy_history(scope,epoch,policy,changed_by)
    SELECT p_scope,revision,p_policy,oid FROM pg_roles WHERE rolname=session_user;
  -- Explicit reviewed policy changes may change the current ceiling. Preserve
  -- both counters and the original denominator; newly written rows cannot
  -- inflate a running window. Historical policy versions remain immutable.
  UPDATE mem9_maintenance.budget_windows w SET limits=(SELECT jsonb_object_agg(risk,
    CASE WHEN p_scope='stage' THEN (p_policy->'limits'->>risk)::bigint ELSE
      least((p_policy->'limits'->>risk)::bigint,ceil(w.active_count*(p_policy->'bps'->>risk)::numeric/10000)::bigint) END)
    FROM unnest(ARRAY['total','rewrite','delete','archive','mark']) risk)
    WHERE w.scope=p_scope AND w.day=(mem9_maintenance.execution_time() AT TIME ZONE 'UTC')::date;
  INSERT INTO mem9_maintenance.apply_admission(scope,tokens,refilled_at)
    VALUES(p_scope,(p_policy->>'burst')::numeric,mem9_maintenance.execution_time()) ON CONFLICT DO NOTHING;
  UPDATE mem9_maintenance.action_state SET status='queued',reason='',next_at=mem9_maintenance.execution_time()
    WHERE (p_scope='stage' OR namespace_id=p_scope) AND (status='policy_blocked' OR (status='queued' AND reason='budget_wait'));
END $$;

CREATE OR REPLACE FUNCTION mem9_maintenance.execution_guard(p_namespace TEXT,p_capability TEXT,p_enabled BOOLEAN DEFAULT TRUE)
RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE c mem9_maintenance.execution_control;
BEGIN
  PERFORM mem9_maintenance.authorize(p_namespace,p_capability);
  SELECT * INTO c FROM mem9_maintenance.execution_control WHERE singleton FOR UPDATE;
  IF p_enabled AND (NOT c.enabled OR cardinality(c.retired_roles)=0 OR
    EXISTS(SELECT FROM pg_roles WHERE oid=ANY(c.retired_roles) AND rolcanlogin) OR
    EXISTS(SELECT FROM pg_stat_activity WHERE usesysid=ANY(c.retired_roles))) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='maintenance execution paused'; END IF;
END $$;

CREATE OR REPLACE FUNCTION mem9_maintenance.review_execution(p_namespace TEXT,p_class TEXT,p_reason TEXT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  INSERT INTO mem9_maintenance.execution_reviews(namespace_id,classification_id,reason) VALUES(p_namespace,p_class,p_reason) ON CONFLICT DO NOTHING;
  RETURN jsonb_build_object('status','review','reason',p_reason);
END $$;

-- Lossless first implementation: the server derives canonical content and
-- provenance. A model cannot inject replacement text, authority or row costs.
CREATE OR REPLACE FUNCTION mem9_maintenance.queue_classification(p_namespace TEXT,p_class TEXT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE c mem9_maintenance.classifications; snapshots JSONB:='[]'; semantic JSONB:='[]'; member RECORD; row_value JSONB;
  first_row JSONB; output JSONB; costs JSONB; content TEXT; target TEXT; count_members INTEGER; id TEXT; semhash TEXT; current_context TEXT;
BEGIN
  PERFORM mem9_maintenance.execution_guard(p_namespace,'planner',FALSE);
  SELECT * INTO c FROM mem9_maintenance.classifications WHERE namespace_id=p_namespace AND classification_id=p_class;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='classification not found'; END IF;
  SELECT action_id INTO id FROM mem9_maintenance.actions WHERE namespace_id=p_namespace AND classification_id=p_class;
  IF FOUND THEN RETURN jsonb_build_object('action_id',id,'status','existing'); END IF;
  SELECT context_hash INTO current_context FROM mem9_maintenance.namespace_state WHERE namespace_id=p_namespace AND capture_enabled;
  IF current_context IS DISTINCT FROM c.context_hash OR c.valid_until<=mem9_maintenance.execution_time() THEN
    RETURN mem9_maintenance.review_execution(p_namespace,p_class,'stale_classification'); END IF;
  IF c.result NOT IN ('MERGE','ARCHIVE','STALE') THEN RETURN mem9_maintenance.review_execution(p_namespace,p_class,'not_automatic'); END IF;
  FOR member IN SELECT * FROM mem9_maintenance.classification_members WHERE namespace_id=p_namespace AND classification_id=p_class ORDER BY memory_id LOOP
    SELECT to_jsonb(m) INTO row_value FROM public.memories m WHERE m.namespace_id=p_namespace AND m.id=member.memory_id
      AND m.state='active' FOR SHARE;
    IF NOT FOUND OR encode(sha256(convert_to(row_value::text,'UTF8')),'hex')<>member.fingerprint THEN
      RETURN mem9_maintenance.review_execution(p_namespace,p_class,'member_changed'); END IF;
    IF jsonb_typeof(nullif(row_value->'metadata','null')) IS NOT NULL AND jsonb_typeof(row_value->'metadata')<>'object' OR
      jsonb_typeof(nullif(row_value->'tags','null')) IS NOT NULL AND jsonb_typeof(row_value->'tags')<>'array' OR
      jsonb_typeof(nullif(row_value->'metadata'->'consolidation','null')) IS NOT NULL AND jsonb_typeof(row_value->'metadata'->'consolidation')<>'object' THEN
      RETURN mem9_maintenance.review_execution(p_namespace,p_class,'invalid_context'); END IF;
    IF row_value->>'memory_type' IS DISTINCT FROM 'insight' OR coalesce(row_value->'metadata'->>'protected','false')<>'false' OR
      coalesce(row_value->'tags','[]') ?| ARRAY['protected','pinned'] THEN
      RETURN mem9_maintenance.review_execution(p_namespace,p_class,'protected_member'); END IF;
    snapshots:=snapshots||jsonb_build_array(row_value);
    semantic:=semantic||jsonb_build_array(row_value-ARRAY['embedding','version','updated_at','updated_by','updated_by_principal_id']);
  END LOOP;
  count_members:=jsonb_array_length(snapshots);
  IF count_members=0 OR octet_length(snapshots::text)>1048576 THEN
    RETURN mem9_maintenance.review_execution(p_namespace,p_class,'input_bound'); END IF;
  SELECT value INTO first_row FROM jsonb_array_elements(snapshots) ORDER BY value->>'created_at',value->>'id' LIMIT 1;
  target:=first_row->>'id';
  costs:='{"total":0,"rewrite":0,"delete":0,"archive":0,"mark":0}';
  IF c.result='MERGE' THEN
    IF count_members NOT BETWEEN 2 AND 10 THEN RETURN mem9_maintenance.review_execution(p_namespace,p_class,'input_bound'); END IF;
    FOR row_value IN SELECT value FROM jsonb_array_elements(snapshots) LOOP
      IF (row_value->'app_id') IS DISTINCT FROM (first_row->'app_id') OR
        (row_value->'source') IS DISTINCT FROM (first_row->'source') OR (row_value->'agent_id') IS DISTINCT FROM (first_row->'agent_id') OR
        coalesce(nullif(row_value->'tags','null'),'[]') IS DISTINCT FROM coalesce(nullif(first_row->'tags','null'),'[]') OR
        (coalesce(nullif(row_value->'metadata','null'),'{}')-ARRAY['source_turns','source_seqs','consolidation']) IS DISTINCT FROM
        (coalesce(nullif(first_row->'metadata','null'),'{}')-ARRAY['source_turns','source_seqs','consolidation']) OR
        (coalesce(nullif(row_value->'metadata'->'consolidation','null'),'{}')-'sources') IS DISTINCT FROM
        (coalesce(nullif(first_row->'metadata'->'consolidation','null'),'{}')-'sources') THEN
        RETURN mem9_maintenance.review_execution(p_namespace,p_class,'context_conflict'); END IF;
    END LOOP;
    IF NOT EXISTS(SELECT FROM jsonb_array_elements(snapshots) m WHERE position((m->>'content') IN (first_row->>'content'))=0) THEN
      content:=first_row->>'content';
    ELSE
      SELECT string_agg(unique_content.text,E'\n\n' ORDER BY unique_content.created,unique_content.id) INTO content FROM
        (SELECT DISTINCT ON(value->>'content') value->>'content' AS text,value->>'created_at' AS created,value->>'id' AS id
         FROM jsonb_array_elements(snapshots) ORDER BY value->>'content',value->>'created_at',value->>'id') unique_content;
    END IF;
    output:=jsonb_build_object('target',target,'content',content,'tags',coalesce(nullif(first_row->'tags','null'),'[]'),
      'metadata',jsonb_set(coalesce(nullif(first_row->'metadata','null'),'{}'),'{consolidation}',coalesce(nullif(first_row->'metadata'->'consolidation','null'),'{}')||jsonb_build_object('sources',
        (SELECT jsonb_agg(value-ARRAY['embedding']) FROM jsonb_array_elements(snapshots))),TRUE));
    costs:=jsonb_build_object('total',count_members,'rewrite',CASE WHEN content IS DISTINCT FROM first_row->>'content' THEN 1 ELSE 0 END,
      'delete',count_members-1,'archive',0,'mark',0);
  ELSIF c.result='ARCHIVE' THEN
    IF count_members<>2 THEN RETURN mem9_maintenance.review_execution(p_namespace,p_class,'input_bound'); END IF;
    target:=c.payload->'details'->>'winner_id';
    SELECT value INTO first_row FROM jsonb_array_elements(snapshots) WHERE value->>'id'=target;
    IF NOT FOUND THEN RETURN mem9_maintenance.review_execution(p_namespace,p_class,'invalid_winner'); END IF;
    FOR row_value IN SELECT value FROM jsonb_array_elements(snapshots) LOOP
      IF first_row->>'created_at' IS NULL OR first_row->>'updated_at' IS NULL OR row_value->>'created_at' IS NULL OR row_value->>'updated_at' IS NULL OR
        (row_value->'tags')?'stale' OR row_value->'metadata'->'consolidation'->>'stale'='true' OR
        ((row_value->>'id')<>target AND ((row_value->>'created_at')::timestamptz >=(first_row->>'created_at')::timestamptz OR
        (row_value->>'updated_at')::timestamptz >=(first_row->>'updated_at')::timestamptz)) THEN
        RETURN mem9_maintenance.review_execution(p_namespace,p_class,'ambiguous_timeline'); END IF;
    END LOOP;
    output:=jsonb_build_object('target',target);
    costs:=jsonb_build_object('total',1,'rewrite',0,'delete',0,'archive',1,'mark',0);
  ELSE
    IF count_members<>1 OR jsonb_array_length(coalesce(nullif(first_row->'tags','null'),'[]'))>=20 THEN
      RETURN mem9_maintenance.review_execution(p_namespace,p_class,'input_bound'); END IF;
    output:=jsonb_build_object('target',target);
    costs:=jsonb_build_object('total',1,'rewrite',0,'delete',0,'archive',0,'mark',1);
  END IF;
  IF coalesce(length(content),0)>200000 OR ((costs->>'rewrite')::int>0 AND octet_length(content)>16384) OR octet_length(snapshots::text)+octet_length(output::text)>1048576 THEN
    RETURN mem9_maintenance.review_execution(p_namespace,p_class,'output_bound'); END IF;
  semhash:=encode(sha256(convert_to(c.result||semantic::text,'UTF8')),'hex');
  IF EXISTS(SELECT FROM mem9_maintenance.suppressions s WHERE s.namespace_id=p_namespace AND
    (s.semantic_hash=semhash OR (s.kind=c.result AND
      (SELECT count(*) FROM jsonb_array_elements(snapshots) m
       WHERE s.member_hashes @> jsonb_build_array(mem9_maintenance.semantic_member_hash(m)))
       >=CASE WHEN c.result='STALE' THEN 1 ELSE 2 END))) THEN
    RETURN mem9_maintenance.review_execution(p_namespace,p_class,'operator_suppressed'); END IF;
  id:=encode(sha256(convert_to(p_class||output::text,'UTF8')),'hex');
  INSERT INTO mem9_maintenance.actions(namespace_id,action_id,classification_id,kind,context_hash,semantic_hash,members,output,cost)
    VALUES(p_namespace,id,p_class,c.result,c.context_hash,semhash,snapshots,output,costs);
  INSERT INTO mem9_maintenance.action_state(namespace_id,action_id,first_seen_at)
    VALUES(p_namespace,id,least(c.created_at,coalesce((SELECT min(w.first_seen_at) FROM mem9_maintenance.work w
      WHERE w.namespace_id=p_namespace AND w.memory_id IN(SELECT value->>'id' FROM jsonb_array_elements(snapshots))),c.created_at)));
  RETURN jsonb_build_object('action_id',id,'status','queued');
END $$;

-- One control-row lock serializes the short execution/accounting transactions.
-- Order: namespace/principal/membership; control; try-only legacy mutex; stage
-- admission/window; namespace admission/window; action; sorted memory rows.
-- No database transaction spans a model or embedding request.
CREATE OR REPLACE FUNCTION mem9_maintenance.open_windows(p_namespace TEXT) RETURNS DATE
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE scope_name TEXT; policy JSONB; n BIGINT; limits JSONB; d DATE; k TEXT; lim BIGINT;
BEGIN
  d:=(mem9_maintenance.execution_time() AT TIME ZONE 'UTC')::date;
  FOREACH scope_name IN ARRAY ARRAY['stage',p_namespace] LOOP
    SELECT p.policy INTO policy FROM mem9_maintenance.budget_policies p WHERE p.scope=scope_name FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='execution budget missing'; END IF;
    PERFORM scope FROM mem9_maintenance.apply_admission WHERE scope=scope_name FOR UPDATE;
    IF NOT EXISTS(SELECT FROM mem9_maintenance.budget_windows WHERE scope=scope_name AND day=d) THEN
      n:=0;
      IF scope_name<>'stage' THEN SELECT count(*) INTO n FROM public.memories WHERE namespace_id=p_namespace AND state='active' AND memory_type='insight'; END IF;
      limits:='{}';
      FOREACH k IN ARRAY ARRAY['total','rewrite','delete','archive','mark'] LOOP
        lim:=(policy->'limits'->>k)::bigint;
        IF scope_name<>'stage' THEN lim:=least(lim,ceil(n*(policy->'bps'->>k)::numeric/10000)::bigint); END IF;
        limits:=limits||jsonb_build_object(k,lim);
      END LOOP;
      INSERT INTO mem9_maintenance.budget_windows(scope,day,active_count,limits) VALUES(scope_name,d,n,limits);
    END IF;
    PERFORM scope FROM mem9_maintenance.budget_windows WHERE scope=scope_name AND day=d FOR UPDATE;
  END LOOP;
  RETURN d;
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.affords(p_namespace TEXT,p_day DATE,p_cost JSONB,p_empty BOOLEAN DEFAULT FALSE) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE scope_name TEXT; w mem9_maintenance.budget_windows; policy JSONB; k TEXT; lim BIGINT;
BEGIN
  FOREACH scope_name IN ARRAY ARRAY['stage',p_namespace] LOOP
    SELECT * INTO w FROM mem9_maintenance.budget_windows WHERE scope=scope_name AND day=p_day;
    SELECT p.policy INTO policy FROM mem9_maintenance.budget_policies p WHERE p.scope=scope_name;
    IF p_empty AND (p_cost->>'total')::bigint>(policy->>'burst')::numeric THEN RETURN FALSE; END IF;
    FOREACH k IN ARRAY ARRAY['total','rewrite','delete','archive','mark'] LOOP
      lim:=least((w.limits->>k)::bigint,(policy->'limits'->>k)::bigint);
      IF scope_name<>'stage' THEN lim:=least(lim,ceil(w.active_count*(policy->'bps'->>k)::numeric/10000)::bigint); END IF;
      IF (p_cost->>k)::bigint+(CASE WHEN p_empty THEN 0 ELSE (w.used->>k)::bigint+(w.reserved->>k)::bigint END)>lim THEN RETURN FALSE; END IF;
    END LOOP;
  END LOOP;
  RETURN TRUE;
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.release_action(p_namespace TEXT,p_id TEXT,p_status TEXT,p_reason TEXT) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s mem9_maintenance.action_state; scope_name TEXT;
BEGIN
  SELECT * INTO s FROM mem9_maintenance.action_state WHERE namespace_id=p_namespace AND action_id=p_id FOR UPDATE;
  IF s.reservation IS NOT NULL THEN
    FOREACH scope_name IN ARRAY ARRAY['stage',p_namespace] LOOP
      UPDATE mem9_maintenance.budget_windows SET reserved=mem9_maintenance.cost_add(reserved,s.reservation,-1)
        WHERE scope=scope_name AND day=s.budget_day;
    END LOOP;
  END IF;
  UPDATE mem9_maintenance.action_state SET status=p_status,reason=p_reason,reservation=NULL,lease_until=NULL,
    generation=generation+1,next_at=mem9_maintenance.execution_time()+interval '5 seconds'
    WHERE namespace_id=p_namespace AND action_id=p_id;
  UPDATE mem9_maintenance.preparations SET status='abandoned' WHERE namespace_id=p_namespace AND action_id=p_id AND status='preparing';
END $$;
-- Administrative metadata reconciliation under the stage control lock. It
-- visits no memory/plan payload and reveals no foreign namespace identifiers.
-- This releases expired capacity even when its original service was revoked.
CREATE OR REPLACE FUNCTION mem9_maintenance.reap_reservations() RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s RECORD;
BEGIN
  FOR s IN SELECT namespace_id,action_id,attempts FROM mem9_maintenance.action_state
    WHERE reservation IS NOT NULL AND lease_until<=mem9_maintenance.execution_time()
    ORDER BY namespace_id,action_id LIMIT 1000 FOR UPDATE LOOP
    PERFORM mem9_maintenance.release_action(s.namespace_id,s.action_id,CASE WHEN s.attempts>=3 THEN 'review' ELSE 'queued' END,'lease_expired');
  END LOOP;
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.claim_action(p_namespace TEXT,p_seconds INTEGER DEFAULT 120,p_max_rows INTEGER DEFAULT 100) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a RECORD; d DATE; observed TIMESTAMPTZ; scope_name TEXT; c mem9_maintenance.execution_control; generation BIGINT; scanned INTEGER:=0;
BEGIN
  PERFORM mem9_maintenance.execution_guard(p_namespace,'executor');
  IF p_seconds IS NULL OR p_seconds NOT BETWEEN 1 AND 300 OR p_max_rows IS NULL OR p_max_rows NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid execution lease or batch'; END IF;
  PERFORM mem9_maintenance.reap_reservations();
  d:=mem9_maintenance.open_windows(p_namespace);
  SELECT * INTO c FROM mem9_maintenance.execution_control WHERE singleton;
  FOR a IN SELECT proposal.*,s.attempts FROM mem9_maintenance.action_state s JOIN mem9_maintenance.actions proposal USING(namespace_id,action_id)
    WHERE s.namespace_id=p_namespace AND s.status='queued' AND s.next_at<=mem9_maintenance.execution_time() AND (proposal.cost->>'total')::int<=p_max_rows
    ORDER BY s.first_seen_at,s.action_id LIMIT 100 FOR UPDATE OF s SKIP LOCKED LOOP
    scanned:=scanned+1;
    IF NOT mem9_maintenance.affords(p_namespace,d,a.cost,TRUE) THEN
      UPDATE mem9_maintenance.action_state SET status='policy_blocked',reason='empty_window_limit' WHERE namespace_id=p_namespace AND action_id=a.action_id;
      CONTINUE;
    END IF;
    IF NOT mem9_maintenance.affords(p_namespace,d,a.cost) THEN
      UPDATE mem9_maintenance.action_state SET reason='budget_wait',next_at=least((d+1)::timestamp AT TIME ZONE 'UTC',mem9_maintenance.execution_time()+interval '5 seconds') WHERE namespace_id=p_namespace AND action_id=a.action_id;
      CONTINUE;
    END IF;
    observed:=mem9_maintenance.execution_time();
    IF (observed AT TIME ZONE 'UTC')::date<>d THEN RETURN jsonb_build_object('status','window_changed'); END IF;
    FOREACH scope_name IN ARRAY ARRAY['stage',p_namespace] LOOP
      UPDATE mem9_maintenance.budget_windows SET reserved=mem9_maintenance.cost_add(reserved,a.cost) WHERE scope=scope_name AND day=d;
    END LOOP;
    UPDATE mem9_maintenance.action_state s SET status='leased',reason='',generation=s.generation+1,attempts=s.attempts+1,
      lease_until=least(observed+make_interval(secs=>p_seconds),(d+1)::timestamp AT TIME ZONE 'UTC'),budget_day=d,reservation=a.cost,
      control_epoch=c.epoch,stage_epoch=(SELECT epoch FROM mem9_maintenance.budget_policies WHERE scope='stage'),
      namespace_epoch=(SELECT epoch FROM mem9_maintenance.budget_policies WHERE scope=p_namespace)
      WHERE s.namespace_id=p_namespace AND s.action_id=a.action_id RETURNING s.generation INTO generation;
    RETURN jsonb_build_object('status','leased','action_id',a.action_id,'lease_generation',generation,'reserved_rows',a.cost->'total');
  END LOOP;
  IF scanned=100 THEN RETURN jsonb_build_object('status','scan_more'); END IF;
  IF EXISTS(SELECT FROM mem9_maintenance.action_state WHERE namespace_id=p_namespace AND status='queued' AND reason='budget_wait') THEN
    RETURN jsonb_build_object('status','budget_wait'); END IF;
  IF EXISTS(SELECT FROM mem9_maintenance.action_state WHERE namespace_id=p_namespace AND status='policy_blocked') THEN
    RETURN jsonb_build_object('status','policy_blocked'); END IF;
  RETURN jsonb_build_object('status','idle');
END $$;

CREATE OR REPLACE FUNCTION mem9_maintenance.execution_valid(p_namespace TEXT,p_id TEXT,p_generation BIGINT) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE s mem9_maintenance.action_state; c mem9_maintenance.execution_control;
BEGIN
  SELECT * INTO s FROM mem9_maintenance.action_state WHERE namespace_id=p_namespace AND action_id=p_id;
  SELECT * INTO c FROM mem9_maintenance.execution_control WHERE singleton;
  RETURN coalesce(s.generation=p_generation AND s.reservation IS NOT NULL AND s.lease_until>mem9_maintenance.execution_time()
    AND s.budget_day=(mem9_maintenance.execution_time() AT TIME ZONE 'UTC')::date AND s.control_epoch=c.epoch
    AND s.stage_epoch=(SELECT epoch FROM mem9_maintenance.budget_policies WHERE scope='stage')
    AND s.namespace_epoch=(SELECT epoch FROM mem9_maintenance.budget_policies WHERE scope=p_namespace),FALSE);
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.action_inputs_valid(p_namespace TEXT,p_id TEXT) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE a mem9_maintenance.actions; saved JSONB; current_row JSONB;
BEGIN
  SELECT * INTO a FROM mem9_maintenance.actions WHERE namespace_id=p_namespace AND action_id=p_id;
  IF NOT FOUND OR a.context_hash IS DISTINCT FROM (SELECT context_hash FROM mem9_maintenance.namespace_state WHERE namespace_id=p_namespace AND capture_enabled)
    OR EXISTS(SELECT FROM mem9_maintenance.suppressions WHERE namespace_id=p_namespace AND semantic_hash=a.semantic_hash)
    OR NOT EXISTS(SELECT FROM mem9_maintenance.classifications WHERE namespace_id=p_namespace AND classification_id=a.classification_id AND valid_until>mem9_maintenance.execution_time()) THEN RETURN FALSE; END IF;
  FOR saved IN SELECT value FROM jsonb_array_elements(a.members) ORDER BY value->>'id' LOOP
    SELECT to_jsonb(m) INTO current_row FROM public.memories m WHERE m.namespace_id=p_namespace AND m.id=saved->>'id' FOR SHARE;
    IF NOT FOUND OR current_row IS DISTINCT FROM saved THEN RETURN FALSE; END IF;
  END LOOP;
  RETURN TRUE;
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.action_status(p_namespace TEXT,p_id TEXT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE result JSONB;
BEGIN
  PERFORM mem9_maintenance.authorize(p_namespace);
  SELECT r.result INTO result FROM mem9_maintenance.receipts r WHERE namespace_id=p_namespace AND action_id=p_id;
  IF FOUND THEN RETURN result; END IF;
  SELECT jsonb_build_object('action_id',action_id,'status',status,'reason',reason,'lease_generation',generation) INTO result
    FROM mem9_maintenance.action_state WHERE namespace_id=p_namespace AND action_id=p_id;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='action not found'; END IF;
  RETURN result;
END $$;

CREATE OR REPLACE FUNCTION mem9_maintenance.prepare_action(p_namespace TEXT,p_id TEXT,p_generation BIGINT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a mem9_maintenance.actions; existing mem9_maintenance.preparations; token UUID; hash TEXT; model TEXT; cached public.vector(1024); receipt JSONB;
BEGIN
  PERFORM mem9_maintenance.authorize(p_namespace,'backend');
  SELECT result INTO receipt FROM mem9_maintenance.receipts WHERE namespace_id=p_namespace AND action_id=p_id;
  IF FOUND THEN RETURN receipt; END IF;
  PERFORM mem9_maintenance.execution_guard(p_namespace,'backend');
  PERFORM mem9_maintenance.open_windows(p_namespace);
  PERFORM action_id FROM mem9_maintenance.action_state WHERE namespace_id=p_namespace AND action_id=p_id FOR UPDATE;
  IF NOT mem9_maintenance.execution_valid(p_namespace,p_id,p_generation) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='execution lease invalid'; END IF;
  IF NOT mem9_maintenance.action_inputs_valid(p_namespace,p_id) THEN
    PERFORM mem9_maintenance.release_action(p_namespace,p_id,'invalidated','member_or_context_changed');
    RETURN jsonb_build_object('status','invalidated'); END IF;
  SELECT * INTO a FROM mem9_maintenance.actions WHERE namespace_id=p_namespace AND action_id=p_id;
  SELECT embedding_model INTO model FROM mem9_maintenance.execution_control WHERE singleton;
  SELECT * INTO existing FROM mem9_maintenance.preparations WHERE namespace_id=p_namespace AND action_id=p_id AND generation=p_generation;
  IF FOUND THEN RETURN jsonb_build_object('status',CASE existing.status WHEN 'ready' THEN 'ready' ELSE 'in_progress' END); END IF;
  hash:=encode(sha256(convert_to(coalesce(a.output->>'content',''),'UTF8')),'hex');
  SELECT p.embedding INTO cached FROM mem9_maintenance.preparations p WHERE p.namespace_id=p_namespace AND p.action_id=p_id
    AND p.content_hash=hash AND p.embedding_model=model AND p.embedding IS NOT NULL ORDER BY p.generation DESC LIMIT 1;
  token:=gen_random_uuid();
  INSERT INTO mem9_maintenance.preparations VALUES(p_namespace,p_id,p_generation,token,
    CASE WHEN cached IS NOT NULL OR (a.cost->>'rewrite')::int=0 THEN 'ready' ELSE 'preparing' END,hash,model,cached);
  UPDATE mem9_maintenance.action_state SET status=CASE WHEN cached IS NOT NULL OR (a.cost->>'rewrite')::int=0 THEN 'ready' ELSE 'preparing' END
    WHERE namespace_id=p_namespace AND action_id=p_id;
  IF cached IS NOT NULL OR (a.cost->>'rewrite')::int=0 THEN RETURN jsonb_build_object('status','ready'); END IF;
  RETURN jsonb_build_object('status','embed','owner_token',token,'content',a.output->>'content','content_hash',hash,'embedding_model',model);
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.finish_preparation(p_namespace TEXT,p_id TEXT,p_generation BIGINT,p_token UUID,p_hash TEXT,p_vector public.vector)
RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  PERFORM mem9_maintenance.execution_guard(p_namespace,'backend');
  PERFORM mem9_maintenance.open_windows(p_namespace);
  PERFORM action_id FROM mem9_maintenance.action_state WHERE namespace_id=p_namespace AND action_id=p_id FOR UPDATE;
  IF NOT mem9_maintenance.execution_valid(p_namespace,p_id,p_generation) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='execution lease invalid'; END IF;
  IF p_vector IS NULL OR public.vector_dims(p_vector)<>1024 OR (p_vector OPERATOR(public.<#>) p_vector) NOT BETWEEN -1.01 AND -0.99 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid maintenance embedding'; END IF;
  UPDATE mem9_maintenance.preparations SET embedding=p_vector,status='ready'
    WHERE namespace_id=p_namespace AND action_id=p_id AND generation=p_generation AND owner_token=p_token AND content_hash=p_hash AND status='preparing';
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='preparation ownership changed'; END IF;
  UPDATE mem9_maintenance.action_state SET status='ready' WHERE namespace_id=p_namespace AND action_id=p_id;
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.abandon_preparation(p_namespace TEXT,p_id TEXT,p_generation BIGINT,p_token UUID) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE attempts INTEGER;
BEGIN
  PERFORM mem9_maintenance.execution_guard(p_namespace,'backend',FALSE);
  PERFORM action_id FROM mem9_maintenance.action_state WHERE namespace_id=p_namespace AND action_id=p_id AND generation=p_generation FOR UPDATE;
  IF NOT FOUND OR EXISTS(SELECT FROM mem9_maintenance.receipts WHERE namespace_id=p_namespace AND action_id=p_id) THEN RETURN; END IF;
  IF NOT EXISTS(SELECT FROM mem9_maintenance.preparations WHERE namespace_id=p_namespace AND action_id=p_id AND generation=p_generation AND owner_token=p_token) THEN RETURN; END IF;
  SELECT s.attempts INTO attempts FROM mem9_maintenance.action_state s WHERE namespace_id=p_namespace AND action_id=p_id;
  PERFORM mem9_maintenance.release_action(p_namespace,p_id,CASE WHEN attempts>=3 THEN 'review' ELSE 'queued' END,'preparation_failed');
END $$;

CREATE OR REPLACE FUNCTION mem9_maintenance.take_apply_rate(p_namespace TEXT,p_rows INTEGER) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE scope_name TEXT; policy JSONB; a mem9_maintenance.apply_admission; now_time TIMESTAMPTZ; available NUMERIC;
BEGIN
  now_time:=mem9_maintenance.execution_time();
  FOREACH scope_name IN ARRAY ARRAY['stage',p_namespace] LOOP
    SELECT p.policy INTO policy FROM mem9_maintenance.budget_policies p WHERE p.scope=scope_name;
    SELECT * INTO a FROM mem9_maintenance.apply_admission WHERE scope=scope_name FOR UPDATE;
    available:=least((policy->>'burst')::numeric,a.tokens+greatest(0,extract(epoch FROM now_time-a.refilled_at))*(policy->>'rate')::numeric);
    IF available<p_rows THEN RETURN FALSE; END IF;
  END LOOP;
  FOREACH scope_name IN ARRAY ARRAY['stage',p_namespace] LOOP
    SELECT p.policy INTO policy FROM mem9_maintenance.budget_policies p WHERE p.scope=scope_name;
    UPDATE mem9_maintenance.apply_admission SET tokens=least((policy->>'burst')::numeric,
      tokens+greatest(0,extract(epoch FROM now_time-refilled_at))*(policy->>'rate')::numeric)-p_rows,refilled_at=now_time WHERE scope=scope_name;
  END LOOP;
  RETURN TRUE;
END $$;

CREATE OR REPLACE FUNCTION mem9_maintenance.apply_action(p_namespace TEXT,p_id TEXT,p_generation BIGINT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE a mem9_maintenance.actions; s mem9_maintenance.action_state; prep mem9_maintenance.preparations; c mem9_maintenance.execution_control;
  saved JSONB; actual JSONB:='{"total":0,"rewrite":0,"delete":0,"archive":0,"mark":0}'; before_rows JSONB:='[]'; after_rows JSONB:='[]'; current_row JSONB;
  actor TEXT; result JSONB; scope_name TEXT; changed INTEGER; target TEXT;
BEGIN
  PERFORM mem9_maintenance.authorize(p_namespace,'backend');
  SELECT r.result INTO result FROM mem9_maintenance.receipts r WHERE namespace_id=p_namespace AND action_id=p_id;
  IF FOUND THEN RETURN result; END IF;
  PERFORM mem9_maintenance.execution_guard(p_namespace,'backend');
  SELECT * INTO c FROM mem9_maintenance.execution_control WHERE singleton;
  IF NOT pg_try_advisory_xact_lock(hashtextextended('mem9-cleanup:'||c.stage||':'||p_namespace,0)) THEN RETURN jsonb_build_object('status','mutex_busy'); END IF;
  PERFORM mem9_maintenance.open_windows(p_namespace);
  SELECT * INTO s FROM mem9_maintenance.action_state WHERE namespace_id=p_namespace AND action_id=p_id FOR UPDATE;
  IF NOT FOUND OR NOT mem9_maintenance.execution_valid(p_namespace,p_id,p_generation) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='execution lease invalid'; END IF;
  SELECT * INTO a FROM mem9_maintenance.actions WHERE namespace_id=p_namespace AND action_id=p_id;
  SELECT * INTO prep FROM mem9_maintenance.preparations WHERE namespace_id=p_namespace AND action_id=p_id AND generation=p_generation;
  IF NOT FOUND OR prep.status<>'ready' OR prep.embedding_model<>c.embedding_model THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='preparation not ready'; END IF;
  FOR saved IN SELECT value FROM jsonb_array_elements(a.members) ORDER BY value->>'id' LOOP
    SELECT to_jsonb(m) INTO current_row FROM public.memories m WHERE m.namespace_id=p_namespace AND m.id=saved->>'id' FOR UPDATE;
    IF NOT FOUND OR current_row IS DISTINCT FROM saved THEN
      PERFORM mem9_maintenance.release_action(p_namespace,p_id,'invalidated','member_changed'); RETURN jsonb_build_object('status','invalidated'); END IF;
    before_rows:=before_rows||jsonb_build_array(current_row);
  END LOOP;
  IF NOT mem9_maintenance.action_inputs_valid(p_namespace,p_id) THEN
    PERFORM mem9_maintenance.release_action(p_namespace,p_id,'invalidated','context_changed'); RETURN jsonb_build_object('status','invalidated'); END IF;
  IF NOT mem9_maintenance.execution_valid(p_namespace,p_id,p_generation) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='execution authorization expired'; END IF;
  IF NOT mem9_maintenance.take_apply_rate(p_namespace,(a.cost->>'total')::int) THEN RETURN jsonb_build_object('status','rate_wait'); END IF;
  SELECT principal_id INTO actor FROM public.memory_principals WHERE principal_key=
    encode(sha256(convert_to('mem9-service-principal-v1','UTF8')||decode('00','hex')||convert_to('consolidation','UTF8')),'hex');
  target:=a.output->>'target';
  IF a.kind='MERGE' THEN
    UPDATE public.memories SET content=a.output->>'content',tags=a.output->'tags',metadata=a.output->'metadata',
      embedding=CASE WHEN (a.cost->>'rewrite')::int>0 THEN prep.embedding ELSE embedding END,
      version=version+1,updated_by_principal_id=actor WHERE namespace_id=p_namespace AND id=target;
    UPDATE public.memories SET state='deleted',superseded_by=target,version=version+1,updated_by_principal_id=actor
      WHERE namespace_id=p_namespace AND id IN(SELECT value->>'id' FROM jsonb_array_elements(a.members)) AND id<>target;
    actual:=a.cost;
  ELSIF a.kind='ARCHIVE' THEN
    UPDATE public.memories SET state='archived',superseded_by=target,version=version+1,updated_by_principal_id=actor
      WHERE namespace_id=p_namespace AND id IN(SELECT value->>'id' FROM jsonb_array_elements(a.members)) AND id<>target;
    actual:=a.cost;
  ELSE
    UPDATE public.memories SET tags=CASE WHEN coalesce(nullif(tags,'null'),'[]')?'stale' THEN tags ELSE coalesce(nullif(tags,'null'),'[]')||'"stale"'::jsonb END,
      metadata=jsonb_set(coalesce(nullif(metadata,'null'),'{}'),'{consolidation}',coalesce(nullif(metadata->'consolidation','null'),'{}')||'{"stale":true}',TRUE),
      version=version+1,updated_by_principal_id=actor
      WHERE namespace_id=p_namespace AND id=target AND (NOT coalesce(tags,'[]')?'stale' OR metadata->'consolidation'->>'stale' IS DISTINCT FROM 'true');
    GET DIAGNOSTICS changed=ROW_COUNT;
    IF changed=1 THEN actual:=a.cost; END IF;
  END IF;
  SELECT jsonb_agg(to_jsonb(m) ORDER BY m.id) INTO after_rows FROM public.memories m WHERE m.namespace_id=p_namespace AND m.id IN(SELECT value->>'id' FROM jsonb_array_elements(a.members));
  FOREACH scope_name IN ARRAY ARRAY['stage',p_namespace] LOOP
    UPDATE mem9_maintenance.budget_windows SET used=mem9_maintenance.cost_add(used,actual),reserved=mem9_maintenance.cost_add(reserved,s.reservation,-1)
      WHERE scope=scope_name AND day=s.budget_day;
  END LOOP;
  result:=jsonb_build_object('action_id',p_id,'status',CASE WHEN (actual->>'total')::int=0 THEN 'noop' ELSE 'applied' END,'changed_rows',actual->'total','cost',actual);
  INSERT INTO mem9_maintenance.receipts(namespace_id,action_id,result,before_images,post_images) VALUES(p_namespace,p_id,result,before_rows,after_rows);
  UPDATE mem9_maintenance.action_state SET status=result->>'status',reason='',reservation=NULL,lease_until=NULL WHERE namespace_id=p_namespace AND action_id=p_id;
  RETURN result;
END $$;

CREATE OR REPLACE FUNCTION mem9_maintenance.undo_action(p_namespace TEXT,p_id TEXT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE r mem9_maintenance.receipts; row_value JSONB; current_row JSONB; before_row public.memories; actor TEXT; restored INTEGER:=0; c mem9_maintenance.execution_control;
BEGIN
  PERFORM mem9_maintenance.execution_guard(p_namespace,'operator',FALSE);
  IF EXISTS(SELECT FROM mem9_maintenance.undo_receipts WHERE namespace_id=p_namespace AND action_id=p_id) THEN RETURN jsonb_build_object('status','already_undone'); END IF;
  SELECT * INTO c FROM mem9_maintenance.execution_control WHERE singleton;
  IF NOT pg_try_advisory_xact_lock(hashtextextended('mem9-cleanup:'||c.stage||':'||p_namespace,0)) THEN RETURN jsonb_build_object('status','mutex_busy'); END IF;
  SELECT * INTO r FROM mem9_maintenance.receipts WHERE namespace_id=p_namespace AND action_id=p_id;
  IF NOT FOUND OR r.committed_at<mem9_maintenance.execution_time()-interval '30 days' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='undo unavailable'; END IF;
  FOR row_value IN SELECT value FROM jsonb_array_elements(r.post_images) ORDER BY value->>'id' LOOP
    SELECT to_jsonb(m) INTO current_row FROM public.memories m WHERE m.namespace_id=p_namespace AND m.id=row_value->>'id' FOR UPDATE;
    IF NOT FOUND OR current_row IS DISTINCT FROM row_value THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='undo post-image changed'; END IF;
  END LOOP;
  SELECT o.principal_id INTO actor FROM mem9_maintenance.operator_principals o JOIN pg_roles p ON p.oid=o.role_oid WHERE p.rolname=session_user;
  FOR row_value IN SELECT value FROM jsonb_array_elements(r.before_images) LOOP
    IF row_value=(SELECT value FROM jsonb_array_elements(r.post_images) p WHERE p.value->>'id'=row_value->>'id') THEN CONTINUE; END IF;
    before_row:=jsonb_populate_record(NULL::public.memories,row_value);
    UPDATE public.memories SET content=before_row.content,source=before_row.source,tags=before_row.tags,metadata=before_row.metadata,
      embedding=before_row.embedding,memory_type=before_row.memory_type,agent_id=before_row.agent_id,session_id=before_row.session_id,
      app_id=before_row.app_id,state=before_row.state,superseded_by=before_row.superseded_by,created_at=before_row.created_at,
      created_by_principal_id=before_row.created_by_principal_id,version=version+1,updated_by_principal_id=actor
      WHERE namespace_id=p_namespace AND id=before_row.id;
    restored:=restored+1;
  END LOOP;
  INSERT INTO mem9_maintenance.undo_receipts(namespace_id,action_id,operator_id,restored_rows) VALUES(p_namespace,p_id,actor,restored);
  INSERT INTO mem9_maintenance.suppressions SELECT namespace_id,semantic_hash,kind,
    (SELECT jsonb_agg(mem9_maintenance.semantic_member_hash(m)) FROM jsonb_array_elements(members) m),'undo' FROM mem9_maintenance.actions
    WHERE namespace_id=p_namespace AND action_id=p_id ON CONFLICT DO NOTHING;
  RETURN jsonb_build_object('status','undone','restored_rows',restored);
END $$;

REVOKE ALL ON ALL TABLES IN SCHEMA mem9_maintenance FROM PUBLIC,mem9_maintenance_planner,mem9_maintenance_executor,mem9_maintenance_backend,mem9_maintenance_operator;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA mem9_maintenance FROM PUBLIC,mem9_maintenance_planner,mem9_maintenance_executor,mem9_maintenance_backend,mem9_maintenance_operator;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mem9_maintenance FROM PUBLIC,mem9_maintenance_backend,mem9_maintenance_operator;
GRANT USAGE ON SCHEMA mem9_maintenance TO mem9_maintenance_backend,mem9_maintenance_operator;
GRANT EXECUTE ON FUNCTION mem9_maintenance.queue_classification(TEXT,TEXT) TO mem9_maintenance_planner;
GRANT EXECUTE ON FUNCTION mem9_maintenance.claim_action(TEXT,INTEGER,INTEGER) TO mem9_maintenance_executor;
GRANT EXECUTE ON FUNCTION mem9_maintenance.action_status(TEXT,TEXT) TO mem9_maintenance_executor,mem9_maintenance_backend;
GRANT EXECUTE ON FUNCTION mem9_maintenance.prepare_action(TEXT,TEXT,BIGINT),
  mem9_maintenance.finish_preparation(TEXT,TEXT,BIGINT,UUID,TEXT,public.vector),
  mem9_maintenance.abandon_preparation(TEXT,TEXT,BIGINT,UUID),
  mem9_maintenance.apply_action(TEXT,TEXT,BIGINT) TO mem9_maintenance_backend;
GRANT EXECUTE ON FUNCTION mem9_maintenance.undo_action(TEXT,TEXT) TO mem9_maintenance_operator;
GRANT EXECUTE ON FUNCTION mem9_maintenance.legacy_write_allowed() TO mem9_maintenance_backend;
COMMIT;
