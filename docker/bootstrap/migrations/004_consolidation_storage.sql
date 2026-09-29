-- Additive planning foundation. No automatic memory DML, executable actions,
-- login credentials, or production budget/schedule changes are introduced.
-- Capture is dormant until an operator explicitly configures a namespace.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
SELECT pg_advisory_xact_lock(hashtext('mem9-maintenance-schema-v1'));

CREATE SCHEMA IF NOT EXISTS mem9_maintenance;
REVOKE ALL ON SCHEMA mem9_maintenance FROM PUBLIC;
DO $$
DECLARE role_name TEXT;
BEGIN
  FOREACH role_name IN ARRAY ARRAY['mem9_maintenance_planner','mem9_maintenance_executor'] LOOP
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname=role_name) THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', role_name);
    END IF;
    IF EXISTS (SELECT FROM pg_roles WHERE rolname=role_name AND
      (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) THEN
      RAISE EXCEPTION 'maintenance group role has unexpected privileges';
    END IF;
  END LOOP;
END $$;

CREATE TABLE IF NOT EXISTS mem9_maintenance.database_callers (
  role_oid OID PRIMARY KEY,
  capability TEXT NOT NULL CHECK (capability IN ('planner','executor'))
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.namespace_state (
  namespace_id VARCHAR(36) PRIMARY KEY REFERENCES public.memory_namespaces(namespace_id),
  capture_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  context_hash TEXT NOT NULL CHECK (context_hash ~ '^[0-9a-f]{64}$')
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.changes (
  namespace_id VARCHAR(36) NOT NULL REFERENCES public.memory_namespaces(namespace_id),
  event_id BIGINT GENERATED ALWAYS AS IDENTITY,
  memory_id VARCHAR(36) NOT NULL,
  revision INTEGER,
  kind TEXT NOT NULL CHECK (kind IN ('insert','update','delete')),
  observed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,event_id)
  -- Historical memory ID deliberately has no FK to public.memories.
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.work (
  namespace_id VARCHAR(36) NOT NULL REFERENCES public.memory_namespaces(namespace_id),
  memory_id VARCHAR(36) NOT NULL,
  desired_generation BIGINT NOT NULL DEFAULT 1,
  claimed_generation BIGINT NOT NULL DEFAULT 0,
  completed_generation BIGINT NOT NULL DEFAULT 0,
  lease_generation BIGINT NOT NULL DEFAULT 0,
  lease_until TIMESTAMPTZ,
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
  first_seen_at TIMESTAMPTZ NOT NULL,
  due_at TIMESTAMPTZ NOT NULL,
  reason TEXT NOT NULL CHECK (reason IN ('changed','audit','expired','lease_exhausted')),
  PRIMARY KEY(namespace_id,memory_id),
  CHECK (0 <= completed_generation AND completed_generation <= claimed_generation
    AND claimed_generation <= desired_generation AND desired_generation > 0),
  CHECK (lease_generation >= 0)
);
CREATE INDEX IF NOT EXISTS maintenance_work_ready ON mem9_maintenance.work
  (namespace_id,due_at,first_seen_at,memory_id) WHERE desired_generation>completed_generation;
CREATE TABLE IF NOT EXISTS mem9_maintenance.classifications (
  namespace_id VARCHAR(36) NOT NULL REFERENCES public.memory_namespaces(namespace_id),
  classification_id TEXT NOT NULL CHECK (classification_id ~ '^[0-9a-f]{64}$'),
  input_hash TEXT NOT NULL CHECK (input_hash ~ '^[0-9a-f]{64}$'),
  context_hash TEXT NOT NULL CHECK (context_hash ~ '^[0-9a-f]{64}$'),
  result TEXT NOT NULL CHECK (result IN ('KEEP','REVIEW','MERGE','ARCHIVE','STALE')),
  payload JSONB NOT NULL CHECK (jsonb_typeof(payload)='object' AND octet_length(payload::text)<=262144),
  valid_until TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,classification_id)
);
CREATE INDEX IF NOT EXISTS maintenance_classification_inputs ON mem9_maintenance.classifications
  (namespace_id,input_hash,valid_until DESC);
CREATE TABLE IF NOT EXISTS mem9_maintenance.classification_members (
  namespace_id VARCHAR(36) NOT NULL,
  classification_id TEXT NOT NULL,
  memory_id VARCHAR(36) NOT NULL,
  revision INTEGER NOT NULL CHECK (revision>0),
  fingerprint TEXT NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
  PRIMARY KEY(namespace_id,classification_id,memory_id),
  FOREIGN KEY(namespace_id,classification_id)
    REFERENCES mem9_maintenance.classifications(namespace_id,classification_id)
);
CREATE INDEX IF NOT EXISTS maintenance_classification_members_lookup
  ON mem9_maintenance.classification_members(namespace_id,memory_id,classification_id);
CREATE TABLE IF NOT EXISTS mem9_maintenance.publications (
  namespace_id VARCHAR(36) NOT NULL,
  memory_id VARCHAR(36) NOT NULL,
  lease_generation BIGINT NOT NULL,
  classification_id TEXT NOT NULL,
  PRIMARY KEY(namespace_id,memory_id,lease_generation),
  FOREIGN KEY(namespace_id,classification_id)
    REFERENCES mem9_maintenance.classifications(namespace_id,classification_id)
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.expiries (
  namespace_id VARCHAR(36) NOT NULL,
  classification_id TEXT NOT NULL,
  memory_id VARCHAR(36) NOT NULL,
  due_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY(namespace_id,classification_id,memory_id),
  FOREIGN KEY(namespace_id,classification_id)
    REFERENCES mem9_maintenance.classifications(namespace_id,classification_id)
);
CREATE INDEX IF NOT EXISTS maintenance_expiries_due ON mem9_maintenance.expiries(namespace_id,due_at);

CREATE OR REPLACE FUNCTION mem9_maintenance.immutable() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='maintenance result is immutable';
END $$;
DROP TRIGGER IF EXISTS maintenance_immutable ON mem9_maintenance.classifications;
CREATE TRIGGER maintenance_immutable BEFORE UPDATE OR DELETE ON mem9_maintenance.classifications
  FOR EACH ROW EXECUTE FUNCTION mem9_maintenance.immutable();
DROP TRIGGER IF EXISTS maintenance_immutable ON mem9_maintenance.classification_members;
CREATE TRIGGER maintenance_immutable BEFORE UPDATE OR DELETE ON mem9_maintenance.classification_members
  FOR EACH ROW EXECUTE FUNCTION mem9_maintenance.immutable();
DROP TRIGGER IF EXISTS maintenance_immutable ON mem9_maintenance.publications;
CREATE TRIGGER maintenance_immutable BEFORE UPDATE OR DELETE ON mem9_maintenance.publications
  FOR EACH ROW EXECUTE FUNCTION mem9_maintenance.immutable();

CREATE OR REPLACE FUNCTION mem9_maintenance.capture_change() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  IF TG_OP='DELETE' OR (TG_OP='UPDATE' AND
    (OLD.namespace_id IS DISTINCT FROM NEW.namespace_id OR OLD.id IS DISTINCT FROM NEW.id)) THEN
    INSERT INTO mem9_maintenance.changes(namespace_id,memory_id,revision,kind)
      SELECT OLD.namespace_id,OLD.id,OLD.version,'delete'
      FROM mem9_maintenance.namespace_state s WHERE s.namespace_id=OLD.namespace_id AND s.capture_enabled;
  END IF;
  IF TG_OP<>'DELETE' THEN
    INSERT INTO mem9_maintenance.changes(namespace_id,memory_id,revision,kind)
      SELECT NEW.namespace_id,NEW.id,NEW.version,
        CASE WHEN TG_OP='INSERT' OR OLD.namespace_id IS DISTINCT FROM NEW.namespace_id
          OR OLD.id IS DISTINCT FROM NEW.id THEN 'insert' ELSE 'update' END
      FROM mem9_maintenance.namespace_state s WHERE s.namespace_id=NEW.namespace_id AND s.capture_enabled;
  END IF;
  RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS trg_memories_maintenance_capture ON public.memories;
CREATE TRIGGER trg_memories_maintenance_capture AFTER INSERT OR UPDATE OR DELETE ON public.memories
  FOR EACH ROW EXECUTE FUNCTION mem9_maintenance.capture_change();

-- Internal functions have no worker grants. Authorization uses authenticated
-- session_user (never current_user inside SECURITY DEFINER, SET ROLE, a GUC,
-- application_name, or a supplied principal). Group membership and the private
-- login-OID binding must both match. Namespace revocation waits for these locks.
CREATE OR REPLACE FUNCTION mem9_maintenance.authorize(p_namespace TEXT,p_capability TEXT DEFAULT NULL)
RETURNS TEXT LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE capability TEXT; actor TEXT; service TEXT; actor_key TEXT; member_role TEXT; source_kind TEXT;
BEGIN
  SELECT c.capability INTO capability FROM mem9_maintenance.database_callers c JOIN pg_roles r ON r.oid=c.role_oid WHERE r.rolname=session_user;
  IF capability IS NULL OR (p_capability IS NOT NULL AND capability<>p_capability) OR
    NOT pg_has_role(session_user,('mem9_maintenance_'||capability)::name,'USAGE') THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='maintenance caller denied'; END IF;
  IF NOT EXISTS(SELECT FROM public.memory_namespace_migration_state WHERE singleton_id AND phase='constraints_complete') THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='maintenance requires namespace enforcement'; END IF;
  PERFORM namespace_id FROM public.memory_namespaces WHERE namespace_id=p_namespace AND status='active' FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='maintenance namespace denied'; END IF;
  IF capability='operator' THEN
    SELECT o.principal_id INTO actor FROM mem9_maintenance.operator_principals o JOIN pg_roles r ON r.oid=o.role_oid WHERE r.rolname=session_user;
    PERFORM principal_id FROM public.memory_principals WHERE principal_id=actor AND status='active' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='maintenance operator denied'; END IF;
  ELSE
    service:=CASE capability WHEN 'planner' THEN 'consolidation-planner' ELSE 'consolidation' END;
    actor_key:=encode(sha256(convert_to('mem9-service-principal-v1','UTF8')||decode('00','hex')||convert_to(service,'UTF8')),'hex');
    SELECT principal_id INTO actor FROM public.memory_principals WHERE principal_key=actor_key AND principal_type='service' AND status='active' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='maintenance service denied'; END IF;
  END IF;
  SELECT role,source_type INTO member_role,source_kind FROM public.memory_namespace_memberships
    WHERE namespace_id=p_namespace AND principal_id=actor AND status='active' FOR SHARE;
  IF member_role IS NULL OR (capability='operator' AND member_role<>'owner') OR
    (capability<>'operator' AND source_kind<>'service') OR
    (capability IN ('executor','backend') AND member_role NOT IN ('member','owner')) THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='maintenance membership denied'; END IF;
  RETURN capability;
END $$;

-- Planning operations have one short namespace queue mutex after authorization.
-- This orders changes/work/expiry/publication locks consistently. It is never
-- held across a model call; independent namespaces remain concurrent. Configure
-- takes the same mutex before its bounded memory-table bootstrap lock.
CREATE OR REPLACE FUNCTION mem9_maintenance.lock_queue(p_namespace TEXT) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('mem9-maintenance-planning-v1'),hashtext(p_namespace));
  IF NOT EXISTS (SELECT FROM mem9_maintenance.namespace_state WHERE namespace_id=p_namespace AND capture_enabled) THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='maintenance planning disabled';
  END IF;
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.dirty(p_namespace TEXT,p_id TEXT,p_seen TIMESTAMPTZ,p_reason TEXT)
RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  INSERT INTO mem9_maintenance.work AS w(namespace_id,memory_id,first_seen_at,due_at,reason)
    VALUES(p_namespace,p_id,p_seen,clock_timestamp(),p_reason)
  ON CONFLICT(namespace_id,memory_id) DO UPDATE SET
    desired_generation=w.desired_generation+1,
    first_seen_at=CASE WHEN w.desired_generation=w.completed_generation THEN EXCLUDED.first_seen_at
      ELSE least(w.first_seen_at,EXCLUDED.first_seen_at) END,
    due_at=least(w.due_at,EXCLUDED.due_at),
    attempts=CASE WHEN w.desired_generation=w.completed_generation THEN 0 ELSE w.attempts END,
    reason=CASE WHEN w.attempts=3 AND w.desired_generation>w.completed_generation THEN w.reason ELSE EXCLUDED.reason END;
END $$;

-- Owner-only explicit opt-in/context invalidation. The table lock drains
-- in-flight writers before seeding the baseline and switching capture, so an
-- earlier unobserved transaction cannot commit behind the baseline snapshot.
-- Repeating unchanged configuration is a no-op and preserves active leases.
CREATE OR REPLACE FUNCTION mem9_maintenance.configure_namespace(p_namespace TEXT,p_context TEXT,p_enabled BOOLEAN)
RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE prior mem9_maintenance.namespace_state; item RECORD;
BEGIN
  IF p_context IS NULL OR p_context !~ '^[0-9a-f]{64}$' OR p_enabled IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid maintenance configuration';
  END IF;
  PERFORM n.namespace_id FROM public.memory_namespaces n WHERE n.namespace_id=p_namespace AND n.status='active' FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='maintenance namespace denied'; END IF;
  PERFORM pg_advisory_xact_lock(hashtext('mem9-maintenance-planning-v1'),hashtext(p_namespace));
  SELECT * INTO prior FROM mem9_maintenance.namespace_state WHERE namespace_id=p_namespace;
  IF prior.context_hash=p_context AND prior.capture_enabled=p_enabled THEN RETURN; END IF;
  LOCK TABLE public.memories IN SHARE ROW EXCLUSIVE MODE;
  INSERT INTO mem9_maintenance.namespace_state(namespace_id,context_hash,capture_enabled)
    VALUES(p_namespace,p_context,p_enabled)
    ON CONFLICT(namespace_id) DO UPDATE SET context_hash=EXCLUDED.context_hash,capture_enabled=EXCLUDED.capture_enabled;
  IF p_enabled THEN
    FOR item IN SELECT m.id FROM public.memories m WHERE m.namespace_id=p_namespace
      AND m.state='active' AND m.memory_type<>'session' ORDER BY m.id LOOP
      PERFORM mem9_maintenance.dirty(p_namespace,item.id,clock_timestamp(),'audit');
    END LOOP;
  END IF;
END $$;

CREATE OR REPLACE FUNCTION mem9_maintenance.consume_changes(p_namespace TEXT,p_limit INTEGER)
RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE event_ids BIGINT[]; item RECORD;
BEGIN
  PERFORM mem9_maintenance.authorize(p_namespace,'planner');
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 1000 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid change batch'; END IF;
  PERFORM mem9_maintenance.lock_queue(p_namespace);
  SELECT array_agg(event_id) INTO event_ids FROM
    (SELECT c.event_id FROM mem9_maintenance.changes c WHERE c.namespace_id=p_namespace
      ORDER BY c.event_id LIMIT p_limit FOR UPDATE SKIP LOCKED) claimed;
  FOR item IN SELECT c.memory_id,min(c.observed_at) AS seen FROM mem9_maintenance.changes c
    WHERE c.namespace_id=p_namespace AND c.event_id=ANY(event_ids) GROUP BY c.memory_id ORDER BY c.memory_id LOOP
    PERFORM mem9_maintenance.dirty(p_namespace,item.memory_id,item.seen,'changed');
  END LOOP;
  DELETE FROM mem9_maintenance.changes WHERE namespace_id=p_namespace AND event_id=ANY(event_ids);
  RETURN coalesce(cardinality(event_ids),0);
END $$;

CREATE OR REPLACE FUNCTION mem9_maintenance.claim_work(p_namespace TEXT,p_limit INTEGER,p_seconds INTEGER)
RETURNS TABLE(memory_id VARCHAR(36),claimed_generation BIGINT,lease_generation BIGINT,lease_until TIMESTAMPTZ)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE item mem9_maintenance.work; observed TIMESTAMPTZ;
BEGIN
  PERFORM mem9_maintenance.authorize(p_namespace,'planner');
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 OR p_seconds IS NULL OR p_seconds NOT BETWEEN 1 AND 300 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid work claim'; END IF;
  PERFORM mem9_maintenance.lock_queue(p_namespace);
  UPDATE mem9_maintenance.work w SET reason='lease_exhausted'
    WHERE w.namespace_id=p_namespace AND w.attempts=3 AND w.desired_generation>w.completed_generation
      AND w.lease_until<=clock_timestamp();
  FOR item IN SELECT w.* FROM mem9_maintenance.work w WHERE w.namespace_id=p_namespace
    AND w.desired_generation>w.completed_generation AND w.attempts<3 AND w.due_at<=clock_timestamp()
    AND (w.lease_until IS NULL OR w.lease_until<=clock_timestamp())
    ORDER BY w.first_seen_at,w.memory_id LIMIT p_limit FOR UPDATE SKIP LOCKED LOOP
    observed := clock_timestamp();
    UPDATE mem9_maintenance.work w SET claimed_generation=w.desired_generation,
      lease_generation=w.lease_generation+1,lease_until=observed+make_interval(secs=>p_seconds),attempts=w.attempts+1
      WHERE w.namespace_id=p_namespace AND w.memory_id=item.memory_id
      RETURNING w.memory_id,w.claimed_generation,w.lease_generation,w.lease_until
      INTO memory_id,claimed_generation,lease_generation,lease_until;
    RETURN NEXT;
  END LOOP;
END $$;

CREATE OR REPLACE FUNCTION mem9_maintenance.read_memories(p_namespace TEXT,p_ids TEXT[])
RETURNS TABLE(memory_id VARCHAR(36),version INTEGER,fingerprint TEXT,memory JSONB)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE payload_bytes BIGINT:=0; item public.memories;
BEGIN
  PERFORM mem9_maintenance.authorize(p_namespace,'planner');
  IF p_ids IS NULL OR cardinality(p_ids) NOT BETWEEN 1 AND 50 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid memory read batch'; END IF;
  PERFORM mem9_maintenance.lock_queue(p_namespace);
  FOR item IN SELECT m.* FROM public.memories m WHERE m.namespace_id=p_namespace AND m.id=ANY(p_ids)
    AND m.state='active' AND m.memory_type<>'session' ORDER BY m.id FOR SHARE LOOP
    memory := to_jsonb(item);
    payload_bytes := payload_bytes+octet_length(memory::text);
    IF payload_bytes>1048576 THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='maintenance input too large'; END IF;
    memory_id := item.id;
    version := item.version;
    fingerprint := encode(sha256(convert_to(memory::text,'UTF8')),'hex');
    RETURN NEXT;
  END LOOP;
END $$;

CREATE OR REPLACE FUNCTION mem9_maintenance.input_fingerprint(p_context TEXT,p_members JSONB,p_absent_anchor TEXT)
RETURNS TEXT LANGUAGE SQL IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
  SELECT encode(sha256(convert_to(jsonb_build_object('context_hash',p_context,'members',p_members)::text ||
    CASE WHEN jsonb_array_length(p_members)=0 THEN '/absent/'||p_absent_anchor ELSE '' END,'UTF8')),'hex');
$$;

CREATE OR REPLACE FUNCTION mem9_maintenance.publish_classification(p_namespace TEXT,p_anchor TEXT,p_lease BIGINT,p_payload JSONB)
RETURNS TEXT LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE work_item mem9_maintenance.work; member JSONB; canonical JSONB; members JSONB;
  stored mem9_maintenance.classifications; receipt TEXT; digest TEXT; input_digest TEXT;
  expected_context TEXT; valid_until TIMESTAMPTZ; current_version INTEGER; current_hash TEXT; observed_time TIMESTAMPTZ;
BEGIN
  PERFORM mem9_maintenance.authorize(p_namespace,'planner');
  IF jsonb_typeof(p_payload) IS DISTINCT FROM 'object' OR octet_length(p_payload::text)>262144 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid classification'; END IF;
  IF (SELECT count(*) FROM jsonb_object_keys(p_payload))<>5 OR
    NOT p_payload ?& ARRAY['context_hash','result','members','valid_until','details'] OR
    p_payload->>'result' NOT IN ('KEEP','REVIEW','MERGE','ARCHIVE','STALE') OR p_payload->>'result' IS NULL OR
    jsonb_typeof(p_payload->'details') IS DISTINCT FROM 'object' OR
    jsonb_typeof(p_payload->'members') IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid classification fields'; END IF;
  IF jsonb_array_length(p_payload->'members')>50 OR
    (p_payload->>'result'='MERGE' AND jsonb_array_length(p_payload->'members') NOT BETWEEN 2 AND 10) THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid classification members'; END IF;
  SELECT coalesce(jsonb_agg(m ORDER BY m->>'id'),'[]'::jsonb) INTO members FROM jsonb_array_elements(p_payload->'members') m;
  canonical := jsonb_set(p_payload,'{members}',members);
  digest := encode(sha256(convert_to(canonical::text ||
    CASE WHEN jsonb_array_length(members)=0 THEN '/absent/'||p_anchor ELSE '' END,'UTF8')),'hex');
  PERFORM mem9_maintenance.lock_queue(p_namespace);
  SELECT p.classification_id INTO receipt FROM mem9_maintenance.publications p
    WHERE p.namespace_id=p_namespace AND p.memory_id=p_anchor AND p.lease_generation=p_lease;
  IF FOUND THEN
    IF receipt<>digest THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='conflicting publication retry'; END IF;
    RETURN receipt;
  END IF;
  SELECT * INTO work_item FROM mem9_maintenance.work w WHERE w.namespace_id=p_namespace AND w.memory_id=p_anchor FOR UPDATE;
  observed_time := clock_timestamp();
  IF NOT FOUND OR p_lease IS NULL OR work_item.lease_generation<>p_lease OR work_item.lease_until IS NULL OR work_item.lease_until<=observed_time THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='stale planning lease'; END IF;
  SELECT context_hash INTO expected_context FROM mem9_maintenance.namespace_state WHERE namespace_id=p_namespace;
  IF p_payload->>'context_hash' IS DISTINCT FROM expected_context THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='classification context changed'; END IF;
  valid_until := (p_payload->>'valid_until')::timestamptz;
  IF valid_until IS NULL OR valid_until<=observed_time OR valid_until>observed_time+interval '24 hours' THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid classification validity'; END IF;
  IF (SELECT count(DISTINCT m->>'id') FROM jsonb_array_elements(members) m)<>jsonb_array_length(members) THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='duplicate classification member'; END IF;
  IF jsonb_array_length(members)=0 THEN
    IF p_payload->>'result'<>'KEEP' OR EXISTS (SELECT FROM public.memories m WHERE m.namespace_id=p_namespace
      AND m.id=p_anchor AND m.state='active' AND m.memory_type<>'session') THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='classification omits active anchor'; END IF;
  ELSIF NOT EXISTS (SELECT FROM jsonb_array_elements(members) m WHERE m->>'id'=p_anchor) THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='classification omits anchor';
  END IF;
  FOR member IN SELECT value FROM jsonb_array_elements(members) LOOP
    IF jsonb_typeof(member) IS DISTINCT FROM 'object' OR
      (SELECT count(*) FROM jsonb_object_keys(member))<>3 OR NOT member ?& ARRAY['id','version','fingerprint'] THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid member snapshot'; END IF;
    IF jsonb_typeof(member->'id') IS DISTINCT FROM 'string' OR
      jsonb_typeof(member->'version') IS DISTINCT FROM 'number' OR
      jsonb_typeof(member->'fingerprint') IS DISTINCT FROM 'string' THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid member field types'; END IF;
    SELECT m.version,encode(sha256(convert_to(to_jsonb(m)::text,'UTF8')),'hex') INTO current_version,current_hash
      FROM public.memories m WHERE m.namespace_id=p_namespace AND m.id=member->>'id'
        AND m.state='active' AND m.memory_type<>'session' FOR SHARE;
    IF NOT FOUND OR member->>'version' IS DISTINCT FROM current_version::text OR member->>'fingerprint' IS DISTINCT FROM current_hash THEN
      RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='classification member changed'; END IF;
  END LOOP;
  -- Recheck advancing wall time after all member locks, not transaction NOW().
  IF work_item.lease_until<=clock_timestamp() OR valid_until<=clock_timestamp() THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='expired planning result'; END IF;
  input_digest := mem9_maintenance.input_fingerprint(expected_context,members,p_anchor);
  SELECT * INTO stored FROM mem9_maintenance.classifications c WHERE c.namespace_id=p_namespace
    AND c.input_hash=input_digest AND c.valid_until>clock_timestamp() ORDER BY c.valid_until DESC LIMIT 1;
  IF FOUND AND stored.classification_id<>digest THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='valid classification already exists'; END IF;
  INSERT INTO mem9_maintenance.classifications(namespace_id,classification_id,input_hash,context_hash,result,payload,valid_until)
    VALUES(p_namespace,digest,input_digest,expected_context,p_payload->>'result',canonical,valid_until)
    ON CONFLICT(namespace_id,classification_id) DO NOTHING;
  FOR member IN SELECT value FROM jsonb_array_elements(members) LOOP
    INSERT INTO mem9_maintenance.classification_members(namespace_id,classification_id,memory_id,revision,fingerprint)
      VALUES(p_namespace,digest,member->>'id',(member->>'version')::integer,member->>'fingerprint') ON CONFLICT DO NOTHING;
  END LOOP;
  INSERT INTO mem9_maintenance.publications VALUES(p_namespace,p_anchor,p_lease,digest);
  INSERT INTO mem9_maintenance.expiries VALUES(p_namespace,digest,p_anchor,valid_until) ON CONFLICT DO NOTHING;
  UPDATE mem9_maintenance.work w SET completed_generation=w.claimed_generation,lease_until=NULL,attempts=0
    WHERE w.namespace_id=p_namespace AND w.memory_id=p_anchor;
  RETURN digest;
END $$;

CREATE OR REPLACE FUNCTION mem9_maintenance.find_classification(p_namespace TEXT,p_ids TEXT[])
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE members JSONB; context TEXT; digest TEXT; found_result JSONB;
BEGIN
  PERFORM mem9_maintenance.authorize(p_namespace,'planner');
  PERFORM mem9_maintenance.lock_queue(p_namespace);
  SELECT jsonb_agg(jsonb_build_object('id',m.memory_id,'version',m.version,'fingerprint',m.fingerprint) ORDER BY m.memory_id)
    INTO members FROM mem9_maintenance.read_memories(p_namespace,p_ids) m;
  IF members IS NULL AND cardinality(p_ids)=1 THEN
    members := '[]'::jsonb;
  ELSIF members IS NULL OR jsonb_array_length(members)<>cardinality(p_ids) THEN
    RETURN NULL;
  END IF;
  SELECT context_hash INTO context FROM mem9_maintenance.namespace_state WHERE namespace_id=p_namespace;
  digest := mem9_maintenance.input_fingerprint(context,members,p_ids[1]);
  SELECT jsonb_build_object('classification_id',c.classification_id,'payload',c.payload) INTO found_result
    FROM mem9_maintenance.classifications c WHERE c.namespace_id=p_namespace AND c.input_hash=digest
      AND c.valid_until>clock_timestamp() ORDER BY c.valid_until DESC LIMIT 1;
  RETURN found_result;
END $$;

CREATE OR REPLACE FUNCTION mem9_maintenance.sweep_due(p_namespace TEXT,p_limit INTEGER)
RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE item RECORD; total INTEGER:=0;
BEGIN
  PERFORM mem9_maintenance.authorize(p_namespace,'planner');
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 1000 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid expiry batch'; END IF;
  PERFORM mem9_maintenance.lock_queue(p_namespace);
  FOR item IN SELECT e.* FROM mem9_maintenance.expiries e WHERE e.namespace_id=p_namespace AND e.due_at<=clock_timestamp()
    ORDER BY e.due_at,e.memory_id LIMIT p_limit FOR UPDATE SKIP LOCKED LOOP
    PERFORM mem9_maintenance.dirty(p_namespace,item.memory_id,item.due_at,'expired');
    DELETE FROM mem9_maintenance.expiries e WHERE e.namespace_id=p_namespace
      AND e.classification_id=item.classification_id AND e.memory_id=item.memory_id;
    total:=total+1;
  END LOOP;
  RETURN total;
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.queue_status(p_namespace TEXT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  PERFORM mem9_maintenance.authorize(p_namespace);
  PERFORM mem9_maintenance.lock_queue(p_namespace);
  RETURN jsonb_build_object(
    'changes',(SELECT count(*) FROM mem9_maintenance.changes WHERE namespace_id=p_namespace),
    'pending',(SELECT count(*) FROM mem9_maintenance.work WHERE namespace_id=p_namespace AND desired_generation>completed_generation),
    'leased',(SELECT count(*) FROM mem9_maintenance.work WHERE namespace_id=p_namespace AND lease_until>clock_timestamp()),
    'blocked',(SELECT count(*) FROM mem9_maintenance.work WHERE namespace_id=p_namespace AND reason='lease_exhausted'),
    'oldest_pending_seconds',(SELECT greatest(0,extract(epoch FROM clock_timestamp()-min(first_seen_at)))
      FROM mem9_maintenance.work WHERE namespace_id=p_namespace AND desired_generation>completed_generation));
END $$;

-- All result storage, caller bindings and configuration remain owner-only.
-- Even a mapped login cannot bypass these operations through direct DML.
REVOKE ALL ON ALL TABLES IN SCHEMA mem9_maintenance FROM PUBLIC,mem9_maintenance_planner,mem9_maintenance_executor;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA mem9_maintenance FROM PUBLIC,mem9_maintenance_planner,mem9_maintenance_executor;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mem9_maintenance FROM PUBLIC;
-- Replaying the base migration must not revoke a later execution migration's
-- grants or temporarily downgrade its backend/operator authorization.
REVOKE ALL ON FUNCTION mem9_maintenance.immutable(),mem9_maintenance.capture_change(),
  mem9_maintenance.authorize(TEXT,TEXT),mem9_maintenance.lock_queue(TEXT),
  mem9_maintenance.dirty(TEXT,TEXT,TIMESTAMPTZ,TEXT),
  mem9_maintenance.configure_namespace(TEXT,TEXT,BOOLEAN),
  mem9_maintenance.consume_changes(TEXT,INTEGER),mem9_maintenance.claim_work(TEXT,INTEGER,INTEGER),
  mem9_maintenance.read_memories(TEXT,TEXT[]),mem9_maintenance.input_fingerprint(TEXT,JSONB,TEXT),
  mem9_maintenance.publish_classification(TEXT,TEXT,BIGINT,JSONB),
  mem9_maintenance.find_classification(TEXT,TEXT[]),mem9_maintenance.sweep_due(TEXT,INTEGER),
  mem9_maintenance.queue_status(TEXT) FROM mem9_maintenance_planner,mem9_maintenance_executor;
GRANT USAGE ON SCHEMA mem9_maintenance TO mem9_maintenance_planner,mem9_maintenance_executor;
GRANT EXECUTE ON FUNCTION mem9_maintenance.consume_changes(TEXT,INTEGER),
  mem9_maintenance.claim_work(TEXT,INTEGER,INTEGER),mem9_maintenance.read_memories(TEXT,TEXT[]),
  mem9_maintenance.publish_classification(TEXT,TEXT,BIGINT,JSONB),
  mem9_maintenance.find_classification(TEXT,TEXT[]),mem9_maintenance.sweep_due(TEXT,INTEGER)
  TO mem9_maintenance_planner;
GRANT EXECUTE ON FUNCTION mem9_maintenance.queue_status(TEXT) TO mem9_maintenance_planner,mem9_maintenance_executor;
COMMIT;
