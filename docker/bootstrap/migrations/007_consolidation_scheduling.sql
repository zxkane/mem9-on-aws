-- Dormant dispatcher coordination. No runtime settings or credentials are enabled.
BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='30s';
SELECT pg_advisory_xact_lock(hashtext('mem9-maintenance-schema-v1'));

CREATE TABLE IF NOT EXISTS mem9_maintenance.dispatcher_settings(
  singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),
  stage TEXT NOT NULL,
  targets TEXT[] NOT NULL,
  target_hash TEXT NOT NULL,
  generation_key TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  epoch BIGINT NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.dispatcher_settings_history(
  epoch BIGINT PRIMARY KEY,
  settings JSONB NOT NULL,
  changed_by OID NOT NULL,
  changed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS mem9_maintenance.dispatcher_leases(
  kind TEXT PRIMARY KEY CHECK(kind IN ('planner','executor')),
  caller OID,
  owner_token UUID,
  generation BIGINT NOT NULL DEFAULT 0,
  settings_epoch BIGINT,
  expires_at TIMESTAMPTZ,
  deadline_at TIMESTAMPTZ,
  cursor BIGINT NOT NULL DEFAULT 0 CHECK(cursor>=0)
);

CREATE OR REPLACE FUNCTION mem9_maintenance.dispatcher_caller(p_kind TEXT) RETURNS OID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE caller_oid OID;
BEGIN
  IF p_kind IS NULL OR p_kind NOT IN ('planner','executor') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='dispatcher kind denied'; END IF;
  SELECT c.role_oid INTO caller_oid FROM mem9_maintenance.database_callers c JOIN pg_roles r ON r.oid=c.role_oid
    WHERE r.rolname=session_user AND c.capability=p_kind AND pg_has_role(r.oid,('mem9_maintenance_'||p_kind)::name,'USAGE');
  IF caller_oid IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='dispatcher caller denied'; END IF;
  IF NOT EXISTS(SELECT FROM public.memory_namespace_migration_state WHERE singleton_id AND phase='constraints_complete') THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='dispatcher requires namespace enforcement'; END IF;
  RETURN caller_oid;
END $$;

CREATE OR REPLACE FUNCTION mem9_maintenance.configure_dispatcher(p_stage TEXT,p_targets TEXT[],p_enabled BOOLEAN,p_generation TEXT) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE sorted TEXT[]; digest TEXT; prior mem9_maintenance.dispatcher_settings; configured_stage TEXT;
BEGIN
  IF p_stage IS NULL OR p_stage!~'^[a-zA-Z0-9][a-zA-Z0-9-]{0,63}$' OR p_enabled IS NULL OR
    p_generation IS NULL OR p_generation!~'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$' OR p_targets IS NULL OR
    cardinality(p_targets) NOT BETWEEN 1 AND 32 OR array_position(p_targets,NULL) IS NOT NULL OR
    EXISTS(SELECT FROM unnest(p_targets) n WHERE n!~'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') OR
    (SELECT count(DISTINCT n) FROM unnest(p_targets) n)<>cardinality(p_targets) THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid dispatcher configuration'; END IF;
  SELECT array_agg(n ORDER BY n) INTO sorted FROM unnest(p_targets) n;
  digest:=encode(sha256(convert_to(array_to_string(sorted,E'\n'),'UTF8')),'hex');
  -- Owner-only settings, always before lease rows; no memory-row or queue locks.
  PERFORM mem9_maintenance.lock_model();
  SELECT stage INTO configured_stage FROM mem9_maintenance.execution_control WHERE singleton;
  IF configured_stage<>'' AND configured_stage<>p_stage THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='dispatcher stage mismatch'; END IF;
  IF p_enabled AND EXISTS(SELECT FROM unnest(sorted) n WHERE NOT EXISTS(
    SELECT FROM mem9_maintenance.namespace_state s JOIN public.memory_namespaces m USING(namespace_id)
    WHERE s.namespace_id=n AND s.capture_enabled AND m.status='active')) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='dispatcher target is not ready'; END IF;
  SELECT * INTO prior FROM mem9_maintenance.dispatcher_settings WHERE singleton FOR UPDATE;
  IF FOUND AND prior.stage<>p_stage THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='dispatcher stage cannot change'; END IF;
  IF FOUND AND prior.targets=sorted AND prior.generation_key=p_generation AND prior.enabled=p_enabled THEN RETURN; END IF;
  INSERT INTO mem9_maintenance.dispatcher_settings(singleton,stage,targets,target_hash,generation_key,enabled,epoch)
    VALUES(TRUE,p_stage,sorted,digest,p_generation,p_enabled,coalesce(prior.epoch,0)+1)
    ON CONFLICT(singleton) DO UPDATE SET targets=EXCLUDED.targets,target_hash=EXCLUDED.target_hash,
      generation_key=EXCLUDED.generation_key,enabled=EXCLUDED.enabled,epoch=EXCLUDED.epoch;
  INSERT INTO mem9_maintenance.dispatcher_settings_history(epoch,settings,changed_by)
    SELECT epoch,to_jsonb(s),(SELECT oid FROM pg_roles WHERE rolname=session_user) FROM mem9_maintenance.dispatcher_settings s WHERE singleton;
END $$;

CREATE OR REPLACE FUNCTION mem9_maintenance.acquire_dispatcher(p_kind TEXT,p_stage TEXT,p_hash TEXT,p_generation TEXT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE actor OID; cfg mem9_maintenance.dispatcher_settings; lease mem9_maintenance.dispatcher_leases; observed TIMESTAMPTZ; token UUID;
BEGIN
  actor:=mem9_maintenance.dispatcher_caller(p_kind);
  PERFORM mem9_maintenance.lock_model();
  SELECT * INTO cfg FROM mem9_maintenance.dispatcher_settings WHERE singleton FOR UPDATE;
  IF NOT FOUND OR NOT cfg.enabled THEN RETURN jsonb_build_object('status','disabled'); END IF;
  IF p_stage IS DISTINCT FROM cfg.stage OR p_hash IS DISTINCT FROM cfg.target_hash OR p_generation IS DISTINCT FROM cfg.generation_key THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='dispatcher configuration changed'; END IF;
  INSERT INTO mem9_maintenance.dispatcher_leases(kind) VALUES(p_kind) ON CONFLICT DO NOTHING;
  SELECT * INTO lease FROM mem9_maintenance.dispatcher_leases WHERE kind=p_kind FOR UPDATE;
  observed:=clock_timestamp();
  IF lease.owner_token IS NOT NULL AND lease.settings_epoch=cfg.epoch AND lease.expires_at>observed AND lease.deadline_at>observed THEN
    RETURN jsonb_build_object('status','busy'); END IF;
  token:=gen_random_uuid();
  UPDATE mem9_maintenance.dispatcher_leases SET caller=actor,owner_token=token,generation=generation+1,settings_epoch=cfg.epoch,
    expires_at=observed+interval '90 seconds',deadline_at=observed+make_interval(secs=>CASE WHEN p_kind='planner' THEN 3000 ELSE 600 END)
    WHERE kind=p_kind RETURNING * INTO lease;
  RETURN jsonb_build_object('status','acquired','generation',lease.generation,'owner_token',token,'lease_seconds',90,
    'max_seconds',CASE WHEN p_kind='planner' THEN 3000 ELSE 600 END);
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.dispatcher_owned(p_kind TEXT,p_generation BIGINT,p_token UUID,p_expiry BOOLEAN DEFAULT TRUE) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE actor OID; cfg mem9_maintenance.dispatcher_settings; lease mem9_maintenance.dispatcher_leases; observed TIMESTAMPTZ;
BEGIN
  actor:=mem9_maintenance.dispatcher_caller(p_kind);
  PERFORM mem9_maintenance.lock_model();
  SELECT * INTO cfg FROM mem9_maintenance.dispatcher_settings WHERE singleton FOR UPDATE;
  SELECT * INTO lease FROM mem9_maintenance.dispatcher_leases WHERE kind=p_kind FOR UPDATE;
  observed:=clock_timestamp();
  RETURN coalesce(lease.caller=actor AND lease.generation=p_generation AND lease.owner_token=p_token AND
    (NOT p_expiry OR (cfg.enabled AND cfg.epoch=lease.settings_epoch AND lease.expires_at>observed AND lease.deadline_at>observed)),FALSE);
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.renew_dispatcher(p_kind TEXT,p_generation BIGINT,p_token UUID) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  IF NOT mem9_maintenance.dispatcher_owned(p_kind,p_generation,p_token) THEN RETURN FALSE; END IF;
  UPDATE mem9_maintenance.dispatcher_leases SET expires_at=least(deadline_at,clock_timestamp()+interval '90 seconds') WHERE kind=p_kind;
  RETURN TRUE;
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.release_dispatcher(p_kind TEXT,p_generation BIGINT,p_token UUID) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  IF NOT mem9_maintenance.dispatcher_owned(p_kind,p_generation,p_token,FALSE) THEN RETURN FALSE; END IF;
  UPDATE mem9_maintenance.dispatcher_leases SET owner_token=NULL,expires_at=NULL WHERE kind=p_kind;
  RETURN TRUE;
END $$;
CREATE OR REPLACE FUNCTION mem9_maintenance.next_dispatcher_target(p_kind TEXT,p_generation BIGINT,p_token UUID) RETURNS INTEGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE position INTEGER;
BEGIN
  IF NOT mem9_maintenance.dispatcher_owned(p_kind,p_generation,p_token) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='dispatcher lease expired'; END IF;
  SELECT (l.cursor % cardinality(s.targets))::integer INTO position FROM mem9_maintenance.dispatcher_leases l
    CROSS JOIN mem9_maintenance.dispatcher_settings s WHERE l.kind=p_kind AND s.singleton;
  UPDATE mem9_maintenance.dispatcher_leases SET cursor=cursor+1 WHERE kind=p_kind;
  RETURN position;
END $$;

DROP TRIGGER IF EXISTS maintenance_immutable ON mem9_maintenance.dispatcher_settings_history;
CREATE TRIGGER maintenance_immutable BEFORE UPDATE OR DELETE ON mem9_maintenance.dispatcher_settings_history
  FOR EACH ROW EXECUTE FUNCTION mem9_maintenance.immutable();
REVOKE ALL ON ALL TABLES IN SCHEMA mem9_maintenance FROM PUBLIC,mem9_maintenance_planner,mem9_maintenance_executor,mem9_maintenance_backend,mem9_maintenance_operator;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA mem9_maintenance FROM PUBLIC,mem9_maintenance_planner,mem9_maintenance_executor,mem9_maintenance_backend,mem9_maintenance_operator;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mem9_maintenance FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mem9_maintenance.acquire_dispatcher(TEXT,TEXT,TEXT,TEXT),
  mem9_maintenance.renew_dispatcher(TEXT,BIGINT,UUID),mem9_maintenance.release_dispatcher(TEXT,BIGINT,UUID),
  mem9_maintenance.next_dispatcher_target(TEXT,BIGINT,UUID) TO mem9_maintenance_planner,mem9_maintenance_executor;
COMMIT;
