-- Preview-only runtime contract. Deliberately NOT included by schema.sql.
-- The stage-validated owner bootstrap installs this while the service is stopped.
CREATE SCHEMA IF NOT EXISTS mem9_runtime;
REVOKE ALL ON SCHEMA mem9_runtime FROM PUBLIC;
CREATE TABLE IF NOT EXISTS mem9_runtime.readiness(
  singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),
  stage TEXT NOT NULL,
  role_oid OID NOT NULL,
  schema_digest TEXT NOT NULL CHECK(schema_digest ~ '^[0-9a-f]{64}$'),
  index_digest TEXT NOT NULL DEFAULT '',
  ready BOOLEAN NOT NULL DEFAULT FALSE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE mem9_runtime.readiness ADD COLUMN IF NOT EXISTS index_digest TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS mem9_runtime.tenant_bindings(
  tenant_id VARCHAR(36) PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind IN ('runtime','consolidation-preview')),
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  database_name TEXT NOT NULL,
  username TEXT NOT NULL,
  role_oid OID NOT NULL,
  password_hash TEXT NOT NULL CHECK(password_hash ~ '^[0-9a-f]{64}$')
);

CREATE OR REPLACE FUNCTION mem9_runtime.unprivileged(p_role OID) RETURNS BOOLEAN
LANGUAGE SQL STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
  SELECT coalesce((SELECT rolcanlogin AND NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)
    AND NOT pg_has_role(p_role,(SELECT datdba FROM pg_database WHERE datname=current_database()),'MEMBER')
    AND NOT has_database_privilege(p_role,current_database(),'CREATE')
    AND NOT EXISTS(SELECT FROM pg_roles owner_role WHERE owner_role.rolname='rds_superuser' AND pg_has_role(p_role,owner_role.oid,'MEMBER'))
    AND NOT EXISTS(SELECT FROM pg_roles elevated WHERE
      (elevated.rolsuper OR elevated.rolcreatedb OR elevated.rolcreaterole OR elevated.rolreplication OR elevated.rolbypassrls
       OR elevated.rolname IN ('pg_read_server_files','pg_write_server_files','pg_execute_server_program','pg_read_all_data','pg_write_all_data'))
      AND pg_has_role(p_role,elevated.oid,'MEMBER'))
    AND NOT EXISTS(SELECT FROM pg_namespace n WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema'
      AND (pg_has_role(p_role,n.nspowner,'MEMBER') OR has_schema_privilege(p_role,n.oid,'CREATE')))
    AND NOT EXISTS(SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND pg_has_role(p_role,c.relowner,'MEMBER'))
    AND NOT EXISTS(SELECT FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND pg_has_role(p_role,p.proowner,'MEMBER'))
    FROM pg_roles WHERE oid=p_role),FALSE)
$$;

CREATE OR REPLACE FUNCTION mem9_runtime.binding_matches(p_row public.tenants) RETURNS BOOLEAN
LANGUAGE SQL STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
  SELECT EXISTS(SELECT FROM mem9_runtime.tenant_bindings b JOIN pg_roles r ON r.oid=b.role_oid
    WHERE b.tenant_id=(p_row).id AND b.username=(p_row).db_user AND r.rolname=b.username
      AND b.host=(p_row).db_host AND b.port=(p_row).db_port AND b.database_name=(p_row).db_name
      AND (p_row).db_tls AND b.password_hash=encode(sha256(convert_to((p_row).db_password,'UTF8')),'hex')
      AND mem9_runtime.unprivileged(b.role_oid))
$$;

CREATE OR REPLACE FUNCTION mem9_runtime.tenant_visible(p_row public.tenants) RETURNS BOOLEAN
LANGUAGE SQL STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
  SELECT EXISTS(SELECT FROM mem9_runtime.readiness s JOIN pg_roles r ON r.oid=s.role_oid
    WHERE s.singleton AND s.ready AND r.rolname=session_user)
    AND mem9_runtime.binding_matches(p_row)
$$;

CREATE OR REPLACE FUNCTION mem9_runtime.invalidate_tenant_change() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  IF TG_OP='DELETE' OR NOT mem9_runtime.binding_matches(NEW) THEN
    UPDATE mem9_runtime.readiness SET ready=FALSE,updated_at=clock_timestamp() WHERE singleton;
  END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS runtime_tenant_binding_changed ON public.tenants;
CREATE TRIGGER runtime_tenant_binding_changed AFTER INSERT OR UPDATE OR DELETE ON public.tenants
FOR EACH ROW EXECUTE FUNCTION mem9_runtime.invalidate_tenant_change();

-- This single catalog of table/column permissions is also used by the live
-- readiness check. Effective PUBLIC and inherited grants cannot escape it.
CREATE OR REPLACE FUNCTION mem9_runtime.table_permission(s TEXT,t TEXT,p TEXT) RETURNS BOOLEAN
LANGUAGE SQL IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
  SELECT s='public' AND CASE
    WHEN t IN ('memories','sessions','ingest_jobs','ingest_job_plans') THEN p IN ('SELECT','INSERT','UPDATE','DELETE')
    WHEN t='tenant_activity' THEN p IN ('SELECT','INSERT','UPDATE')
    WHEN t IN ('memory_principals','memory_namespace_memberships') THEN p IN ('SELECT','INSERT')
    WHEN t IN ('tenants','memory_namespace_migration_state','memory_cognito_group_bindings','memory_m2m_namespace_bindings','memory_namespaces') THEN p='SELECT'
    ELSE FALSE END
$$;
CREATE OR REPLACE FUNCTION mem9_runtime.column_permission(s TEXT,t TEXT,c TEXT,p TEXT) RETURNS BOOLEAN
LANGUAGE SQL IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
  SELECT mem9_runtime.table_permission(s,t,p) OR (s='public' AND
    ((p='UPDATE' AND (t,c) IN (('memory_principals','last_seen_at'),('memory_namespace_memberships','granted_at'),('memory_namespaces','updated_at')))
      OR (p='SELECT' AND t='upload_tasks' AND c='namespace_id')))
$$;
CREATE OR REPLACE FUNCTION mem9_runtime.acl_valid(p_role OID) RETURNS BOOLEAN
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE t RECORD; c RECORD; f RECORD; permission TEXT; expected BOOLEAN;
BEGIN
  FOR t IN SELECT r.oid,r.relname,n.nspname FROM pg_class r JOIN pg_namespace n ON n.oid=r.relnamespace
    WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND r.relkind IN ('r','p','v','m','f') LOOP
    FOREACH permission IN ARRAY ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN'] LOOP
      expected:=mem9_runtime.table_permission(t.nspname,t.relname,permission);
      IF has_table_privilege(p_role,t.oid,permission) IS DISTINCT FROM expected OR
        has_table_privilege(p_role,t.oid,permission||' WITH GRANT OPTION') THEN RETURN FALSE; END IF;
    END LOOP;
    FOR c IN SELECT attnum,attname FROM pg_attribute WHERE attrelid=t.oid AND attnum>0 AND NOT attisdropped LOOP
      FOREACH permission IN ARRAY ARRAY['SELECT','INSERT','UPDATE','REFERENCES'] LOOP
        expected:=mem9_runtime.column_permission(t.nspname,t.relname,c.attname,permission);
        IF has_column_privilege(p_role,t.oid,c.attnum,permission) IS DISTINCT FROM expected OR
          has_column_privilege(p_role,t.oid,c.attnum,permission||' WITH GRANT OPTION') THEN RETURN FALSE; END IF;
      END LOOP;
    END LOOP;
  END LOOP;
  IF EXISTS(SELECT FROM pg_class seq JOIN pg_namespace n ON n.oid=seq.relnamespace
    WHERE CASE WHEN seq.relkind='S' AND n.nspname !~ '^pg_'
      THEN has_sequence_privilege(p_role,seq.oid,'SELECT,UPDATE,USAGE') ELSE FALSE END) THEN RETURN FALSE; END IF;
  FOR f IN SELECT p.oid,p.prosecdef,n.nspname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema' LOOP
    IF has_function_privilege(p_role,f.oid,'EXECUTE WITH GRANT OPTION') THEN RETURN FALSE; END IF;
    IF f.nspname IN ('mem9_runtime','mem9_maintenance') OR f.prosecdef THEN
      expected:=f.oid IN (
        'mem9_runtime.ready_for(text,text)'::regprocedure,'mem9_runtime.tenant_visible(public.tenants)'::regprocedure,
        'mem9_maintenance.action_status(text,text)'::regprocedure,'mem9_maintenance.prepare_action(text,text,bigint)'::regprocedure,
        'mem9_maintenance.finish_preparation(text,text,bigint,uuid,text,public.vector)'::regprocedure,
        'mem9_maintenance.abandon_preparation(text,text,bigint,uuid)'::regprocedure,
        'mem9_maintenance.apply_action(text,text,bigint)'::regprocedure,'mem9_maintenance.legacy_write_allowed()'::regprocedure);
      IF has_function_privilege(p_role,f.oid,'EXECUTE') IS DISTINCT FROM expected THEN RETURN FALSE; END IF;
    END IF;
  END LOOP;
  RETURN NOT has_database_privilege(p_role,current_database(),'CONNECT WITH GRANT OPTION')
    AND NOT EXISTS(SELECT FROM pg_namespace n WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema'
      AND has_schema_privilege(p_role,n.oid,'USAGE WITH GRANT OPTION'));
END $$;

CREATE OR REPLACE FUNCTION mem9_runtime.schema_valid() RETURNS BOOLEAN
LANGUAGE SQL STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
  SELECT NOT EXISTS(SELECT FROM (VALUES
    ('memories','namespace_id'),('sessions','namespace_id'),('sessions','principal_id'),
    ('ingest_jobs','namespace_id'),('ingest_jobs','principal_id'),('ingest_job_plans','namespace_id'),
    ('ingest_job_plans','principal_id'),('upload_tasks','namespace_id')) expected(t,c)
    WHERE NOT EXISTS(SELECT FROM pg_attribute a WHERE a.attrelid=to_regclass('public.'||expected.t)
      AND a.attname=expected.c AND a.attnotnull AND NOT a.attisdropped))
    AND NOT EXISTS(SELECT FROM (VALUES
      ('memories','fk_memories_namespace','namespace_id','memory_namespaces','namespace_id'),
      ('memories','fk_memories_created_principal','created_by_principal_id','memory_principals','principal_id'),
      ('memories','fk_memories_updated_principal','updated_by_principal_id','memory_principals','principal_id'),
      ('sessions','fk_sessions_namespace','namespace_id','memory_namespaces','namespace_id'),
      ('sessions','fk_sessions_principal','principal_id','memory_principals','principal_id'),
      ('sessions','fk_sessions_updated_principal','updated_by_principal_id','memory_principals','principal_id'),
      ('ingest_jobs','fk_ingest_jobs_namespace','namespace_id','memory_namespaces','namespace_id'),
      ('ingest_jobs','fk_ingest_jobs_principal','principal_id','memory_principals','principal_id'),
      ('ingest_job_plans','fk_ingest_job_plans_namespace','namespace_id','memory_namespaces','namespace_id'),
      ('ingest_job_plans','fk_ingest_job_plans_principal','principal_id','memory_principals','principal_id'),
      ('ingest_job_plans','fk_ingest_job_plans_job_namespace','tenant_id,namespace_id,job_id','ingest_jobs','tenant_id,namespace_id,job_id'),
      ('upload_tasks','fk_upload_tasks_namespace','namespace_id','memory_namespaces','namespace_id')) expected(t,n,c,rt,rc)
      WHERE NOT EXISTS(SELECT FROM pg_constraint k WHERE k.conrelid=to_regclass('public.'||expected.t)
        AND k.conname=expected.n AND k.contype='f' AND k.convalidated AND k.confrelid=to_regclass('public.'||expected.rt)
        AND ARRAY(SELECT a.attname::text FROM unnest(k.conkey) WITH ORDINALITY keys(num,ord)
          JOIN pg_attribute a ON a.attrelid=k.conrelid AND a.attnum=keys.num ORDER BY keys.ord)=string_to_array(expected.c,',')
        AND ARRAY(SELECT a.attname::text FROM unnest(k.confkey) WITH ORDINALITY keys(num,ord)
          JOIN pg_attribute a ON a.attrelid=k.confrelid AND a.attnum=keys.num ORDER BY keys.ord)=string_to_array(expected.rc,',')))
$$;

CREATE OR REPLACE FUNCTION mem9_runtime.index_digest() RETURNS TEXT
LANGUAGE SQL STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
  SELECT encode(sha256(convert_to(coalesce(string_agg(pg_get_indexdef(i.indexrelid),E'\n' ORDER BY x.relname),''),'UTF8')),'hex')
  FROM pg_index i JOIN pg_class x ON x.oid=i.indexrelid JOIN pg_class t ON t.oid=i.indrelid
    JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname='public'
$$;

CREATE OR REPLACE FUNCTION mem9_runtime.ready_for(p_stage TEXT,p_digest TEXT) RETURNS BOOLEAN
LANGUAGE SQL STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
  SELECT EXISTS(SELECT FROM mem9_runtime.readiness s JOIN pg_roles r ON r.oid=s.role_oid
    WHERE s.singleton AND s.ready AND s.stage=p_stage AND s.schema_digest=p_digest AND r.rolname=session_user
      AND mem9_runtime.unprivileged(r.oid) AND NOT has_database_privilege(r.oid,current_database(),'TEMP')
      AND mem9_runtime.acl_valid(r.oid)
      AND mem9_runtime.schema_valid()
      AND s.index_digest=mem9_runtime.index_digest()
      AND (SELECT relrowsecurity FROM pg_class WHERE oid='public.tenants'::regclass)
      AND EXISTS(SELECT FROM public.memory_namespace_migration_state WHERE singleton_id AND phase='constraints_complete')
      AND EXISTS(SELECT FROM mem9_runtime.tenant_bindings b JOIN public.tenants t ON t.id=b.tenant_id
        WHERE b.kind='runtime' AND b.role_oid=r.oid AND mem9_runtime.binding_matches(t))
      AND EXISTS(SELECT FROM pg_auth_members a JOIN pg_roles g ON g.oid=a.roleid
        WHERE a.member=r.oid AND g.rolname='mem9_maintenance_backend' AND a.inherit_option AND NOT a.set_option AND NOT a.admin_option)
      AND NOT EXISTS(SELECT FROM pg_auth_members a JOIN pg_roles g ON g.oid=a.roleid
        WHERE a.member=r.oid AND (g.rolname<>'mem9_maintenance_backend' OR a.set_option OR a.admin_option))
      AND NOT EXISTS(SELECT FROM pg_index i JOIN pg_class t ON t.oid=i.indrelid JOIN pg_namespace n ON n.oid=t.relnamespace
        WHERE n.nspname='public' AND NOT (i.indisvalid AND i.indisready AND i.indislive)))
$$;

CREATE OR REPLACE FUNCTION mem9_runtime.grant_runtime(p_role NAME) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE table_name TEXT; col RECORD;
BEGIN
  IF p_role::text!~'^mem9_runtime_[a-f0-9]{12}$' THEN RAISE EXCEPTION 'invalid runtime role'; END IF;
  EXECUTE format('REVOKE CREATE,TEMPORARY ON DATABASE %I FROM PUBLIC',current_database());
  REVOKE CREATE ON SCHEMA public FROM PUBLIC;
  IF NOT mem9_runtime.unprivileged(p_role::regrole::oid) THEN RAISE EXCEPTION 'runtime role is privileged'; END IF;
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I',current_database(),p_role);
  EXECUTE format('GRANT USAGE ON SCHEMA public,mem9_runtime TO %I',p_role);
  EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA public,mem9_runtime,mem9_maintenance FROM %I',p_role);
  -- PostgreSQL keeps column ACLs separate from relation ACLs.
  FOR col IN SELECT n.nspname,c.relname,a.attname FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('public','mem9_runtime','mem9_maintenance')
      AND a.attnum>0 AND NOT a.attisdropped AND a.attacl IS NOT NULL LOOP
    EXECUTE format('REVOKE ALL (%I) ON %I.%I FROM %I',col.attname,col.nspname,col.relname,p_role);
  END LOOP;
  EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mem9_runtime,mem9_maintenance FROM %I',p_role);
  EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA public,mem9_runtime,mem9_maintenance FROM %I',p_role);
  FOREACH table_name IN ARRAY ARRAY['memories','sessions','ingest_jobs','ingest_job_plans'] LOOP
    EXECUTE format('GRANT SELECT,INSERT,UPDATE,DELETE ON public.%I TO %I',table_name,p_role);
  END LOOP;
  EXECUTE format('GRANT SELECT,INSERT,UPDATE ON public.tenant_activity TO %I',p_role);
  EXECUTE format('GRANT SELECT ON public.tenants,public.memory_namespace_migration_state,public.memory_cognito_group_bindings,public.memory_m2m_namespace_bindings TO %I',p_role);
  EXECUTE format('GRANT SELECT,INSERT ON public.memory_principals,public.memory_namespace_memberships TO %I',p_role);
  EXECUTE format('GRANT UPDATE(last_seen_at) ON public.memory_principals TO %I',p_role);
  EXECUTE format('GRANT UPDATE(granted_at) ON public.memory_namespace_memberships TO %I',p_role);
  EXECUTE format('GRANT SELECT,UPDATE(updated_at) ON public.memory_namespaces TO %I',p_role);
  EXECUTE format('GRANT SELECT(namespace_id) ON public.upload_tasks TO %I',p_role);
  EXECUTE format('GRANT mem9_maintenance_backend TO %I WITH INHERIT TRUE, SET FALSE, ADMIN FALSE',p_role);
  INSERT INTO mem9_maintenance.database_callers(role_oid,capability) VALUES(p_role::regrole::oid,'backend')
    ON CONFLICT(role_oid) DO UPDATE SET capability=EXCLUDED.capability;
  EXECUTE format('GRANT EXECUTE ON FUNCTION mem9_runtime.ready_for(TEXT,TEXT),mem9_runtime.tenant_visible(public.tenants) TO %I',p_role);
  ALTER TABLE public.tenants ENABLE ROW LEVEL SECURITY;
  DROP POLICY IF EXISTS runtime_tenant_visibility ON public.tenants;
  EXECUTE format('CREATE POLICY runtime_tenant_visibility ON public.tenants FOR SELECT TO %I USING (mem9_runtime.tenant_visible(tenants))',p_role);
  DROP POLICY IF EXISTS runtime_tenant_binding_guard ON public.tenants;
  EXECUTE format('CREATE POLICY runtime_tenant_binding_guard ON public.tenants AS RESTRICTIVE FOR SELECT TO %I USING (mem9_runtime.tenant_visible(tenants))',p_role);
END $$;

REVOKE ALL ON ALL TABLES IN SCHEMA mem9_runtime FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mem9_runtime FROM PUBLIC;
