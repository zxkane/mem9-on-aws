// Owner-installed replacement for mem9_maintenance.queue_classification. The
// bootstrap migrations are sealed by the runtime schema digest after the
// credential cutover, so merge-policy changes are installed by the
// consolidation operator. scripts/consolidation-merge-policy.test.mjs proves
// that this body differs from migration 005 only in the documented hunks.
export const MERGE_POLICY_VERSION=2;
export const MERGE_POLICY_SQL=String.raw`CREATE OR REPLACE FUNCTION mem9_maintenance.queue_classification(p_namespace TEXT,p_class TEXT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE c mem9_maintenance.classifications; snapshots JSONB:='[]'; semantic JSONB:='[]'; member RECORD; row_value JSONB;
  first_row JSONB; output JSONB; costs JSONB; content TEXT; target TEXT; count_members INTEGER; id TEXT; semhash TEXT; current_context TEXT; merged_tags JSONB;
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
    -- Members may come from different agents, sources and tag sets. The
    -- survivor keeps the oldest member's agent and source, takes the union of
    -- tags, and every member's complete row stays in consolidation.sources.
    SELECT coalesce(jsonb_agg(tag ORDER BY tag),'[]') INTO merged_tags FROM
      (SELECT DISTINCT t AS tag FROM jsonb_array_elements(snapshots) m,jsonb_array_elements(coalesce(nullif(m->'tags','null'),'[]')) t) tags;
    IF jsonb_array_length(merged_tags)>50 THEN RETURN mem9_maintenance.review_execution(p_namespace,p_class,'output_bound'); END IF;
    output:=jsonb_build_object('target',target,'content',content,'tags',merged_tags,
      'metadata',jsonb_set(coalesce(nullif(first_row->'metadata','null'),'{}'),'{consolidation}',coalesce(nullif(first_row->'metadata'->'consolidation','null'),'{}')||jsonb_build_object('sources',
        (SELECT jsonb_agg(value-ARRAY['embedding']) FROM jsonb_array_elements(snapshots))),TRUE));
    costs:=jsonb_build_object('total',count_members,'rewrite',CASE WHEN content IS DISTINCT FROM first_row->>'content' OR
        merged_tags IS DISTINCT FROM coalesce(nullif(first_row->'tags','null'),'[]') THEN 1 ELSE 0 END,
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
END $$;`;
