import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';

// Installed by the existing schema administrator in the caller's transaction.
// Full images remain private; references never grant namespace access.
export const PROVENANCE_VERSION=1;
const hash=value=>createHash('sha256').update(value).digest('hex');
const body=sql=>sql.slice(sql.indexOf('AS $$')+5,sql.lastIndexOf('$$'));
const scalar=async(db,sql,args=[])=>(await db.query(sql,args)).rows[0]?.result;
const fail=()=>{throw Error('ProvenanceUpgradeCatalogMismatch');};

export const provenanceDefinitions=[
{signature:'mem9_maintenance.source_post_images_fit(text,jsonb,jsonb,boolean)',args:['p_kind','p_members','p_output','p_rewrite'],result:'boolean',grants:[],sql:String.raw`CREATE OR REPLACE FUNCTION mem9_maintenance.source_post_images_fit(p_kind TEXT,p_members JSONB,p_output JSONB,p_rewrite BOOLEAN) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE image JSONB; target TEXT:=p_output->>'target';
BEGIN
  FOR image IN SELECT value FROM jsonb_array_elements(p_members) LOOP
    IF p_kind='MERGE' THEN
      IF image->>'id'=target THEN
        image:=image||jsonb_build_object('content',p_output->'content','tags',p_output->'tags','metadata',p_output->'metadata');
        -- A normalized 1024-dimensional float4 vector needs less than this
        -- allowance, including JSON escaping. Validate the actual image again
        -- inside the final atomic commit.
        IF p_rewrite THEN image:=jsonb_set(image,'{embedding}',to_jsonb(repeat('0',65536))); END IF;
      ELSE image:=image||jsonb_build_object('state','deleted','superseded_by',target); END IF;
    ELSIF p_kind='ARCHIVE' AND image->>'id'<>target THEN
      image:=image||jsonb_build_object('state','archived','superseded_by',target);
    ELSIF p_kind='STALE' THEN
      image:=image||jsonb_build_object('tags',coalesce(nullif(image->'tags','null'),'[]')||'"stale"'::jsonb,
        'metadata',jsonb_set(coalesce(nullif(image->'metadata','null'),'{}'),'{consolidation}',
          coalesce(nullif(image->'metadata'->'consolidation','null'),'{}')||'{"stale":true}',TRUE));
    END IF;
    image:=image||jsonb_build_object('version',2147483647,'updated_at',repeat('0',40),'updated_by_principal_id',repeat('0',216));
    IF octet_length(image::text)>1048576 THEN RETURN FALSE; END IF;
  END LOOP;
  RETURN TRUE;
END $$;`},
{signature:'mem9_maintenance.valid_source_image(character varying,character varying,integer,text,jsonb)',args:['p_namespace','p_id','p_version','p_hash','p_image'],result:'boolean',language:'sql',volatility:'i',security:false,grants:[],sql:String.raw`CREATE OR REPLACE FUNCTION mem9_maintenance.valid_source_image(p_namespace VARCHAR(36),p_id VARCHAR(36),p_version INTEGER,p_hash TEXT,p_image JSONB)
RETURNS BOOLEAN LANGUAGE SQL IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
  SELECT coalesce(jsonb_typeof(p_image)='object' AND octet_length(p_image::text)<=1048576
    AND p_image->>'namespace_id'=p_namespace AND p_image->>'id'=p_id
    AND p_version>0 AND p_image->>'version'=p_version::text
    AND p_hash=encode(sha256(convert_to(p_image::text,'UTF8')),'hex'),FALSE)
$$;`},
{signature:'mem9_maintenance.image_reference(text,jsonb)',args:['p_namespace','p_image'],grants:[],sql:String.raw`CREATE OR REPLACE FUNCTION mem9_maintenance.image_reference(p_namespace TEXT,p_image JSONB) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE digest TEXT;
BEGIN
  IF p_image IS NULL OR jsonb_typeof(p_image)<>'object' OR p_image->>'namespace_id' IS DISTINCT FROM p_namespace OR
    jsonb_typeof(p_image->'id') IS DISTINCT FROM 'string' OR length(p_image->>'id') NOT BETWEEN 1 AND 36 OR
    coalesce(p_image->>'version','')!~'^[1-9][0-9]*$' THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid source image'; END IF;
  IF octet_length(p_image::text)>1048576 THEN
    RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='maintenance source image too large'; END IF;
  digest:=encode(sha256(convert_to(p_image::text,'UTF8')),'hex');
  RETURN jsonb_build_object('format','mem9-image-v1','id',p_image->>'id','version',p_image->'version','image_hash',digest);
END $$;`},
{signature:'mem9_maintenance.store_images(text,jsonb)',args:['p_namespace','p_images'],grants:[],sql:String.raw`CREATE OR REPLACE FUNCTION mem9_maintenance.store_images(p_namespace TEXT,p_images JSONB) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE image JSONB; reference JSONB; result_refs JSONB:='[]'; saved JSONB;
BEGIN
  IF p_images IS NULL OR jsonb_typeof(p_images)<>'array' OR jsonb_array_length(p_images)>10 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid source image batch'; END IF;
  FOR image IN SELECT value FROM jsonb_array_elements(p_images) ORDER BY value->>'id' LOOP
    reference:=mem9_maintenance.image_reference(p_namespace,image);
    INSERT INTO mem9_maintenance.source_images(namespace_id,image_hash,memory_id,version,image)
      VALUES(p_namespace,reference->>'image_hash',reference->>'id',(reference->>'version')::integer,image)
      ON CONFLICT(namespace_id,image_hash) DO NOTHING;
    SELECT s.image INTO saved FROM mem9_maintenance.source_images s
      WHERE s.namespace_id=p_namespace AND s.image_hash=reference->>'image_hash';
    IF saved IS DISTINCT FROM image THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='source image conflict'; END IF;
    result_refs:=result_refs||jsonb_build_array(reference);
  END LOOP;
  RETURN result_refs;
END $$;`},
{signature:'mem9_maintenance.load_image(text,jsonb)',args:['p_namespace','p_reference'],grants:[],sql:String.raw`CREATE OR REPLACE FUNCTION mem9_maintenance.load_image(p_namespace TEXT,p_reference JSONB) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE image JSONB;
BEGIN
  IF p_reference IS NULL OR jsonb_typeof(p_reference)<>'object' THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid source reference'; END IF;
  IF NOT p_reference?'format' AND NOT p_reference?'image_hash' THEN
    IF p_reference->>'namespace_id' IS DISTINCT FROM p_namespace THEN
      RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='source namespace denied'; END IF;
    RETURN p_reference;
  END IF;
  IF p_reference->>'format' IS DISTINCT FROM 'mem9-image-v1' OR
    (SELECT count(*) FROM jsonb_object_keys(p_reference))<>4 OR
    NOT p_reference ?& ARRAY['format','id','version','image_hash'] OR
    coalesce(p_reference->>'image_hash','')!~'^[a-f0-9]{64}$' OR
    jsonb_typeof(p_reference->'id') IS DISTINCT FROM 'string' OR
    jsonb_typeof(p_reference->'version') IS DISTINCT FROM 'number' THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid source reference'; END IF;
  SELECT s.image INTO image FROM mem9_maintenance.source_images s
    WHERE s.namespace_id=p_namespace AND s.image_hash=p_reference->>'image_hash';
  IF NOT FOUND OR image->>'id' IS DISTINCT FROM p_reference->>'id' OR
    image->'version' IS DISTINCT FROM p_reference->'version' OR
    encode(sha256(convert_to(image::text,'UTF8')),'hex') IS DISTINCT FROM p_reference->>'image_hash' THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='source image unavailable'; END IF;
  RETURN image;
END $$;`},
{signature:'mem9_maintenance.load_images(text,jsonb)',args:['p_namespace','p_references'],grants:[],sql:String.raw`CREATE OR REPLACE FUNCTION mem9_maintenance.load_images(p_namespace TEXT,p_references JSONB) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE reference JSONB; images JSONB:='[]';
BEGIN
  IF p_references IS NULL OR jsonb_typeof(p_references)<>'array' OR jsonb_array_length(p_references)>10 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid source reference batch'; END IF;
  FOR reference IN SELECT value FROM jsonb_array_elements(p_references) ORDER BY value->>'id' LOOP
    images:=images||jsonb_build_array(mem9_maintenance.load_image(p_namespace,reference));
  END LOOP;
  RETURN images;
END $$;`},
{signature:'mem9_maintenance.read_provenance_image(text,jsonb)',args:['p_namespace','p_reference'],grants:['mem9_maintenance_operator'],sql:String.raw`CREATE OR REPLACE FUNCTION mem9_maintenance.read_provenance_image(p_namespace TEXT,p_reference JSONB) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  PERFORM mem9_maintenance.authorize(p_namespace,'operator');
  IF p_reference IS NULL OR octet_length(p_reference::text)>512 OR p_reference->>'format' IS DISTINCT FROM 'mem9-image-v1' THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid source reference'; END IF;
  RETURN mem9_maintenance.load_image(p_namespace,p_reference);
END $$;`},
{signature:'mem9_maintenance.verify_source_images()',args:[],result:'boolean',grants:[],sql:String.raw`CREATE OR REPLACE FUNCTION mem9_maintenance.verify_source_images() RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE link RECORD;
BEGIN
  -- Audit every retained provenance location, including historical inline
  -- chains. Referenced images are audited separately as roots, so reference
  -- chains need no recursive hydration and cannot create traversal cycles.
  FOR link IN WITH RECURSIVE roots(namespace_id,images) AS (
    SELECT namespace_id,members FROM mem9_maintenance.actions
    UNION ALL SELECT namespace_id,output#>'{metadata,consolidation,sources}' FROM mem9_maintenance.actions
    UNION ALL SELECT namespace_id,before_images FROM mem9_maintenance.receipts
    UNION ALL SELECT namespace_id,post_images FROM mem9_maintenance.receipts
    UNION ALL SELECT namespace_id,metadata#>'{consolidation,sources}' FROM public.memories
    UNION ALL SELECT namespace_id,image#>'{metadata,consolidation,sources}' FROM mem9_maintenance.source_images
  ), images(namespace_id,image) AS (
    SELECT r.namespace_id,e.value FROM roots r,LATERAL jsonb_array_elements(
      CASE WHEN jsonb_typeof(r.images)='array' THEN r.images ELSE '[]'::jsonb END) e
    UNION ALL
    SELECT i.namespace_id,e.value FROM images i,LATERAL jsonb_array_elements(
      CASE WHEN jsonb_typeof(i.image#>'{metadata,consolidation,sources}')='array'
        THEN i.image#>'{metadata,consolidation,sources}' ELSE '[]'::jsonb END) e
  ) SELECT DISTINCT namespace_id,image FROM images
    WHERE jsonb_typeof(image)='object' AND (image?'format' OR image?'image_hash')
  LOOP
    PERFORM mem9_maintenance.load_image(link.namespace_id,link.image);
  END LOOP;
  RETURN TRUE;
END $$;`},
{signature:'mem9_maintenance.read_planner_memories(text,text[])',args:['p_namespace','p_ids','memory_id','version','fingerprint','memory'],allTypes:['text','text[]','character varying','integer','text','jsonb'],argModes:['i','i','t','t','t','t'],result:'record',retset:true,settings:['search_path=pg_catalog, pg_temp','TimeZone=UTC'],grants:['mem9_maintenance_planner'],sql:String.raw`CREATE OR REPLACE FUNCTION mem9_maintenance.read_planner_memories(p_namespace TEXT,p_ids TEXT[])
RETURNS TABLE(memory_id VARCHAR(36),version INTEGER,fingerprint TEXT,memory JSONB)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE payload_bytes BIGINT:=0; item public.memories; original JSONB; metadata JSONB;
BEGIN
  PERFORM mem9_maintenance.authorize(p_namespace,'planner');
  IF p_ids IS NULL OR cardinality(p_ids) NOT BETWEEN 1 AND 10 THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid memory read batch'; END IF;
  PERFORM mem9_maintenance.lock_queue(p_namespace);
  FOR item IN SELECT m.* FROM public.memories m WHERE m.namespace_id=p_namespace AND m.id=ANY(p_ids)
    AND m.state='active' AND m.memory_type<>'session' ORDER BY m.id FOR SHARE LOOP
    original:=to_jsonb(item);
    IF octet_length(original::text)>1048576 THEN
      RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='maintenance input too large'; END IF;
    memory:=original-'embedding';metadata:=memory->'metadata';
    IF jsonb_typeof(metadata)='object' THEN
      metadata:=metadata-ARRAY['source_turns','source_seqs'];
      IF jsonb_typeof(metadata->'consolidation')='object' THEN
        metadata:=jsonb_set(metadata,'{consolidation}',(metadata->'consolidation')-'sources'); END IF;
      memory:=jsonb_set(memory,'{metadata}',metadata);
    END IF;
    payload_bytes:=payload_bytes+octet_length(memory::text);
    IF payload_bytes>1048576 THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='maintenance input too large'; END IF;
    memory_id:=item.id;version:=item.version;
    fingerprint:=encode(sha256(convert_to(original::text,'UTF8')),'hex');
    RETURN NEXT;
  END LOOP;
END $$;`},
];

provenanceDefinitions.push({"signature":"mem9_maintenance.queue_classification(text,text)","args":["p_namespace","p_class"],"grants":["mem9_maintenance_planner"],"previousHashes":["1b3b329ba12ac518bb60d0e4cb3138a8c55ad5e9f111ebd4d858c536d592b5fa","889d66e7470d035cf93ad2ff8b71951fe542e343ebeef1c1835043a674fcf37d"],"settings":["search_path=pg_catalog, pg_temp","TimeZone=UTC"],"result":"jsonb",sql:String.raw`CREATE OR REPLACE FUNCTION mem9_maintenance.queue_classification(p_namespace TEXT,p_class TEXT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE c mem9_maintenance.classifications; snapshots JSONB:='[]'; semantic JSONB:='[]'; member RECORD; row_value JSONB;
  first_row JSONB; output JSONB; costs JSONB; content TEXT; target TEXT; count_members INTEGER; id TEXT; semhash TEXT; current_context TEXT; merged_tags JSONB; source_refs JSONB;
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
  IF (SELECT count(*) FROM mem9_maintenance.classification_members WHERE namespace_id=p_namespace AND classification_id=p_class)
    NOT BETWEEN 1 AND 10 THEN RETURN mem9_maintenance.review_execution(p_namespace,p_class,'input_bound'); END IF;
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
    IF octet_length(row_value::text)>1048576 THEN
      RETURN mem9_maintenance.review_execution(p_namespace,p_class,'input_bound'); END IF;
    snapshots:=snapshots||jsonb_build_array(row_value);
    semantic:=semantic||jsonb_build_array(row_value-ARRAY['embedding','version','updated_at','updated_by','updated_by_principal_id']);
  END LOOP;
  count_members:=jsonb_array_length(snapshots);
  IF count_members=0 OR count_members>10 THEN
    RETURN mem9_maintenance.review_execution(p_namespace,p_class,'input_bound'); END IF;
  SELECT jsonb_agg(mem9_maintenance.image_reference(p_namespace,value) ORDER BY value->>'id') INTO source_refs FROM jsonb_array_elements(snapshots);
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
        source_refs),TRUE));
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
  IF coalesce(length(content),0)>200000 OR ((costs->>'rewrite')::int>0 AND octet_length(content)>16384) OR octet_length(source_refs::text)+octet_length(output::text)>1048576 OR
    NOT mem9_maintenance.source_post_images_fit(c.result,snapshots,output,(costs->>'rewrite')::int>0) THEN
    RETURN mem9_maintenance.review_execution(p_namespace,p_class,'output_bound'); END IF;
  semhash:=encode(sha256(convert_to(c.result||semantic::text,'UTF8')),'hex');
  IF EXISTS(SELECT FROM mem9_maintenance.suppressions s WHERE s.namespace_id=p_namespace AND
    (s.semantic_hash=semhash OR (s.kind=c.result AND
      (SELECT count(*) FROM jsonb_array_elements(snapshots) m
       WHERE s.member_hashes @> jsonb_build_array(mem9_maintenance.semantic_member_hash(m)))
       >=CASE WHEN c.result='STALE' THEN 1 ELSE 2 END))) THEN
    RETURN mem9_maintenance.review_execution(p_namespace,p_class,'operator_suppressed'); END IF;
  source_refs:=mem9_maintenance.store_images(p_namespace,snapshots);
  id:=encode(sha256(convert_to(p_class||output::text,'UTF8')),'hex');
  INSERT INTO mem9_maintenance.actions(namespace_id,action_id,classification_id,kind,context_hash,semantic_hash,members,output,cost)
    VALUES(p_namespace,id,p_class,c.result,c.context_hash,semhash,source_refs,output,costs);
  INSERT INTO mem9_maintenance.action_state(namespace_id,action_id,first_seen_at)
    VALUES(p_namespace,id,least(c.created_at,coalesce((SELECT min(w.first_seen_at) FROM mem9_maintenance.work w
      WHERE w.namespace_id=p_namespace AND w.memory_id IN(SELECT value->>'id' FROM jsonb_array_elements(snapshots))),c.created_at)));
  RETURN jsonb_build_object('action_id',id,'status','queued');
END $$;`});

provenanceDefinitions.push({"signature":"mem9_maintenance.action_inputs_valid(text,text)","args":["p_namespace","p_id"],"grants":[],"previousHashes":["af58642e23407d4f1a361e6c5d70d9745d6c44cd3a182d305d8f9a7c0f141d60"],"settings":["search_path=pg_catalog, pg_temp","TimeZone=UTC"],"result":"boolean",sql:String.raw`CREATE OR REPLACE FUNCTION mem9_maintenance.action_inputs_valid(p_namespace TEXT,p_id TEXT) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE a mem9_maintenance.actions; saved JSONB; current_row JSONB;
BEGIN
  SELECT * INTO a FROM mem9_maintenance.actions WHERE namespace_id=p_namespace AND action_id=p_id;
  IF NOT FOUND OR a.context_hash IS DISTINCT FROM (SELECT context_hash FROM mem9_maintenance.namespace_state WHERE namespace_id=p_namespace AND capture_enabled)
    OR EXISTS(SELECT FROM mem9_maintenance.suppressions WHERE namespace_id=p_namespace AND semantic_hash=a.semantic_hash)
    OR NOT EXISTS(SELECT FROM mem9_maintenance.classifications WHERE namespace_id=p_namespace AND classification_id=a.classification_id AND valid_until>mem9_maintenance.execution_time()) THEN RETURN FALSE; END IF;
  FOR saved IN SELECT value FROM jsonb_array_elements(mem9_maintenance.load_images(p_namespace,a.members)) ORDER BY value->>'id' LOOP
    SELECT to_jsonb(m) INTO current_row FROM public.memories m WHERE m.namespace_id=p_namespace AND m.id=saved->>'id' FOR SHARE;
    IF NOT FOUND OR current_row IS DISTINCT FROM saved THEN RETURN FALSE; END IF;
  END LOOP;
  RETURN TRUE;
END $$;`});

provenanceDefinitions.push({"signature":"mem9_maintenance.apply_action(text,text,bigint)","args":["p_namespace","p_id","p_generation"],"grants":["mem9_maintenance_backend"],"previousHashes":["bd22bcd6f20591302d535449689c5e35d0fb26547ea976efcb6a8b19bc9e8250"],"settings":["search_path=pg_catalog, pg_temp","TimeZone=UTC"],"result":"jsonb",sql:String.raw`CREATE OR REPLACE FUNCTION mem9_maintenance.apply_action(p_namespace TEXT,p_id TEXT,p_generation BIGINT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE a mem9_maintenance.actions; s mem9_maintenance.action_state; prep mem9_maintenance.preparations; c mem9_maintenance.execution_control;
  saved JSONB; actual JSONB:='{"total":0,"rewrite":0,"delete":0,"archive":0,"mark":0}'; before_rows JSONB:='[]'; after_rows JSONB:='[]'; current_row JSONB;
  actor TEXT; result JSONB; scope_name TEXT; changed INTEGER; target TEXT; limit_message TEXT;
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
  FOR saved IN SELECT value FROM jsonb_array_elements(mem9_maintenance.load_images(p_namespace,a.members)) ORDER BY value->>'id' LOOP
    SELECT to_jsonb(m) INTO current_row FROM public.memories m WHERE m.namespace_id=p_namespace AND m.id=saved->>'id' FOR UPDATE;
    IF NOT FOUND OR current_row IS DISTINCT FROM saved THEN
      PERFORM mem9_maintenance.release_action(p_namespace,p_id,'invalidated','member_changed'); RETURN jsonb_build_object('status','invalidated'); END IF;
    before_rows:=before_rows||jsonb_build_array(current_row);
  END LOOP;
  IF NOT mem9_maintenance.action_inputs_valid(p_namespace,p_id) THEN
    PERFORM mem9_maintenance.release_action(p_namespace,p_id,'invalidated','context_changed'); RETURN jsonb_build_object('status','invalidated'); END IF;
  IF NOT mem9_maintenance.execution_valid(p_namespace,p_id,p_generation) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='execution authorization expired'; END IF;
  -- Rate and burst count atomic actions; risk reservations/settlement below
  -- still charge every changed row. A burst of one must admit a multi-row merge.
  IF NOT mem9_maintenance.take_apply_rate(p_namespace,1) THEN RETURN jsonb_build_object('status','rate_wait'); END IF;
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
  INSERT INTO mem9_maintenance.receipts(namespace_id,action_id,result,before_images,post_images) VALUES(p_namespace,p_id,result,mem9_maintenance.store_images(p_namespace,before_rows),mem9_maintenance.store_images(p_namespace,after_rows));
  UPDATE mem9_maintenance.action_state SET status=result->>'status',reason='',reservation=NULL,lease_until=NULL WHERE namespace_id=p_namespace AND action_id=p_id;
  RETURN result;
EXCEPTION WHEN program_limit_exceeded THEN
  GET STACKED DIAGNOSTICS limit_message=MESSAGE_TEXT;
  IF limit_message<>'maintenance source image too large' THEN RAISE; END IF;
  -- The exception subtransaction rolled back every mutation and accounting
  -- write. Reacquire authorization and admission before releasing this lease.
  PERFORM mem9_maintenance.execution_guard(p_namespace,'backend');
  PERFORM mem9_maintenance.open_windows(p_namespace);
  PERFORM action_id FROM mem9_maintenance.action_state WHERE namespace_id=p_namespace AND action_id=p_id FOR UPDATE;
  IF NOT mem9_maintenance.execution_valid(p_namespace,p_id,p_generation) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='execution lease invalid'; END IF;
  PERFORM mem9_maintenance.release_action(p_namespace,p_id,'review','source_image_bound');
  RETURN jsonb_build_object('status','review','reason','source_image_bound');
END $$;`});

provenanceDefinitions.push({"signature":"mem9_maintenance.undo_action(text,text)","args":["p_namespace","p_id"],"grants":["mem9_maintenance_operator"],"previousHashes":["aee14a185988ac7148a430c68c76b340c6c54557948c1f62ef110c352c011e49"],"settings":["search_path=pg_catalog, pg_temp","TimeZone=UTC"],"result":"jsonb",sql:String.raw`CREATE OR REPLACE FUNCTION mem9_maintenance.undo_action(p_namespace TEXT,p_id TEXT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE r mem9_maintenance.receipts; row_value JSONB; current_row JSONB; before_row public.memories; actor TEXT; restored INTEGER:=0; c mem9_maintenance.execution_control;
BEGIN
  PERFORM mem9_maintenance.execution_guard(p_namespace,'operator',FALSE);
  IF EXISTS(SELECT FROM mem9_maintenance.undo_receipts WHERE namespace_id=p_namespace AND action_id=p_id) THEN RETURN jsonb_build_object('status','already_undone'); END IF;
  SELECT * INTO c FROM mem9_maintenance.execution_control WHERE singleton;
  IF NOT pg_try_advisory_xact_lock(hashtextextended('mem9-cleanup:'||c.stage||':'||p_namespace,0)) THEN RETURN jsonb_build_object('status','mutex_busy'); END IF;
  SELECT * INTO r FROM mem9_maintenance.receipts WHERE namespace_id=p_namespace AND action_id=p_id;
  IF NOT FOUND OR r.committed_at<mem9_maintenance.execution_time()-interval '30 days' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='undo unavailable'; END IF;
  r.before_images:=mem9_maintenance.load_images(p_namespace,r.before_images);
  r.post_images:=mem9_maintenance.load_images(p_namespace,r.post_images);
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
    (SELECT jsonb_agg(mem9_maintenance.semantic_member_hash(mem9_maintenance.load_image(p_namespace,m))) FROM jsonb_array_elements(members) m),'undo' FROM mem9_maintenance.actions
    WHERE namespace_id=p_namespace AND action_id=p_id ON CONFLICT DO NOTHING;
  RETURN jsonb_build_object('status','undone','restored_rows',restored);
END $$;`});

provenanceDefinitions.push({"signature":"mem9_maintenance.publish_classification(text,text,bigint,jsonb)","args":["p_namespace","p_anchor","p_lease","p_payload"],"grants":["mem9_maintenance_planner"],"previousHashes":["5b727ecdb079923f17bbfadbec82d5d0b6ac976ecd8c2654983b2a3ee78eec16"],"settings":["search_path=pg_catalog, pg_temp","TimeZone=UTC"],"result":"text",sql:String.raw`CREATE OR REPLACE FUNCTION mem9_maintenance.publish_classification(p_namespace TEXT,p_anchor TEXT,p_lease BIGINT,p_payload JSONB)
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
    AND c.input_hash=input_digest AND c.valid_until>clock_timestamp()
    AND NOT coalesce(c.result='REVIEW' AND c.payload->'details'->>'reason' IN ('snapshot_input_bound','model_input_bound')
      AND p_payload->'details'->>'planner'='neighborhood-v1' AND p_payload->'details'->>'reason'='classified'
      AND EXISTS(SELECT FROM mem9_maintenance.neighborhoods n WHERE n.namespace_id=p_namespace AND n.memory_id=p_anchor AND n.lease_generation=p_lease
        AND n.context_hash=expected_context AND n.forced_result IS NULL AND n.cached IS NULL
        AND (SELECT coalesce(jsonb_agg(value-'memory' ORDER BY value->>'id'),'[]') FROM jsonb_array_elements(n.members))=(canonical->'members')),FALSE)
    ORDER BY c.valid_until DESC LIMIT 1;
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
END $$;`});

export const PROVENANCE_MERGE_POLICY_SQL=provenanceDefinitions.find(d=>d.signature==='mem9_maintenance.queue_classification(text,text)').sql;
export const provenanceMergePolicyBody=()=>body(PROVENANCE_MERGE_POLICY_SQL);

const tableSql=String.raw`CREATE TABLE mem9_maintenance.source_images(
  namespace_id VARCHAR(36) NOT NULL REFERENCES public.memory_namespaces(namespace_id),
  image_hash TEXT NOT NULL,memory_id VARCHAR(36) NOT NULL,version INTEGER NOT NULL,image JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(namespace_id,image_hash),
  CONSTRAINT source_images_valid CHECK(mem9_maintenance.valid_source_image(namespace_id,memory_id,version,image_hash,image)));
CREATE TRIGGER source_images_immutable BEFORE UPDATE OR DELETE ON mem9_maintenance.source_images
  FOR EACH ROW EXECUTE FUNCTION mem9_maintenance.immutable();
CREATE TRIGGER source_images_no_truncate BEFORE TRUNCATE ON mem9_maintenance.source_images
  FOR EACH STATEMENT EXECUTE FUNCTION mem9_maintenance.immutable();
CREATE TABLE mem9_maintenance.source_recoveries(
  namespace_id VARCHAR(36) NOT NULL,memory_id VARCHAR(36) NOT NULL,classification_id TEXT NOT NULL,
  invocation TEXT NOT NULL CHECK(invocation~'^[a-f0-9]{32}$'),recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(namespace_id,memory_id,classification_id),
  FOREIGN KEY(namespace_id,classification_id) REFERENCES mem9_maintenance.classifications(namespace_id,classification_id));
CREATE TRIGGER source_recoveries_immutable BEFORE UPDATE OR DELETE ON mem9_maintenance.source_recoveries
  FOR EACH ROW EXECUTE FUNCTION mem9_maintenance.immutable();
CREATE TRIGGER source_recoveries_no_truncate BEFORE TRUNCATE ON mem9_maintenance.source_recoveries
  FOR EACH STATEMENT EXECUTE FUNCTION mem9_maintenance.immutable();
CREATE TABLE mem9_maintenance.source_recovery_invocations(
  invocation TEXT PRIMARY KEY CHECK(invocation~'^[a-f0-9]{32}$'),
  generation TEXT NOT NULL CHECK(generation~'^[a-f0-9]{64}$'),
  targets JSONB NOT NULL CHECK(jsonb_typeof(targets)='array' AND jsonb_array_length(targets) BETWEEN 1 AND 32),
  anchors INTEGER NOT NULL CHECK(anchors BETWEEN 0 AND 100*jsonb_array_length(targets)),
  has_more BOOLEAN NOT NULL,recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp());
CREATE TRIGGER source_recovery_invocations_immutable BEFORE UPDATE OR DELETE ON mem9_maintenance.source_recovery_invocations
  FOR EACH ROW EXECUTE FUNCTION mem9_maintenance.immutable();
CREATE TRIGGER source_recovery_invocations_no_truncate BEFORE TRUNCATE ON mem9_maintenance.source_recovery_invocations
  FOR EACH STATEMENT EXECUTE FUNCTION mem9_maintenance.immutable();
CREATE TABLE mem9_maintenance.provenance_upgrade_history(
  version INTEGER PRIMARY KEY CHECK(version=1),sql_hash TEXT NOT NULL CHECK(sql_hash~'^[a-f0-9]{64}$'),
  invocation TEXT NOT NULL CHECK(invocation~'^[a-f0-9]{32}$'),installed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp());
CREATE TRIGGER provenance_upgrade_history_immutable BEFORE UPDATE OR DELETE ON mem9_maintenance.provenance_upgrade_history
  FOR EACH ROW EXECUTE FUNCTION mem9_maintenance.immutable();
CREATE TRIGGER provenance_upgrade_history_no_truncate BEFORE TRUNCATE ON mem9_maintenance.provenance_upgrade_history
  FOR EACH STATEMENT EXECUTE FUNCTION mem9_maintenance.immutable();
REVOKE ALL ON mem9_maintenance.source_images,mem9_maintenance.source_recoveries,mem9_maintenance.source_recovery_invocations,mem9_maintenance.provenance_upgrade_history
  FROM PUBLIC,mem9_maintenance_planner,mem9_maintenance_executor,mem9_maintenance_backend,mem9_maintenance_operator;`;
export const PROVENANCE_HASH=hash(JSON.stringify({tableSql,definitions:provenanceDefinitions}));
const tables={
  source_images:['namespace_id:character varying(36):true','image_hash:text:true','memory_id:character varying(36):true','version:integer:true','image:jsonb:true','created_at:timestamp with time zone:true'],
  source_recoveries:['namespace_id:character varying(36):true','memory_id:character varying(36):true','classification_id:text:true','invocation:text:true','recorded_at:timestamp with time zone:true'],
  source_recovery_invocations:['invocation:text:true','generation:text:true','targets:jsonb:true','anchors:integer:true','has_more:boolean:true','recorded_at:timestamp with time zone:true'],
  provenance_upgrade_history:['version:integer:true','sql_hash:text:true','invocation:text:true','installed_at:timestamp with time zone:true'],
};

async function functionCatalog(db,signature){
  return (await db.query(`SELECT p.prosrc AS body,p.proowner=session_user::regrole::oid AS owned,
    p.prosecdef,p.proisstrict,p.proleakproof,p.proretset,p.provolatile,p.proparallel,p.prokind,p.pronargdefaults,
    p.proconfig AS settings,p.proargnames AS args,p.prorettype::regtype::text AS result,l.lanname AS language,
    p.proargmodes::text[] AS arg_modes,CASE WHEN p.proallargtypes IS NOT NULL THEN
      ARRAY(SELECT t::regtype::text FROM unnest(p.proallargtypes) t) END AS all_types,
    ARRAY(SELECT CASE WHEN a.grantee=p.proowner THEN 'owner' ELSE coalesce(r.rolname::text,'PUBLIC') END
      FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a LEFT JOIN pg_roles r ON r.oid=a.grantee
      WHERE a.privilege_type='EXECUTE' AND NOT a.is_grantable AND a.grantor=p.proowner ORDER BY 1) AS grants,
    (SELECT count(*)::int FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner)))) AS grant_count
    FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure($1)`,[signature])).rows[0];
}
function functionState(row,definition){
  if(!row)return 'absent';
  const current=body(definition.sql)===row.body;
  if(!current&&!definition.previousHashes?.includes(hash(row.body)))fail();
  const grants=[...definition.grants,'owner'].sort();
  if(!row.owned||row.prosecdef!==(definition.security??true)||row.proisstrict||row.proleakproof||
    row.proretset!==(definition.retset??false)||row.provolatile!==(definition.volatility??'v')||
    row.proparallel!=='u'||row.prokind!=='f'||row.pronargdefaults!==0||row.language!==(definition.language??'plpgsql')||
    row.result!==(definition.result??'jsonb')||!isDeepStrictEqual(row.settings,definition.settings??['search_path=pg_catalog, pg_temp'])||
    !isDeepStrictEqual(row.arg_modes,definition.argModes??null)||!isDeepStrictEqual(row.all_types,definition.allTypes??null)||
    !isDeepStrictEqual(row.args??[],definition.args)||!isDeepStrictEqual(row.grants,grants)||row.grant_count!==grants.length)fail();
  return current?'current':'previous';
}
async function verifyTables(db){
  const immutable=await functionCatalog(db,'mem9_maintenance.immutable()');
  const immutableBody="\nBEGIN\n  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='maintenance result is immutable';\nEND ";
  if(!immutable?.owned||immutable.body!==immutableBody||immutable.prosecdef||immutable.language!=='plpgsql'||
    immutable.result!=='trigger'||immutable.provolatile!=='v'||immutable.proisstrict||immutable.proleakproof||
    !isDeepStrictEqual(immutable.settings,['search_path=pg_catalog, pg_temp']))fail();
  for(const [name,columns] of Object.entries(tables)){
    const row=(await db.query(`SELECT c.oid,c.relowner=session_user::regrole::oid AS owned,c.relkind,c.relrowsecurity,
      NOT EXISTS(SELECT FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
        WHERE a.grantee<>c.relowner OR a.grantor<>c.relowner OR a.is_grantable) AS private,
      ARRAY(SELECT a.attname||':'||format_type(a.atttypid,a.atttypmod)||':'||a.attnotnull::text
        FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum) AS columns,
      NOT EXISTS(SELECT FROM pg_attribute a,LATERAL aclexplode(a.attacl) x WHERE a.attrelid=c.oid AND a.attnum>0) AS column_private,
      (SELECT count(*)::int FROM pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal) AS triggers,
      EXISTS(SELECT FROM pg_trigger t WHERE t.tgrelid=c.oid AND t.tgname=$2
        AND t.tgfoid='mem9_maintenance.immutable()'::regprocedure AND t.tgtype=27 AND t.tgenabled='O'
        AND t.tgqual IS NULL AND t.tgnargs=0 AND t.tgattr::text='' AND octet_length(t.tgargs)=0) AS immutable,
      EXISTS(SELECT FROM pg_trigger t WHERE t.tgrelid=c.oid AND t.tgname=$3
        AND t.tgfoid='mem9_maintenance.immutable()'::regprocedure AND t.tgtype=34 AND t.tgenabled='O'
        AND t.tgqual IS NULL AND t.tgnargs=0 AND t.tgattr::text='' AND octet_length(t.tgargs)=0) AS no_truncate
      FROM pg_class c WHERE c.oid=to_regclass($1)`,['mem9_maintenance.'+name,name+'_immutable',name+'_no_truncate'])).rows[0];
    if(!row?.owned||row.relkind!=='r'||row.relrowsecurity||!row.private||!row.column_private||
      !row.immutable||!row.no_truncate||row.triggers!==2||!isDeepStrictEqual(row.columns,columns))fail();
    if(await scalar(db,`SELECT EXISTS(SELECT FROM pg_roles r WHERE r.rolname=ANY($2::text[]) AND
      (has_table_privilege(r.oid,$1::oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR
       has_any_column_privilege(r.oid,$1::oid,'SELECT,INSERT,UPDATE,REFERENCES'))) AS result`,
      [row.oid,['mem9_maintenance_planner','mem9_maintenance_executor','mem9_maintenance_backend','mem9_maintenance_operator']]))fail();
  }
  const expectedConstraints={
    source_images:['PRIMARY KEY (namespace_id, image_hash)',
      'FOREIGN KEY (namespace_id) REFERENCES memory_namespaces(namespace_id)',
      'CHECK (mem9_maintenance.valid_source_image(namespace_id, memory_id, version, image_hash, image))'],
    source_recoveries:['PRIMARY KEY (namespace_id, memory_id, classification_id)',
      'FOREIGN KEY (namespace_id, classification_id) REFERENCES mem9_maintenance.classifications(namespace_id, classification_id)',
      "CHECK ((invocation ~ '^[a-f0-9]{32}$'::text))"],
    source_recovery_invocations:['PRIMARY KEY (invocation)',"CHECK ((invocation ~ '^[a-f0-9]{32}$'::text))",
      "CHECK ((generation ~ '^[a-f0-9]{64}$'::text))",
      "CHECK (((jsonb_typeof(targets) = 'array'::text) AND ((jsonb_array_length(targets) >= 1) AND (jsonb_array_length(targets) <= 32))))",
      'CHECK (((anchors >= 0) AND (anchors <= (100 * jsonb_array_length(targets)))))'],
    provenance_upgrade_history:['PRIMARY KEY (version)','CHECK ((version = 1))',
      "CHECK ((sql_hash ~ '^[a-f0-9]{64}$'::text))","CHECK ((invocation ~ '^[a-f0-9]{32}$'::text))"],
  };
  for(const [name,expected] of Object.entries(expectedConstraints)){
    const constraints=(await db.query(`SELECT convalidated,condeferrable,condeferred,
      pg_get_constraintdef(oid) AS definition FROM pg_constraint WHERE conrelid=$1::regclass`,['mem9_maintenance.'+name])).rows;
    if(constraints.some(c=>!c.convalidated||c.condeferrable||c.condeferred)||
      !isDeepStrictEqual(constraints.map(c=>c.definition.replace('REFERENCES public.','REFERENCES ')).sort(),[...expected].sort()))fail();
  }
}
async function verifyHistory(db){
  await verifyTables(db);
  const rows=(await db.query('SELECT version,sql_hash,invocation FROM mem9_maintenance.provenance_upgrade_history ORDER BY version LIMIT 2')).rows;
  if(rows.length!==1||rows[0].version!==PROVENANCE_VERSION||rows[0].sql_hash!==PROVENANCE_HASH||!/^[a-f0-9]{32}$/.test(rows[0].invocation))fail();
}
export async function verifyProvenanceUpgrade(db){
  await verifyHistory(db);
  for(const definition of provenanceDefinitions)if(functionState(await functionCatalog(db,definition.signature),definition)!=='current')fail();
  try{await db.query('SELECT mem9_maintenance.verify_source_images()');}
  catch{throw Error('ProvenanceUpgradeImageMismatch');}
  return {version:PROVENANCE_VERSION,sqlHash:PROVENANCE_HASH};
}
export async function installProvenanceUpgrade(db,{invocation,repairLegacyQueue=false}){
  if(!/^[a-f0-9]{32}$/.test(invocation??''))throw Error('ProvenanceUpgradeInvocationRequired');
  await db.query('SAVEPOINT provenance_upgrade');
  try{
    await db.query('SELECT singleton FROM mem9_maintenance.execution_control WHERE singleton FOR UPDATE');
    const installed=await scalar(db,"SELECT to_regclass('mem9_maintenance.provenance_upgrade_history') IS NOT NULL AS result");
    if(installed)await verifyHistory(db);
    else if(await scalar(db,"SELECT to_regclass('mem9_maintenance.source_images') IS NOT NULL OR to_regclass('mem9_maintenance.source_recoveries') IS NOT NULL OR to_regclass('mem9_maintenance.source_recovery_invocations') IS NOT NULL AS result"))fail();
    let repair=false;
    for(const definition of provenanceDefinitions){
      const state=functionState(await functionCatalog(db,definition.signature),definition);
      if(installed){
        if(state==='previous'&&repairLegacyQueue&&definition.signature==='mem9_maintenance.queue_classification(text,text)')repair=true;
        else if(state!=='current')fail();
      }else if(state!==(definition.previousHashes?'previous':'absent'))fail();
    }
    if(!installed){
      for(const definition of provenanceDefinitions){
        await db.query(definition.sql);
        if(!definition.previousHashes){
          // Fixed reviewed signatures and roles, never operator/model input.
          await db.query(`REVOKE ALL ON FUNCTION ${definition.signature} FROM PUBLIC,mem9_maintenance_planner,mem9_maintenance_executor,mem9_maintenance_backend,mem9_maintenance_operator`);
          for(const role of definition.grants)await db.query(`GRANT EXECUTE ON FUNCTION ${definition.signature} TO ${role}`);
        }
      }
      await db.query(tableSql);
      await db.query('INSERT INTO mem9_maintenance.provenance_upgrade_history(version,sql_hash,invocation) VALUES($1,$2,$3)',[PROVENANCE_VERSION,PROVENANCE_HASH,invocation]);
    }else if(repair)await db.query(PROVENANCE_MERGE_POLICY_SQL);
    await verifyProvenanceUpgrade(db);
    await db.query('RELEASE SAVEPOINT provenance_upgrade');
    return {changed:!installed||repair,version:PROVENANCE_VERSION,sqlHash:PROVENANCE_HASH};
  }catch(error){await db.query('ROLLBACK TO SAVEPOINT provenance_upgrade').catch(()=>{});throw error;}
}

const reference=value=>value&&typeof value==='object'&&(Object.hasOwn(value,'image_hash')||Object.hasOwn(value,'format'));
/** Owner-only read path, also usable inside a read-only frozen-canary audit. */
export async function hydrateCanaryImages(db,entries){
  if(!Array.isArray(entries)||entries.length>20)throw Error('CanarySourceImagesInvalid');
  for(const entry of entries){
    const namespace=entry.receipt?.namespace_id;
    const lists=[entry.receipt?.before_images,entry.receipt?.post_images,entry.action?.members];
    if(typeof namespace!=='string'||!namespace||lists.some(rows=>!Array.isArray(rows)||rows.length>10))throw Error('CanarySourceImagesInvalid');
    if(lists.some(rows=>rows.some(reference))){
      const images=(await db.query(`SELECT mem9_maintenance.load_images($1,$2) AS before_images,
        mem9_maintenance.load_images($1,$3) AS post_images,mem9_maintenance.load_images($1,$4) AS members`,
        [namespace,...lists.map(rows=>JSON.stringify(rows))])).rows[0];
      entry.receipt={...entry.receipt,before_images:images.before_images,post_images:images.post_images};
      entry.action={...entry.action,members:images.members};
    }
    const sources=entry.action?.output?.metadata?.consolidation?.sources;
    if(Array.isArray(sources)&&sources.some(reference)){
      if(sources.length>10)throw Error('CanarySourceImagesInvalid');
      // Resolve the actual immutable output links, never manufacture their
      // expected contents from the independently resolved before-images.
      const sourcesWithImages=(await db.query(`SELECT source AS reference,mem9_maintenance.load_image($1,source) AS image
        FROM jsonb_array_elements($2::jsonb) source ORDER BY source->>'id'`,[namespace,JSON.stringify(sources)])).rows;
      entry.action={...entry.action,source_images:sourcesWithImages};
    }
  }
  return entries;
}
