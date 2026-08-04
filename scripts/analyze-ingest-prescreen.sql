\set ON_ERROR_STOP on
\pset pager off

-- Read-only evaluation for docs/designs/ingest-prescreen.md.
--
-- Session and action text is used only in transaction-local feature queries.
-- Output is bounded JSONL: no content, tenant/job/session identifier, or hash
-- leaves PostgreSQL. Invoke psql with:
--
--   --set=analysis_cutoff=2026-07-31T10:00:00Z
--   --set=label_start=2026-07-27T06:00:00Z
--   --set=window_days=30
--   --file scripts/analyze-ingest-prescreen.sql
--
-- label_start is a fixed, coarsened timestamp after the zero_fact deployment
-- reached ECS steady state. false uses omitempty in the persisted plan, so
-- pre-deployment plans cannot be labeled from their payload alone.

\if :{?analysis_cutoff}
\else
  \set analysis_cutoff '2026-07-31T10:00:00Z'
\endif

\if :{?label_start}
\else
  \set label_start '2026-07-27T06:00:00Z'
\endif

\if :{?window_days}
\else
  \set window_days '30'
\endif

-- PostgreSQL permits a read-only transaction to modify existing temporary
-- tables, but creating them is classified as DDL. A read-only role may also
-- default every transaction to read-only. Use one explicit read-write
-- transaction only to define empty session-local objects; committing it
-- restores the role default before every source-table read and populated row.
BEGIN TRANSACTION READ WRITE;
CREATE TEMP TABLE ingest_prescreen_features (
  job_id varchar(36) NOT NULL,
  tenant_id varchar(36) NOT NULL,
  split text NOT NULL,
  zero_fact boolean NOT NULL,
  message_count int NOT NULL,
  total_runes int NOT NULL,
  user_message_count int NOT NULL,
  assistant_message_count int NOT NULL,
  tool_message_count int NOT NULL,
  user_message_share double precision NOT NULL,
  user_rune_share double precision NOT NULL,
  tool_role_ratio double precision NOT NULL,
  has_decision_language boolean NOT NULL,
  has_preference_language boolean NOT NULL,
  has_constraint_language boolean NOT NULL,
  has_environment_language boolean NOT NULL,
  has_durable_language boolean NOT NULL,
  cause_category text,
  message_count_bucket text NOT NULL,
  rune_bucket text NOT NULL
);

CREATE TEMP TABLE ingest_prescreen_false_skip_items (
  item text PRIMARY KEY,
  category text NOT NULL,
  message_count_bucket text NOT NULL,
  rune_bucket text NOT NULL,
  has_decision_language boolean NOT NULL,
  has_preference_language boolean NOT NULL,
  has_constraint_language boolean NOT NULL,
  has_environment_language boolean NOT NULL
);

CREATE TEMP VIEW ingest_prescreen_candidates AS
SELECT
  features.*,
  candidate.name AS candidate,
  candidate.should_skip
FROM ingest_prescreen_features AS features
CROSS JOIN LATERAL (
  VALUES
    ('messages_le_1', message_count <= 1),
    ('messages_le_2', message_count <= 2),
    ('runes_le_80', total_runes <= 80),
    ('runes_le_160', total_runes <= 160),
    ('runes_le_320', total_runes <= 320),
    (
      'runes_le_80_no_durable_language',
      total_runes <= 80 AND NOT has_durable_language
    ),
    (
      'runes_le_160_no_durable_language',
      total_runes <= 160 AND NOT has_durable_language
    ),
    (
      'runes_le_320_no_durable_language',
      total_runes <= 320 AND NOT has_durable_language
    ),
    (
      'low_user_rune_share_no_durable_language',
      user_rune_share <= 0.10 AND NOT has_durable_language
    ),
    (
      'low_user_message_share_no_durable_language',
      user_message_share <= 0.25 AND NOT has_durable_language
    ),
    (
      'tool_role_ratio_80_no_durable_language',
      tool_role_ratio >= 0.80 AND NOT has_durable_language
    ),
    (
      'conservative_union',
      (
        total_runes <= 160
        OR (
          message_count <= 4
          AND user_rune_share <= 0.10
        )
      )
      AND NOT has_durable_language
    )
) AS candidate(name, should_skip);

CREATE TEMP VIEW ingest_prescreen_candidate_metrics AS
SELECT
  split,
  candidate,
  count(*)::int AS sessions,
  count(*) FILTER (WHERE should_skip)::int AS skipped_sessions,
  count(*) FILTER (WHERE should_skip AND zero_fact)::int AS zero_fact_skipped,
  count(*) FILTER (WHERE should_skip AND NOT zero_fact)::int AS false_skips,
  count(*) FILTER (WHERE NOT zero_fact)::int AS fact_producing_sessions,
  sum(total_runes)::bigint AS total_runes,
  coalesce(sum(total_runes) FILTER (WHERE should_skip), 0)::bigint
    AS skipped_runes
FROM ingest_prescreen_candidates
GROUP BY split, candidate;

CREATE TEMP VIEW ingest_prescreen_choice AS
SELECT candidate
FROM ingest_prescreen_candidate_metrics
WHERE split = 'tuning'
  AND false_skips = 0
  AND skipped_sessions > 0
ORDER BY
  skipped_sessions::double precision / sessions DESC,
  skipped_runes::double precision / greatest(total_runes, 1) DESC,
  candidate
LIMIT 1;
COMMIT;

BEGIN TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '120s';

INSERT INTO ingest_prescreen_features
WITH
parameters AS (
  SELECT
    :'analysis_cutoff'::timestamptz AS analysis_cutoff,
    :'label_start'::timestamptz AS label_start,
    :'window_days'::int AS window_days
),
decoded_jobs AS MATERIALIZED (
  SELECT
    -- job_id globally identifies feature joins, while tenant_id is retained
    -- for the composite ingest_job_plans key used by the taxonomy lookup.
    job.job_id,
    job.tenant_id,
    mod(
      (
        'x' || substr(
          md5(
            concat_ws(
              chr(31),
              job.tenant_id,
              job.agent_id,
              job.app_id,
              CASE
                WHEN job.session_id = '' THEN job.job_id
                ELSE job.session_id
              END
            )
          ),
          1,
          8
        )
      )::bit(32)::bigint,
      5
    ) AS split_bucket,
    convert_from(job.canonical_payload, 'UTF8')::jsonb AS envelope,
    coalesce((plan.plan_json->>'zero_fact') = 'true', false) AS zero_fact
  FROM ingest_jobs AS job
  JOIN LATERAL (
    SELECT
      retained.applied_at,
      convert_from(retained.plan_payload, 'UTF8')::jsonb AS plan_json
    FROM ingest_job_plans AS retained
    WHERE retained.tenant_id = job.tenant_id
      AND retained.job_id = job.job_id
      AND retained.state = 'applied'
    ORDER BY retained.plan_revision DESC
    LIMIT 1
  ) AS plan ON TRUE
  CROSS JOIN parameters
  WHERE job.state = 'succeeded'
    AND job.mode = 'smart'
    AND plan.applied_at >= greatest(
      parameters.label_start,
      parameters.analysis_cutoff - make_interval(days => parameters.window_days)
    )
    AND plan.applied_at < parameters.analysis_cutoff
),
message_features AS (
  SELECT
    job.job_id,
    count(message.value)::int AS message_count,
    coalesce(sum(char_length(message.value->>'content')), 0)::int AS total_runes,
    count(*) FILTER (WHERE lower(message.value->>'role') = 'user')::int
      AS user_message_count,
    count(*) FILTER (WHERE lower(message.value->>'role') = 'assistant')::int
      AS assistant_message_count,
    count(*) FILTER (
      WHERE lower(message.value->>'role') IN ('tool', 'function')
    )::int AS tool_message_count,
    coalesce(sum(char_length(message.value->>'content')) FILTER (
      WHERE lower(message.value->>'role') = 'user'
    ), 0)::int AS user_runes,
    coalesce(
      string_agg(
        lower(message.value->>'content'),
        E'\n'
        ORDER BY message.ordinality
      ),
      ''
    ) AS transcript_text
  FROM decoded_jobs AS job
  LEFT JOIN LATERAL jsonb_array_elements(
    CASE
      WHEN jsonb_typeof(job.envelope->'messages') = 'array'
        THEN job.envelope->'messages'
      ELSE '[]'::jsonb
    END
  )
    WITH ORDINALITY AS message(value, ordinality)
    ON TRUE
  GROUP BY job.job_id
),
features AS (
  SELECT
    job.job_id,
    job.tenant_id,
    CASE
      WHEN job.split_bucket = 0 THEN 'tuning'
      ELSE 'held_out'
    END AS split,
    job.zero_fact,
    message.message_count,
    message.total_runes,
    message.user_message_count,
    message.assistant_message_count,
    message.tool_message_count,
    message.user_message_count::double precision /
      greatest(message.message_count, 1) AS user_message_share,
    message.user_runes::double precision /
      greatest(message.total_runes, 1) AS user_rune_share,
    message.tool_message_count::double precision /
      greatest(message.message_count, 1) AS tool_role_ratio,
    message.transcript_text ~
      '\m(decid(e|ed|ing)|decision|choose|chose|rationale|because|root cause)\M'
      AS has_decision_language,
    message.transcript_text ~
      '\m(prefer|preference|always|never|like|dislike)\M'
      AS has_preference_language,
    message.transcript_text ~
      '\m(must|should|require[ds]?|constraint|policy|do not|don''t|avoid)\M'
      AS has_constraint_language,
    message.transcript_text ~
      '\m(config|configuration|configured|environment|runtime|version|deploy|'
      'architecture|workaround|gotcha|remember|fix(ed)?|uses?)\M'
      AS has_environment_language
  FROM decoded_jobs AS job
  JOIN message_features AS message USING (job_id)
)
SELECT
  features.*,
  (
    has_decision_language
    OR has_preference_language
    OR has_constraint_language
    OR has_environment_language
  ) AS has_durable_language,
  CASE
    WHEN NOT zero_fact THEN NULL
    WHEN (
      has_decision_language
      OR has_preference_language
      OR has_constraint_language
      OR has_environment_language
    ) THEN 'borderline_durable_language_rejected'
    WHEN total_runes <= 160 THEN 'minimal_exchange'
    WHEN tool_role_ratio >= 0.50 THEN 'tool_role_dominated'
    WHEN user_rune_share <= 0.20 THEN 'assistant_heavy'
    ELSE 'routine_without_durable_language'
  END AS cause_category,
  CASE
    WHEN message_count = 0 THEN '0'
    WHEN message_count = 1 THEN '1'
    WHEN message_count = 2 THEN '2'
    WHEN message_count <= 4 THEN '3-4'
    WHEN message_count <= 8 THEN '5-8'
    ELSE '9+'
  END AS message_count_bucket,
  CASE
    WHEN total_runes <= 80 THEN '0000-0080'
    WHEN total_runes <= 160 THEN '0081-0160'
    WHEN total_runes <= 320 THEN '0161-0320'
    WHEN total_runes <= 1000 THEN '0321-1000'
    WHEN total_runes <= 5000 THEN '1001-5000'
    ELSE '5001+'
  END AS rune_bucket
FROM features;

INSERT INTO ingest_prescreen_false_skip_items (
  item,
  category,
  message_count_bucket,
  rune_bucket,
  has_decision_language,
  has_preference_language,
  has_constraint_language,
  has_environment_language
)
WITH
selected AS MATERIALIZED (
  SELECT
    hit.job_id,
    hit.tenant_id,
    hit.message_count_bucket,
    hit.rune_bucket,
    hit.has_decision_language,
    hit.has_preference_language,
    hit.has_constraint_language,
    hit.has_environment_language
  FROM ingest_prescreen_candidates AS hit
  JOIN ingest_prescreen_choice ON ingest_prescreen_choice.candidate = hit.candidate
  WHERE hit.split = 'held_out'
    AND hit.should_skip
    AND NOT hit.zero_fact
),
categorized AS (
  SELECT
    'H-' || lpad(
      row_number() OVER (ORDER BY md5(hit.job_id))::text,
      4,
      '0'
    ) AS item,
    CASE
      WHEN action_summary.action_count = 0
        THEN 'fact_extracted_no_memory_mutation'
      WHEN action_summary.action_count > 0
        AND action_summary.action_text = ''
        THEN 'action_without_content_text'
      WHEN action_summary.action_text ~
        '\m(prefer|preference|always|never|like|dislike)\M'
        THEN 'preference'
      WHEN action_summary.action_text ~
        '\m(decid(e|ed|ing)|decision|choose|chose|rationale|because|root cause)\M'
        THEN 'decision_or_rationale'
      WHEN action_summary.action_text ~
        '\m(must|should|require[ds]?|constraint|policy|do not|don''t|avoid)\M'
        THEN 'constraint_or_policy'
      WHEN action_summary.action_text ~
        '\m(config|configuration|configured|environment|runtime|version|deploy|'
        'architecture|uses?)\M'
        THEN 'environment_or_configuration'
      WHEN action_summary.action_text ~
        '\m(error|failure|failed|bug|workaround|gotcha|remember|fix(ed)?)\M'
        THEN 'failure_or_workaround'
      ELSE 'other_durable_fact'
    END AS category,
    hit.message_count_bucket,
    hit.rune_bucket,
    hit.has_decision_language,
    hit.has_preference_language,
    hit.has_constraint_language,
    hit.has_environment_language
  FROM selected AS hit
  JOIN LATERAL (
    SELECT convert_from(retained.plan_payload, 'UTF8')::jsonb AS plan_json
    FROM ingest_job_plans AS retained
    WHERE retained.tenant_id = hit.tenant_id
      AND retained.job_id = hit.job_id
      AND retained.state = 'applied'
    ORDER BY retained.plan_revision DESC
    LIMIT 1
  ) AS plan ON TRUE
  CROSS JOIN LATERAL (
    SELECT
      count(*)::int AS action_count,
      coalesce(string_agg(lower(action.value->>'content'), E'\n'), '')
        AS action_text
    FROM jsonb_array_elements(
      CASE
        WHEN jsonb_typeof(plan.plan_json->'actions') = 'array'
          THEN plan.plan_json->'actions'
        ELSE '[]'::jsonb
      END
    ) AS action(value)
  ) AS action_summary
)
SELECT
  item,
  category,
  message_count_bucket,
  rune_bucket,
  has_decision_language,
  has_preference_language,
  has_constraint_language,
  has_environment_language
FROM categorized;

SELECT jsonb_build_object(
  'section', 'protocol',
  'data', jsonb_build_object(
    'analysis_cutoff', :'analysis_cutoff'::timestamptz,
    'window_days', :'window_days'::int,
    'label_start', :'label_start'::timestamptz,
    'split',
      'md5(tenant/agent/app/session scope; job fallback) modulo 5: '
      '0=tuning, 1-4=held_out',
    'selection', 'highest tuning skip rate with zero tuning false skips',
    'acceptance', jsonb_build_object(
      'held_out_false_skips', 0,
      'false_skip_rate_wilson_upper_95_lte', 0.005,
      'held_out_skip_rate_gte', 0.10
    )
  )
);

SELECT jsonb_build_object(
  'section', 'baseline',
  'data', jsonb_build_object(
    'sessions', count(*),
    'zero_fact_sessions', count(*) FILTER (WHERE zero_fact),
    'fact_producing_sessions', count(*) FILTER (WHERE NOT zero_fact),
    'zero_fact_rate',
      round(
        count(*) FILTER (WHERE zero_fact)::numeric / greatest(count(*), 1),
        6
      ),
    'tuning_sessions', count(*) FILTER (WHERE split = 'tuning'),
    'held_out_sessions', count(*) FILTER (WHERE split = 'held_out'),
    'empty_message_sessions', count(*) FILTER (WHERE message_count = 0)
  )
)
FROM ingest_prescreen_features;

SELECT jsonb_build_object(
  'section', 'size_by_outcome',
  'data', jsonb_agg(to_jsonb(summary) ORDER BY zero_fact DESC)
)
FROM (
  SELECT
    zero_fact,
    count(*)::int AS sessions,
    percentile_cont(0.25) WITHIN GROUP (ORDER BY message_count)
      AS message_count_p25,
    percentile_cont(0.50) WITHIN GROUP (ORDER BY message_count)
      AS message_count_p50,
    percentile_cont(0.75) WITHIN GROUP (ORDER BY message_count)
      AS message_count_p75,
    percentile_cont(0.25) WITHIN GROUP (ORDER BY total_runes)
      AS total_runes_p25,
    percentile_cont(0.50) WITHIN GROUP (ORDER BY total_runes)
      AS total_runes_p50,
    percentile_cont(0.75) WITHIN GROUP (ORDER BY total_runes)
      AS total_runes_p75,
    round(avg(user_message_share)::numeric, 6) AS mean_user_message_share,
    round(avg(user_rune_share)::numeric, 6) AS mean_user_rune_share,
    round(avg(tool_role_ratio)::numeric, 6) AS mean_tool_role_ratio,
    count(*) FILTER (WHERE has_durable_language)::int
      AS durable_language_sessions
  FROM ingest_prescreen_features
  GROUP BY zero_fact
) AS summary;

SELECT jsonb_build_object(
  'section', 'shape_distribution',
  'data', jsonb_agg(to_jsonb(summary) ORDER BY dimension, bucket, zero_fact DESC)
)
FROM (
  SELECT
    'message_count'::text AS dimension,
    message_count_bucket AS bucket,
    zero_fact,
    count(*)::int AS sessions
  FROM ingest_prescreen_features
  GROUP BY message_count_bucket, zero_fact
  UNION ALL
  SELECT
    'total_runes',
    rune_bucket,
    zero_fact,
    count(*)::int
  FROM ingest_prescreen_features
  GROUP BY rune_bucket, zero_fact
) AS summary;

SELECT jsonb_build_object(
  'section', 'zero_fact_causes',
  'data', jsonb_agg(to_jsonb(summary) ORDER BY sessions DESC, cause_category)
)
FROM (
  SELECT cause_category, count(*)::int AS sessions
  FROM ingest_prescreen_features
  WHERE zero_fact
  GROUP BY cause_category
) AS summary;

SELECT jsonb_build_object(
  'section', 'candidates',
  'data', jsonb_agg(
    jsonb_build_object(
      'split', split,
      'candidate', candidate,
      'sessions', sessions,
      'skipped_sessions', skipped_sessions,
      'zero_fact_skipped', zero_fact_skipped,
      'false_skips', false_skips,
      'skip_rate', round(skipped_sessions::numeric / sessions, 6),
      'false_skip_rate', round(false_skips::numeric / sessions, 6),
      'fact_loss_rate',
        round(false_skips::numeric / greatest(fact_producing_sessions, 1), 6),
      'rune_share_skipped',
        round(skipped_runes::numeric / greatest(total_runes, 1), 6)
    )
    ORDER BY split DESC, candidate
  )
)
FROM ingest_prescreen_candidate_metrics;

WITH
parameters AS (
  SELECT
    1.64485362695::double precision AS z,
    0.005::double precision AS max_upper,
    0.10::double precision AS min_skip
),
held_out AS (
  SELECT
    metrics.*,
    metrics.skipped_sessions::double precision / metrics.sessions AS skip_rate,
    metrics.false_skips::double precision / metrics.sessions
      AS false_skip_rate,
    metrics.false_skips::double precision /
      greatest(metrics.fact_producing_sessions, 1) AS fact_loss_rate
  FROM ingest_prescreen_candidate_metrics AS metrics
  JOIN ingest_prescreen_choice USING (candidate)
  WHERE metrics.split = 'held_out'
),
result AS (
  SELECT
    held_out.*,
    (
      (
        false_skip_rate + parameters.z * parameters.z / (2 * sessions)
        + parameters.z * sqrt(
          (
            false_skip_rate * (1 - false_skip_rate)
            + parameters.z * parameters.z / (4 * sessions)
          ) / sessions
        )
      ) / (1 + parameters.z * parameters.z / sessions)
    ) AS upper,
    parameters.max_upper,
    parameters.min_skip
  FROM held_out
  CROSS JOIN parameters
)
SELECT jsonb_build_object(
  'section', 'selected',
  'data', CASE
    WHEN result.candidate IS NULL THEN jsonb_build_object(
      'candidate', NULL,
      'accepted', false,
      'reason', 'no tuning candidate skipped a session without a false skip'
    )
    ELSE jsonb_build_object(
      'candidate', result.candidate,
      'held_out_sessions', result.sessions,
      'skipped_sessions', result.skipped_sessions,
      'zero_fact_skipped', result.zero_fact_skipped,
      'false_skips', result.false_skips,
      'skip_rate', round(result.skip_rate::numeric, 6),
      'false_skip_rate', round(result.false_skip_rate::numeric, 6),
      'fact_loss_rate', round(result.fact_loss_rate::numeric, 6),
      'false_skip_rate_wilson_upper_95', round(result.upper::numeric, 6),
      'accepted',
        result.false_skips = 0
        AND result.upper <= result.max_upper
        AND result.skip_rate >= result.min_skip
    )
  END
)
FROM (SELECT 1) AS one
LEFT JOIN result ON TRUE;

SELECT jsonb_build_object(
  'section', 'false_skip_item',
  'data', to_jsonb(ingest_prescreen_false_skip_items)
)
FROM ingest_prescreen_false_skip_items
ORDER BY item;

WITH
actual AS (
  SELECT count(*)::int AS false_skip_items
  FROM ingest_prescreen_false_skip_items
),
expected AS (
  SELECT coalesce(sum(metrics.false_skips), 0)::int AS false_skips
  FROM ingest_prescreen_candidate_metrics AS metrics
  JOIN ingest_prescreen_choice USING (candidate)
  WHERE metrics.split = 'held_out'
)
SELECT jsonb_build_object(
  'section', 'complete',
  'data', jsonb_build_object(
    'false_skip_items', actual.false_skip_items,
    'expected_false_skips', expected.false_skips,
    'consistent', actual.false_skip_items = expected.false_skips
  )
)
FROM actual
CROSS JOIN expected;

ROLLBACK;
