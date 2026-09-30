-- Phase 11.3 rehearsal: a comparable fingerprint of one database.
--
-- One line per fact, "<kind>|<name>|<value>", sorted, so two snapshots diff
-- line by line. Read-only. Run with `psql -AtX -f`, as the bootstrap superuser
-- (the audit_chain/audit_retention schemas are not readable by ccure_user).
--
--   alembic   one row per head in alembic_version
--   schema    every non-system schema, with its owner and table count
--   rows      row count of every table (partition parents include children)
--   data      md5 over every row's text form, order-independent
--   columns / constraints / indexes / triggers / functions / grants
--             one md5 per schema over the definitions, so a structural change
--             anywhere in a schema shows up as a changed line for that schema

\set QUIET on
SET statement_timeout = 0;

WITH tables AS (
    SELECT n.nspname AS s, c.relname AS t
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition
      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%'
),
facts AS (
    SELECT 'alembic' AS kind, version_num AS name, 'head' AS value
    FROM public.alembic_version
  UNION ALL
    SELECT 'schema', n.nspname,
           pg_get_userbyid(n.nspowner) || ' tables=' ||
           (SELECT count(*) FROM pg_class c
             WHERE c.relnamespace = n.oid AND c.relkind IN ('r', 'p'))
    FROM pg_namespace n
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%'
  UNION ALL
    SELECT 'rows', s || '.' || t,
           (xpath('/row/c/text()', query_to_xml(
               format('SELECT count(*) AS c FROM %I.%I', s, t), false, true, '')))[1]::text
    FROM tables
  UNION ALL
    SELECT 'data', s || '.' || t,
           coalesce((xpath('/row/h/text()', query_to_xml(
               format('SELECT md5(string_agg(md5(x::text), '''' ORDER BY md5(x::text))) AS h FROM %I.%I x', s, t),
               false, true, '')))[1]::text, 'empty')
    FROM tables
  UNION ALL
    SELECT 'columns', table_schema,
           md5(string_agg(concat_ws(':', table_name, column_name, data_type, udt_name,
                                    is_nullable, column_default, character_maximum_length),
                          ',' ORDER BY table_name, column_name))
    FROM information_schema.columns
    WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
    GROUP BY table_schema
  UNION ALL
    SELECT 'constraints', n.nspname,
           md5(string_agg(c.conrelid::regclass::text || ':' || c.conname || ':' || pg_get_constraintdef(c.oid),
                          ',' ORDER BY c.conrelid::regclass::text, c.conname))
    FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
    GROUP BY n.nspname
  UNION ALL
    SELECT 'indexes', schemaname, md5(string_agg(indexdef, ',' ORDER BY indexdef))
    FROM pg_indexes
    WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
    GROUP BY schemaname
  UNION ALL
    SELECT 'triggers', n.nspname,
           md5(string_agg(pg_get_triggerdef(tg.oid) || ':' || tg.tgenabled::text, ',' ORDER BY pg_get_triggerdef(tg.oid)))
    FROM pg_trigger tg JOIN pg_class c ON c.oid = tg.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE NOT tg.tgisinternal
    GROUP BY n.nspname
  UNION ALL
    SELECT 'functions', n.nspname,
           md5(string_agg(pg_get_functiondef(p.oid) || coalesce(p.proacl::text, ''),
                          ',' ORDER BY p.oid::regprocedure::text))
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND p.prokind IN ('f', 'p')
      AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid AND d.deptype = 'e')
    GROUP BY n.nspname
  UNION ALL
    SELECT 'grants', n.nspname,
           md5(coalesce(n.nspacl::text, '') || '|' ||
               coalesce((SELECT string_agg(c.relname || '=' || pg_get_userbyid(c.relowner) || coalesce(c.relacl::text, ''),
                                           ',' ORDER BY c.relname)
                         FROM pg_class c WHERE c.relnamespace = n.oid), ''))
    FROM pg_namespace n
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%'
)
SELECT kind || '|' || name || '|' || value FROM facts ORDER BY 1;
