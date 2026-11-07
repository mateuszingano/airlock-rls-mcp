#!/usr/bin/env node
// Airlock MCP — expose the Airlock RLS engine to an AI coding agent.
//
// One dependency (airlock-rls, the engine). Speaks MCP's JSON-RPC 2.0 over stdio
// (newline-delimited) directly, so it starts instantly inside an agent.
//
// Five local tools an agent (Cursor, Claude Code, any MCP client) can call while
// it is building a Supabase app:
//
//   1. scan_site_for_exposed_key — point it at a DEPLOYED URL. Reads the page
//      and its JS bundles for a Supabase service_role key shipped to the
//      browser. No database, no credentials. A hit means anyone can bypass
//      every RLS policy. This is the #1 "vibe-coding" leak.
//
//   2. audit_supabase_rls — point it at a Postgres/Supabase connection string.
//      Fails on RLS-off tables, permissive (always-true) policies, and
//      anon/authenticated tenant leaks. Reads only catalog metadata
//      (pg_tables, pg_policies, grants) — never your row data.
//
//   3. get_findings — like audit_supabase_rls but returns machine-readable
//      structured JSON (severity counts, grouped findings) instead of a
//      human-readable summary. Built for programmatic consumption.
//
//   4. explain_finding — pure lookup: given a finding kind (e.g. 'rls_disabled'),
//      returns what it means, why it's dangerous, the fix pattern with example
//      SQL, and related findings. No database connection needed.
//
//   5. generate_fix — pure function: given a finding kind, table name, and
//      optional policy name, returns the exact SQL to fix that specific finding.
//      No database connection needed.
//
// The heavy lifting is the published Airlock engine (npm: airlock-rls). This file
// is only the MCP wrapper.

import { audit } from 'airlock-rls'
import { scanSiteForServiceRole } from 'airlock-rls/service-role'
import { MONITOR_TOOLS, callMonitorTool } from './monitor.mjs'

const SERVER_INFO = { name: 'airlock-mcp', version: '0.1.1' }
const PROTOCOL_VERSION = '2025-06-18'

// Honest bridge to the paid product. A one-shot scan proves the problem is real
// and recurring; the paid Monitor is what a single run can't do — watch the DB
// on a schedule and alert on drift. Claims stay true: hourly, not instant; the
// free gate is the real-time layer, the Monitor is the between-deploys net.
const CTA = [
  '──────────',
  'That was a one-shot check of your public frontend, right now.',
  '• Free gate (CI): blocks a leak on every deploy.',
  '• Airlock Monitor (paid): checks your database every hour and emails you when a new exposure drifts in between deploys — the changes CI never sees (a policy edited by hand, an out-of-band migration, RLS switched off in prod).',
  'No cron to wire up — paste a read-only connection string → https://airlock-monitor.vercel.app/?utm_source=mcp&utm_medium=referral&utm_campaign=airlock-rls-mcp',
].join('\n')

const TOOLS = [
  {
    name: 'scan_site_for_exposed_key',
    description:
      "Scan a DEPLOYED website's HTML and JavaScript bundles for an exposed " +
      'Supabase service_role key (a service_role JWT or an sb_secret_... key). ' +
      'Needs only the public URL — no database, no credentials. A found key is a ' +
      'critical leak: it bypasses ALL Row Level Security, giving anyone who reads ' +
      'it full read/write to the database. Use this right after deploying a ' +
      'Supabase app, or whenever an AI-generated app might have bundled a secret ' +
      'into the frontend. Never prints the full key.',
    inputSchema: {
      type: 'object',
      properties: {
        site_url: {
          type: 'string',
          description:
            'Public https URL of the deployed site to scan (e.g. https://myapp.com). ' +
            'Only public http(s) hosts are allowed.',
        },
        max_scripts: {
          type: 'integer',
          description:
            'How many JS bundles to read (default 50). If the site has more, the ' +
            'result says how many went unscanned instead of implying it looked at all.',
          minimum: 1,
          default: 50,
        },
      },
      required: ['site_url'],
    },
  },
  {
    name: 'audit_supabase_rls',
    description:
      "Audit a Supabase/Postgres database's Row Level Security. Fails when a " +
      'table has RLS disabled, when a policy is permissive (USING (true) / ' +
      'WITH CHECK (true) or anything that reduces to always-true), when an anon ' +
      'or authenticated policy does not scope rows to the caller (tenant leak), ' +
      'and on exposed materialized views. Reads ONLY catalog metadata ' +
      '(pg_tables, pg_policies, grants, functions, views) — never your row data. ' +
      'A read-only connection string is enough.',
    inputSchema: {
      type: 'object',
      properties: {
        db_url: {
          type: 'string',
          description:
            'Postgres connection string for the project to audit (e.g. ' +
            'postgresql://... — get it from `supabase status` locally or your ' +
            "project's connection settings). A read-only role is enough.",
        },
        schema: {
          type: 'string',
          description: 'Schema to audit (default: public).',
          default: 'public',
        },
        allow: {
          type: 'array',
          items: { type: 'string' },
          description:
            'Policy names that are intentionally permissive (e.g. a public status ' +
            'page). Prefer the qualified form "table.policy".',
        },
      },
      required: ['db_url'],
    },
  },
  {
    name: 'get_findings',
    description:
      "Audit a Supabase/Postgres database's Row Level Security and return " +
      'machine-readable structured JSON. Unlike audit_supabase_rls (which ' +
      'returns a human-readable summary), this tool returns findings grouped ' +
      'by severity with counts, suitable for programmatic consumption by an ' +
      'agent that needs to iterate over findings, generate fixes, or build a ' +
      'report. Same engine, same checks, different output shape.',
    inputSchema: {
      type: 'object',
      properties: {
        db_url: {
          type: 'string',
          description:
            'Postgres connection string for the project to audit (e.g. ' +
            'postgresql://... — a read-only role is enough).',
        },
        schema: {
          type: 'string',
          description: 'Schema to audit (default: public).',
          default: 'public',
        },
        allow: {
          type: 'array',
          items: { type: 'string' },
          description:
            'Policy names that are intentionally permissive. Prefer the qualified form "table.policy".',
        },
      },
      required: ['db_url'],
    },
  },
  {
    name: 'explain_finding',
    description:
      'Explain what an Airlock finding kind means, why it is dangerous, how to ' +
      'fix it (with example SQL), and which other findings are related. Pure ' +
      'lookup — no database connection needed. Use this after get_findings or ' +
      'audit_supabase_rls to understand a specific finding before fixing it. ' +
      'Supported kinds: rls_disabled, permissive_true, anon_unscoped, ' +
      'authenticated_unscoped, write_unchecked, write_unscoped, ' +
      'update_using_unscoped, or_branch_unscoped, helper_scoped, ' +
      'security_definer, anon_executes_definer, definer_search_path_mutable, ' +
      'view_bypasses_rls, matview_exposed, public_bucket, realtime_exposure, ' +
      'cross_tenant_read_leak, cross_tenant_write_leak, ' +
      'cross_tenant_delete_leak, bypassrls_role, owner_bypasses_rls.',
    inputSchema: {
      type: 'object',
      properties: {
        finding_kind: {
          type: 'string',
          description:
            "The finding kind string from an audit result (e.g. 'rls_disabled', " +
            "'permissive_true', 'cross_tenant_read_leak').",
        },
      },
      required: ['finding_kind'],
    },
  },
  {
    name: 'generate_fix',
    description:
      'Generate the exact SQL to fix a specific Airlock finding. Pure function — ' +
      'no database connection needed. Returns a ready-to-run SQL statement ' +
      'tailored to the table and policy names you provide. Use after ' +
      'get_findings or audit_supabase_rls to get a fix you can paste into a ' +
      'migration file.',
    inputSchema: {
      type: 'object',
      properties: {
        finding_kind: {
          type: 'string',
          description:
            "The finding kind to fix (e.g. 'rls_disabled', 'permissive_true').",
        },
        table_name: {
          type: 'string',
          description: 'The table the finding applies to (e.g. "profiles").',
        },
        policy_name: {
          type: 'string',
          description:
            'The policy name, if the finding is about a specific policy. ' +
            'Not needed for table-level findings like rls_disabled.',
        },
        schema: {
          type: 'string',
          description: 'Schema the table lives in (default: public).',
          default: 'public',
        },
      },
      required: ['finding_kind', 'table_name'],
    },
  },
]

function summarize(findings) {
  return {
    fails: findings.filter((f) => f.severity === 'fail'),
    warns: findings.filter((f) => f.severity === 'warn'),
  }
}

function renderFindings(findings) {
  const { fails, warns } = summarize(findings)
  const lines = []
  if (fails.length) {
    lines.push(`✗ ${fails.length} problem(s) — the build should be blocked:`)
    for (const f of fails) lines.push(`   ✗ [${f.kind}] ${f.object} — ${f.detail}`)
  }
  if (warns.length) {
    lines.push(`! ${warns.length} warning(s) worth a review:`)
    for (const f of warns) lines.push(`   ! [${f.kind}] ${f.object} — ${f.detail}`)
  }
  if (!fails.length && !warns.length) lines.push('✓ Nothing flagged.')
  return lines.join('\n')
}

async function handleScanSite(args) {
  const siteUrl = args?.site_url
  if (!siteUrl || typeof siteUrl !== 'string') {
    throw new Error('site_url is required (a public https URL of the deployed site).')
  }
  const maxScripts = Number.isInteger(args?.max_scripts) ? args.max_scripts : 50
  const { findings, scanned } = await scanSiteForServiceRole({ siteUrl, maxScripts })
  const { fails } = summarize(findings)
  const verdict = fails.length
    ? `LEAK FOUND — a Supabase service_role key is exposed on ${siteUrl}. Rotate it now and move it server-side.`
    : `Clean — no exposed service_role key found on ${siteUrl} (${scanned} document(s) scanned).`
  return {
    content: [{ type: 'text', text: `${verdict}\n\n${renderFindings(findings)}\n\n${CTA}` }],
    structuredContent: { site: siteUrl, scanned, leaked: fails.length > 0, findings },
    isError: false,
  }
}

async function handleAuditRls(args) {
  const dbUrl = args?.db_url
  if (!dbUrl || typeof dbUrl !== 'string') {
    throw new Error('db_url is required (a Postgres connection string).')
  }
  const schema = typeof args?.schema === 'string' && args.schema ? args.schema : 'public'
  const allow = Array.isArray(args?.allow) ? args.allow : []
  const result = await audit({ dbUrl, schema, allow })
  const verdict = result.passed
    ? `RLS audit PASSED for schema "${schema}" — no exposure found.`
    : `RLS audit FAILED for schema "${schema}" — ${result.problems} problem(s) would block the merge.`
  const { findings, problems, warnings, passed, tables } = result
  return {
    content: [{ type: 'text', text: `${verdict}\n\n${renderFindings(findings)}\n\n${CTA}` }],
    structuredContent: { schema, passed, problems, warnings, tableCount: tables?.length ?? 0, findings },
    isError: false,
  }
}

// ── Finding knowledge base (pure data, no DB) ──────────────────────────────

const FINDING_KNOWLEDGE = {
  rls_disabled: {
    title: 'RLS Disabled',
    severity: 'fail',
    what: 'The table has Row Level Security turned off. Every row is exposed to any API role (anon, authenticated) through PostgREST/Supabase.',
    why: 'Without RLS, the Supabase anon key (public, in every browser bundle) gives full read/write to every row. This is the most common vibe-coding leak.',
    fix: 'Enable RLS and add at least one policy.',
    example_sql: (table, _policy, schema) =>
      `ALTER TABLE "${schema}"."${table}" ENABLE ROW LEVEL SECURITY;\n\n` +
      `-- Then add a policy, e.g. restrict reads to the row owner:\n` +
      `CREATE POLICY "owner_read" ON "${schema}"."${table}"\n` +
      `  FOR SELECT USING (auth.uid() = user_id);`,
    related: ['permissive_true', 'anon_unscoped'],
  },
  permissive_true: {
    title: 'Permissive USING(true) or WITH CHECK(true)',
    severity: 'fail',
    what: 'A policy uses USING(true) or WITH CHECK(true), making it always pass. RLS is on but the policy does not filter anything.',
    why: 'USING(true) means every row is visible. WITH CHECK(true) means any row can be written, including rows belonging to other users. It is RLS in name only.',
    fix: 'Replace the tautology with a real scope that ties the row to the caller.',
    example_sql: (table, policy, schema) =>
      policy
        ? `-- Drop the permissive policy and replace it:\n` +
          `DROP POLICY "${policy}" ON "${schema}"."${table}";\n\n` +
          `CREATE POLICY "${policy}" ON "${schema}"."${table}"\n` +
          `  FOR SELECT USING (auth.uid() = user_id);`
        : `-- Replace USING(true) with a real scope:\n` +
          `-- Example: restrict to the row owner\n` +
          `CREATE POLICY "owner_only" ON "${schema}"."${table}"\n` +
          `  USING (auth.uid() = user_id)\n` +
          `  WITH CHECK (auth.uid() = user_id);`,
    related: ['rls_disabled', 'anon_unscoped', 'write_unscoped'],
  },
  anon_unscoped: {
    title: 'Anonymous Read Without Scoping',
    severity: 'fail',
    what: 'The anon role can read rows without the policy scoping to a specific user. The USING clause does not reference auth.uid() or equivalent.',
    why: 'Anyone with the public anon key (in the browser) reads every row. If the table holds user data, it is a full data breach.',
    fix: 'Scope the USING clause to the caller, or revoke SELECT from anon if the table should not be publicly readable.',
    example_sql: (table, policy, schema) =>
      policy
        ? `DROP POLICY "${policy}" ON "${schema}"."${table}";\n\n` +
          `CREATE POLICY "${policy}" ON "${schema}"."${table}"\n` +
          `  FOR SELECT TO anon\n` +
          `  USING (auth.uid() = user_id);`
        : `-- Option A: scope to the caller\n` +
          `CREATE POLICY "anon_scoped" ON "${schema}"."${table}"\n` +
          `  FOR SELECT TO anon\n` +
          `  USING (auth.uid() = user_id);\n\n` +
          `-- Option B: revoke anon access entirely\n` +
          `REVOKE SELECT ON "${schema}"."${table}" FROM anon;`,
    related: ['permissive_true', 'authenticated_unscoped', 'cross_tenant_read_leak'],
  },
  authenticated_unscoped: {
    title: 'Authenticated Read Without Scoping (Cross-Tenant)',
    severity: 'fail',
    what: 'Any logged-in user can read all rows — the policy does not scope to auth.uid(). This is a cross-tenant / IDOR leak.',
    why: 'User A can read user B\'s data. In a multi-tenant app, every tenant sees every other tenant\'s rows.',
    fix: 'Add auth.uid() scoping to the USING clause.',
    example_sql: (table, policy, schema) =>
      policy
        ? `DROP POLICY "${policy}" ON "${schema}"."${table}";\n\n` +
          `CREATE POLICY "${policy}" ON "${schema}"."${table}"\n` +
          `  FOR SELECT TO authenticated\n` +
          `  USING (auth.uid() = user_id);`
        : `CREATE POLICY "tenant_read" ON "${schema}"."${table}"\n` +
          `  FOR SELECT TO authenticated\n` +
          `  USING (auth.uid() = user_id);`,
    related: ['anon_unscoped', 'permissive_true', 'cross_tenant_read_leak'],
  },
  write_unchecked: {
    title: 'Write Without WITH CHECK',
    severity: 'warn',
    what: 'An INSERT or UPDATE policy has no WITH CHECK clause and the USING clause does not scope to the caller. Writes are not tied to a tenant.',
    why: 'A user can insert or update rows attributed to another user. The row "owner" field can be set to anyone.',
    fix: 'Add a WITH CHECK clause that ties the written row to the caller.',
    example_sql: (table, policy, schema) =>
      policy
        ? `DROP POLICY "${policy}" ON "${schema}"."${table}";\n\n` +
          `CREATE POLICY "${policy}" ON "${schema}"."${table}"\n` +
          `  FOR INSERT TO authenticated\n` +
          `  WITH CHECK (auth.uid() = user_id);`
        : `CREATE POLICY "write_scoped" ON "${schema}"."${table}"\n` +
          `  FOR INSERT TO authenticated\n` +
          `  WITH CHECK (auth.uid() = user_id);`,
    related: ['write_unscoped', 'permissive_true'],
  },
  write_unscoped: {
    title: 'Write WITH CHECK Not Scoped to Caller',
    severity: 'fail',
    what: 'The WITH CHECK clause exists but does not tie the row to the caller (no auth.uid() comparison). A user can forge rows as another tenant.',
    why: 'Cross-tenant write: user A inserts or updates a row setting the owner to user B.',
    fix: 'Rewrite WITH CHECK to include auth.uid() = user_id (or your tenant column).',
    example_sql: (table, policy, schema) =>
      policy
        ? `DROP POLICY "${policy}" ON "${schema}"."${table}";\n\n` +
          `CREATE POLICY "${policy}" ON "${schema}"."${table}"\n` +
          `  FOR INSERT TO authenticated\n` +
          `  WITH CHECK (auth.uid() = user_id);`
        : `CREATE POLICY "write_owned" ON "${schema}"."${table}"\n` +
          `  FOR ALL TO authenticated\n` +
          `  USING (auth.uid() = user_id)\n` +
          `  WITH CHECK (auth.uid() = user_id);`,
    related: ['write_unchecked', 'permissive_true', 'cross_tenant_write_leak'],
  },
  update_using_unscoped: {
    title: 'UPDATE USING Not Scoped (Row Takeover)',
    severity: 'fail',
    what: 'An UPDATE policy\'s USING clause does not scope to the caller. A user can overwrite any row, including rows belonging to other tenants.',
    why: 'Row takeover: user A can UPDATE user B\'s row, changing its contents or re-assigning its ownership. This destroys data and is irreversible.',
    fix: 'Scope the USING clause to auth.uid() so a user can only update their own rows.',
    example_sql: (table, policy, schema) =>
      policy
        ? `DROP POLICY "${policy}" ON "${schema}"."${table}";\n\n` +
          `CREATE POLICY "${policy}" ON "${schema}"."${table}"\n` +
          `  FOR UPDATE TO authenticated\n` +
          `  USING (auth.uid() = user_id)\n` +
          `  WITH CHECK (auth.uid() = user_id);`
        : `CREATE POLICY "update_own" ON "${schema}"."${table}"\n` +
          `  FOR UPDATE TO authenticated\n` +
          `  USING (auth.uid() = user_id)\n` +
          `  WITH CHECK (auth.uid() = user_id);`,
    related: ['write_unscoped', 'cross_tenant_write_leak'],
  },
  or_branch_unscoped: {
    title: 'OR Branch Widens Access',
    severity: 'warn',
    what: 'The policy is scoped by auth.uid() but an OR branch widens it (e.g. "auth.uid() = user_id OR is_public"). The OR may let unscoped rows through.',
    why: 'An OR branch that does not restrict to the caller can leak rows to any user. "auth.uid() = user_id OR status = \'published\'" exposes all published rows to everyone.',
    fix: 'Prove the OR branch restricts to the caller, or split into two policies (one scoped, one for public rows on a separate allow-listed table).',
    example_sql: (table, policy, schema) =>
      `-- Option A: remove the OR and use a separate policy for public rows\n` +
      `DROP POLICY "${policy || 'read_policy'}" ON "${schema}"."${table}";\n\n` +
      `CREATE POLICY "owner_read" ON "${schema}"."${table}"\n` +
      `  FOR SELECT TO authenticated\n` +
      `  USING (auth.uid() = user_id);\n\n` +
      `CREATE POLICY "public_read" ON "${schema}"."${table}"\n` +
      `  FOR SELECT TO authenticated\n` +
      `  USING (is_public = true);`,
    related: ['anon_unscoped', 'authenticated_unscoped'],
  },
  helper_scoped: {
    title: 'Scoped Through Helper Function',
    severity: 'warn',
    what: 'The policy delegates scoping to a helper function. A static scan cannot see inside it to verify it actually restricts to the caller.',
    why: 'If the helper function does not check auth.uid() internally, the policy is effectively unscoped. Static analysis cannot prove this either way.',
    fix: 'Verify the helper function restricts to the caller. If it does, add the policy to the allow list. If not, rewrite it to check auth.uid().',
    example_sql: (table, policy, schema) =>
      `-- Verify the helper function, then allow-list if intentional:\n` +
      `-- airlock audit --allow "${table}.${policy || 'policy_name'}"\n\n` +
      `-- Or rewrite the policy to use auth.uid() directly:\n` +
      `DROP POLICY "${policy || 'policy_name'}" ON "${schema}"."${table}";\n\n` +
      `CREATE POLICY "${policy || 'policy_name'}" ON "${schema}"."${table}"\n` +
      `  FOR SELECT USING (auth.uid() = user_id);`,
    related: ['anon_unscoped', 'authenticated_unscoped', 'security_definer'],
  },
  security_definer: {
    title: 'SECURITY DEFINER Function',
    severity: 'warn',
    what: 'A function is marked SECURITY DEFINER, meaning it runs as its owner (usually postgres) and bypasses RLS.',
    why: 'If any API-reachable role can call this function, it can read/write data that RLS would otherwise block. Legitimate for RLS helpers and triggers, but dangerous if it does data mutations.',
    fix: 'Review who can call it. Revoke EXECUTE from public/anon if not needed. Pin its search_path.',
    example_sql: (table, _policy, schema) =>
      `-- Revoke from public (stops anon and authenticated):\n` +
      `REVOKE EXECUTE ON FUNCTION "${schema}"."${table}" FROM PUBLIC;\n\n` +
      `-- Pin search_path to prevent hijacking:\n` +
      `ALTER FUNCTION "${schema}"."${table}" SET search_path = '';`,
    related: ['anon_executes_definer', 'definer_search_path_mutable'],
  },
  anon_executes_definer: {
    title: 'Anonymous Can Execute SECURITY DEFINER',
    severity: 'warn',
    what: 'The anon role can EXECUTE a SECURITY DEFINER function. It runs as the function owner, bypassing RLS.',
    why: 'An unauthenticated user (anyone with the public anon key) can call a function that runs with elevated privileges. If the function reads or mutates data, it is a privilege escalation.',
    fix: 'Revoke EXECUTE from anon (and from PUBLIC, which includes anon).',
    example_sql: (table, _policy, schema) =>
      `REVOKE EXECUTE ON FUNCTION "${schema}"."${table}" FROM PUBLIC;\n` +
      `REVOKE EXECUTE ON FUNCTION "${schema}"."${table}" FROM anon;`,
    related: ['security_definer', 'definer_search_path_mutable'],
  },
  definer_search_path_mutable: {
    title: 'SECURITY DEFINER Without Pinned search_path',
    severity: 'warn',
    what: 'A SECURITY DEFINER function does not pin its search_path. It resolves unqualified names against the caller\'s search_path.',
    why: 'A privilege escalation path: an attacker sets search_path to a schema containing a malicious function with the same name as one the DEFINER calls, hijacking execution with owner privileges.',
    fix: 'Pin the search_path on the function.',
    example_sql: (table, _policy, schema) =>
      `ALTER FUNCTION "${schema}"."${table}" SET search_path = '';`,
    related: ['security_definer', 'anon_executes_definer'],
  },
  view_bypasses_rls: {
    title: 'View Bypasses RLS',
    severity: 'warn',
    what: 'A view runs as its owner (security_invoker is off). It can bypass RLS on the tables it reads.',
    why: 'If anon or authenticated can SELECT from this view, they see rows the underlying table policies would block. The view owner (usually postgres) is not subject to RLS.',
    fix: 'Set security_invoker = on so the view runs as the querying role, or restrict access.',
    example_sql: (table, _policy, schema) =>
      `ALTER VIEW "${schema}"."${table}" SET (security_invoker = on);`,
    related: ['matview_exposed', 'security_definer'],
  },
  matview_exposed: {
    title: 'Materialized View Exposed',
    severity: 'fail',
    what: 'A materialized view is accessible to anon or authenticated. RLS does not apply to materialized views — every row it holds is exposed.',
    why: 'Materialized views are not subject to RLS. If they contain user data and an API role can SELECT from them, it is a full data leak.',
    fix: 'Revoke SELECT from anon/authenticated, or move the matview to a schema PostgREST does not expose.',
    example_sql: (table, _policy, schema) =>
      `REVOKE SELECT ON "${schema}"."${table}" FROM anon;\n` +
      `REVOKE SELECT ON "${schema}"."${table}" FROM authenticated;`,
    related: ['view_bypasses_rls', 'rls_disabled'],
  },
  public_bucket: {
    title: 'Public Storage Bucket',
    severity: 'warn',
    what: 'A Supabase Storage bucket is marked public. Anyone with the URL can read its files.',
    why: 'Files in a public bucket are accessible without authentication. If it holds private user uploads, it is a data leak.',
    fix: 'Set the bucket to private, or confirm it is intentionally public (e.g. avatars, marketing assets).',
    example_sql: (table) =>
      `-- Make the bucket private:\n` +
      `UPDATE storage.buckets SET public = false WHERE id = '${table}';\n\n` +
      `-- Or allow-list if intentional:\n` +
      `-- airlock audit --allow "storage.${table}"`,
    related: ['anon_unscoped'],
  },
  realtime_exposure: {
    title: 'Realtime Streams Anon-Readable Table',
    severity: 'warn',
    what: 'A table published to Supabase Realtime is also anon-readable. Its row changes stream to anonymous subscribers.',
    why: 'Anonymous WebSocket subscribers receive every INSERT, UPDATE, DELETE on this table in real time — including rows that belong to other users.',
    fix: 'Restrict Realtime to authenticated users, or remove the table from the Realtime publication.',
    example_sql: (table) =>
      `-- Remove from the Realtime publication:\n` +
      `ALTER PUBLICATION supabase_realtime DROP TABLE "${table}";\n\n` +
      `-- Or restrict anon access:\n` +
      `REVOKE SELECT ON "${table}" FROM anon;`,
    related: ['anon_unscoped', 'public_bucket'],
  },
  cross_tenant_read_leak: {
    title: 'Cross-Tenant Read Leak (DAST-Proven)',
    severity: 'fail',
    what: 'Dynamic Application Security Testing (DAST) proved that user B can read user A\'s rows. This is not a static guess — the attack succeeded.',
    why: 'An actual cross-tenant read was executed and confirmed. User B retrieved rows belonging to user A through the Supabase API.',
    fix: 'Add or fix the RLS policy to scope SELECT to auth.uid().',
    example_sql: (table, _policy, schema) =>
      `-- Ensure RLS is enabled:\n` +
      `ALTER TABLE "${schema}"."${table}" ENABLE ROW LEVEL SECURITY;\n\n` +
      `-- Add a scoped read policy:\n` +
      `CREATE POLICY "tenant_read" ON "${schema}"."${table}"\n` +
      `  FOR SELECT TO authenticated\n` +
      `  USING (auth.uid() = user_id);`,
    related: ['anon_unscoped', 'authenticated_unscoped', 'cross_tenant_write_leak'],
  },
  cross_tenant_write_leak: {
    title: 'Cross-Tenant Write Leak (DAST-Proven)',
    severity: 'fail',
    what: 'DAST proved that user B can insert or update rows as user A. The attack succeeded — this is confirmed, not theoretical.',
    why: 'User B modified or created rows attributed to user A. Data integrity is broken.',
    fix: 'Add or fix the RLS policy to scope INSERT/UPDATE to auth.uid() in both USING and WITH CHECK.',
    example_sql: (table, _policy, schema) =>
      `ALTER TABLE "${schema}"."${table}" ENABLE ROW LEVEL SECURITY;\n\n` +
      `CREATE POLICY "tenant_write" ON "${schema}"."${table}"\n` +
      `  FOR ALL TO authenticated\n` +
      `  USING (auth.uid() = user_id)\n` +
      `  WITH CHECK (auth.uid() = user_id);`,
    related: ['write_unscoped', 'write_unchecked', 'cross_tenant_read_leak', 'cross_tenant_delete_leak'],
  },
  cross_tenant_delete_leak: {
    title: 'Cross-Tenant Delete Leak (DAST-Proven)',
    severity: 'fail',
    what: 'DAST proved that user B can delete user A\'s rows. The attack succeeded.',
    why: 'User B deleted rows belonging to user A. Data loss is confirmed and irreversible.',
    fix: 'Add or fix the RLS policy to scope DELETE to auth.uid().',
    example_sql: (table, _policy, schema) =>
      `ALTER TABLE "${schema}"."${table}" ENABLE ROW LEVEL SECURITY;\n\n` +
      `CREATE POLICY "tenant_delete" ON "${schema}"."${table}"\n` +
      `  FOR DELETE TO authenticated\n` +
      `  USING (auth.uid() = user_id);`,
    related: ['cross_tenant_write_leak', 'cross_tenant_read_leak'],
  },
  cross_tenant_discrepancy: {
    title: 'Cross-Tenant Discrepancy (Static Missed, DAST Caught)',
    severity: 'fail',
    what: 'DAST proved a cross-tenant leak that the static analysis did NOT flag. The policy text looked safe but the attack succeeded.',
    why: 'This is the worst case: the static checker said "clean" but the real database is leaking. The policy qualifier may use a function or construct that fools static analysis.',
    fix: 'Investigate why static analysis missed it. The DAST result is ground truth — fix the policy.',
    example_sql: (table, _policy, schema) =>
      `-- The static checker missed this — review the actual policy:\n` +
      `SELECT * FROM pg_policies WHERE tablename = '${table}' AND schemaname = '${schema}';\n\n` +
      `-- Then fix it:\n` +
      `ALTER TABLE "${schema}"."${table}" ENABLE ROW LEVEL SECURITY;\n\n` +
      `CREATE POLICY "tenant_scoped" ON "${schema}"."${table}"\n` +
      `  FOR ALL TO authenticated\n` +
      `  USING (auth.uid() = user_id)\n` +
      `  WITH CHECK (auth.uid() = user_id);`,
    related: ['cross_tenant_read_leak', 'cross_tenant_write_leak', 'helper_scoped'],
  },
  bypassrls_role: {
    title: 'Non-Managed Role With BYPASSRLS',
    severity: 'warn',
    what: 'A database role outside the standard Supabase-managed set has the BYPASSRLS privilege.',
    why: 'If this role is reachable through the API (via SET ROLE or a function), it bypasses all RLS policies.',
    fix: 'Remove BYPASSRLS from the role, or confirm it is intentional and not API-reachable.',
    example_sql: (table) =>
      `ALTER ROLE "${table}" NOBYPASSRLS;`,
    related: ['owner_bypasses_rls', 'security_definer'],
  },
  owner_bypasses_rls: {
    title: 'Table Owner Bypasses RLS',
    severity: 'warn',
    what: 'The table owner is a role the API can reach, and FORCE ROW LEVEL SECURITY is not set. The owner bypasses RLS.',
    why: 'If the API can reach the owner role (via SET ROLE), RLS policies do not apply — the owner sees and writes all rows.',
    fix: 'Force RLS on the table owner, or reassign the table to a non-API-reachable role.',
    example_sql: (table, _policy, schema) =>
      `ALTER TABLE "${schema}"."${table}" FORCE ROW LEVEL SECURITY;`,
    related: ['bypassrls_role', 'rls_disabled'],
  },
  nothing_audited: {
    title: 'Nothing Audited',
    severity: 'fail',
    what: 'No tables or policies were found in the specified schema. The audit checked nothing.',
    why: 'Either the schema is empty, the connection role cannot see the tables, or the schema name is wrong.',
    fix: 'Verify the schema name and the connection role\'s privileges.',
    example_sql: (table, _policy, schema) =>
      `-- Check what tables exist:\n` +
      `SELECT tablename FROM pg_tables WHERE schemaname = '${schema}';\n\n` +
      `-- Check grants:\n` +
      `SELECT grantee, privilege_type FROM information_schema.table_privileges\n` +
      `  WHERE table_schema = '${schema}';`,
    related: [],
  },
  check_skipped: {
    title: 'Check Skipped (Insufficient Access)',
    severity: 'warn',
    what: 'A check did not run because the audit role lacks read access to the required catalog tables.',
    why: 'The result for this check is UNKNOWN, not clean. A missing check is not a passing check.',
    fix: 'Grant the audit role read access to the relevant catalog, or re-run with a more privileged role.',
    example_sql: () =>
      `-- Grant read access to the storage schema (example):\n` +
      `GRANT USAGE ON SCHEMA storage TO your_audit_role;\n` +
      `GRANT SELECT ON storage.buckets TO your_audit_role;`,
    related: [],
  },
  allow_unused: {
    title: 'Allow-List Entry Unused',
    severity: 'warn',
    what: 'An --allow entry matched nothing in this audit. The object was renamed, dropped, or never existed.',
    why: 'A waiver that applies to nothing is not protecting anything. It may hide a real finding on a renamed table.',
    fix: 'Remove the entry or fix its spelling.',
    example_sql: () => `-- No SQL fix — remove the stale --allow entry from your config.`,
    related: ['allow_ambiguous'],
  },
  allow_ambiguous: {
    title: 'Allow-List Entry Ambiguous',
    severity: 'warn',
    what: 'An --allow entry matches multiple tables. It was NOT applied because it is ambiguous.',
    why: 'A bare policy name that matches in two tables would silently waive both. Use the qualified "table.policy" form.',
    fix: 'Qualify the allow entry, e.g. --allow "users.read_all".',
    example_sql: () => `-- No SQL fix — qualify the --allow entry in your config.`,
    related: ['allow_unused'],
  },
}

// Strip the storage_ prefix for lookup — storage findings reuse the base kind
function normalizeFindingKind(kind) {
  return kind.replace(/^storage_/, '')
}

// ── New tool handlers ───────────────────────────────────────────────────────

async function handleGetFindings(args) {
  const dbUrl = args?.db_url
  if (!dbUrl || typeof dbUrl !== 'string') {
    throw new Error('db_url is required (a Postgres connection string).')
  }
  const schema = typeof args?.schema === 'string' && args.schema ? args.schema : 'public'
  const allow = Array.isArray(args?.allow) ? args.allow : []
  const result = await audit({ dbUrl, schema, allow })
  const { findings, allowed, problems, warnings, passed, tables, stats } = result
  const { fails, warns } = summarize(findings)
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(
          {
            schema,
            passed,
            problems,
            warnings,
            table_count: tables?.length ?? 0,
            severity_counts: { fail: fails.length, warn: warns.length },
            findings,
            allowed,
            stats: stats || null,
          },
          null,
          2,
        ),
      },
    ],
    structuredContent: {
      schema,
      passed,
      problems,
      warnings,
      table_count: tables?.length ?? 0,
      severity_counts: { fail: fails.length, warn: warns.length },
      findings,
      allowed,
      stats: stats || null,
    },
    isError: false,
  }
}

function handleExplainFinding(args) {
  const kind = args?.finding_kind
  if (!kind || typeof kind !== 'string') {
    throw new Error('finding_kind is required (e.g. "rls_disabled", "permissive_true").')
  }
  const normalized = normalizeFindingKind(kind)
  const entry = FINDING_KNOWLEDGE[normalized]
  if (!entry) {
    const known = Object.keys(FINDING_KNOWLEDGE).join(', ')
    throw new Error(`Unknown finding kind: "${kind}". Known kinds: ${known}`)
  }
  const isStorage = kind.startsWith('storage_') && kind !== normalized
  const explanation = {
    kind,
    title: isStorage ? `Storage: ${entry.title}` : entry.title,
    default_severity: entry.severity,
    what: entry.what,
    why_dangerous: entry.why,
    how_to_fix: entry.fix,
    example_sql: entry.example_sql('your_table', 'your_policy', 'public'),
    related_findings: entry.related,
  }
  const text = [
    `## ${explanation.title}`,
    `**Kind:** ${kind}`,
    `**Default severity:** ${entry.severity}`,
    '',
    `### What it means`,
    entry.what,
    '',
    `### Why it's dangerous`,
    entry.why,
    '',
    `### How to fix`,
    entry.fix,
    '',
    `### Example SQL`,
    '```sql',
    explanation.example_sql,
    '```',
    '',
    entry.related.length
      ? `### Related findings\n${entry.related.join(', ')}`
      : '',
  ]
    .filter(Boolean)
    .join('\n')
  return {
    content: [{ type: 'text', text }],
    structuredContent: explanation,
    isError: false,
  }
}

function handleGenerateFix(args) {
  const kind = args?.finding_kind
  const table = args?.table_name
  if (!kind || typeof kind !== 'string') {
    throw new Error('finding_kind is required (e.g. "rls_disabled", "permissive_true").')
  }
  if (!table || typeof table !== 'string') {
    throw new Error('table_name is required (the table the finding applies to).')
  }
  const policy = typeof args?.policy_name === 'string' ? args.policy_name : null
  const schema = typeof args?.schema === 'string' && args.schema ? args.schema : 'public'
  const normalized = normalizeFindingKind(kind)
  const entry = FINDING_KNOWLEDGE[normalized]
  if (!entry) {
    const known = Object.keys(FINDING_KNOWLEDGE).join(', ')
    throw new Error(`Unknown finding kind: "${kind}". Known kinds: ${known}`)
  }
  const sql = entry.example_sql(table, policy, schema)
  const text = [
    `-- Fix for ${kind} on ${schema}.${table}${policy ? ` (policy: ${policy})` : ''}`,
    `-- ${entry.fix}`,
    '',
    sql,
  ].join('\n')
  return {
    content: [{ type: 'text', text }],
    structuredContent: {
      kind,
      table: table,
      policy: policy || null,
      schema,
      sql,
      description: entry.fix,
    },
    isError: false,
  }
}

async function callTool(name, args) {
  try {
    if (name === 'scan_site_for_exposed_key') return await handleScanSite(args)
    if (name === 'audit_supabase_rls') return await handleAuditRls(args)
    if (name === 'get_findings') return await handleGetFindings(args)
    if (name === 'explain_finding') return handleExplainFinding(args)
    if (name === 'generate_fix') return handleGenerateFix(args)
    const monitorResult = await callMonitorTool(name, args)
    if (monitorResult) return monitorResult
    throw new Error(`Unknown tool: ${name}`)
  } catch (err) {
    return {
      content: [{ type: 'text', text: `Airlock error: ${err?.message || String(err)}` }],
      isError: true,
    }
  }
}

// ── MCP JSON-RPC over stdio (newline-delimited) ──────────────────────────────

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + '\n')
}

async function handle(msg) {
  const { id, method, params } = msg
  const isRequest = id !== undefined && id !== null

  switch (method) {
    case 'initialize':
      return {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: params?.protocolVersion || PROTOCOL_VERSION,
          capabilities: { tools: {} },
          serverInfo: SERVER_INFO,
        },
      }
    case 'tools/list':
      return { jsonrpc: '2.0', id, result: { tools: [...TOOLS, ...MONITOR_TOOLS] } }
    case 'tools/call': {
      const result = await callTool(params?.name, params?.arguments || {})
      return { jsonrpc: '2.0', id, result }
    }
    case 'ping':
      return { jsonrpc: '2.0', id, result: {} }
    case 'notifications/initialized':
    case 'notifications/cancelled':
      return null // notifications get no reply
    default:
      if (isRequest) {
        return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } }
      }
      return null
  }
}

let buf = ''
process.stdin.setEncoding('utf8')
process.stdin.on('data', (chunk) => {
  buf += chunk
  let nl
  while ((nl = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, nl).trim()
    buf = buf.slice(nl + 1)
    if (!line) continue
    let msg
    try {
      msg = JSON.parse(line)
    } catch {
      continue // ignore non-JSON lines
    }
    Promise.resolve(handle(msg))
      .then((resp) => {
        if (resp) send(resp)
      })
      .catch((err) => {
        if (msg.id !== undefined && msg.id !== null) {
          send({ jsonrpc: '2.0', id: msg.id, error: { code: -32603, message: String(err?.message || err) } })
        }
      })
  }
})
process.stdin.on('end', () => process.exit(0))

console.error('airlock-mcp running (stdio). Tools: scan_site_for_exposed_key, audit_supabase_rls, get_findings, explain_finding, generate_fix, list_monitor_projects, start_monitor_run, get_monitor_run, get_monitor_findings, get_monitor_attestation')
