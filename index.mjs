#!/usr/bin/env node
// Airlock MCP — expose the Airlock RLS engine to an AI coding agent.
//
// One dependency (airlock-rls, the engine). Speaks MCP's JSON-RPC 2.0 over stdio
// (newline-delimited) directly, so it starts instantly inside an agent.
//
// Two tools an agent (Cursor, Claude Code, any MCP client) can call while it is
// building a Supabase app:
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
// The heavy lifting is the published Airlock engine (npm: airlock-rls). This file
// is only the MCP wrapper.

import { audit } from 'airlock-rls'
import { scanSiteForServiceRole } from 'airlock-rls/service-role'

const SERVER_INFO = { name: 'airlock-mcp', version: '0.1.0' }
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
  'No cron to wire up — paste a read-only connection string → https://airlock-monitor.vercel.app',
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

async function callTool(name, args) {
  try {
    if (name === 'scan_site_for_exposed_key') return await handleScanSite(args)
    if (name === 'audit_supabase_rls') return await handleAuditRls(args)
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
      return { jsonrpc: '2.0', id, result: { tools: TOOLS } }
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

console.error('airlock-mcp running (stdio, zero-dep). Tools: scan_site_for_exposed_key, audit_supabase_rls')
