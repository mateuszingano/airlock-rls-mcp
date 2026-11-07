// Airlock Monitor — hosted API tools for the MCP server.
//
// These tools talk to the Airlock Monitor REST API (future). They let an AI
// coding agent list projects, trigger runs, read findings and download signed
// attestations without leaving the editor.
//
// The API routes are designed but NOT yet deployed — this module is the
// client-side contract so the MCP wrapper is ready when the server ships.

const DEFAULT_BASE = 'https://app.shipsealed.com'

async function apiCall(method, path, { apiKey, baseUrl, body } = {}) {
  const base = (baseUrl || DEFAULT_BASE).replace(/\/$/, '')
  const url = `${base}${path}`
  const headers = {
    Authorization: `Bearer ${apiKey}`,
    'Content-Type': 'application/json',
  }
  const res = await fetch(url, {
    method,
    headers,
    ...(body ? { body: JSON.stringify(body) } : {}),
  })
  const text = await res.text()
  let data
  try {
    data = JSON.parse(text)
  } catch {
    data = { raw: text }
  }
  if (!res.ok) {
    const msg = data?.error || data?.message || `HTTP ${res.status}`
    throw new Error(`Monitor API ${method} ${path} → ${msg}`)
  }
  return data
}

// ── Tool definitions (MCP schema) ───────────────────────────────────────────

const API_KEY_PROP = {
  type: 'string',
  description: 'Airlock Monitor API key (starts with amk_).',
}
const BASE_URL_PROP = {
  type: 'string',
  description: `Base URL of the Monitor instance (default: ${DEFAULT_BASE}).`,
}

export const MONITOR_TOOLS = [
  {
    name: 'list_monitor_projects',
    description:
      'List the Supabase projects connected to your Airlock Monitor account. ' +
      'Returns project id, label, and last-run timestamp for each.',
    inputSchema: {
      type: 'object',
      properties: {
        api_key: API_KEY_PROP,
        base_url: BASE_URL_PROP,
      },
      required: ['api_key'],
    },
  },
  {
    name: 'start_monitor_run',
    description:
      'Start an Airlock Monitor run (RLS audit + DAST) on a connected project. ' +
      'Returns the run id and initial status. Poll with get_monitor_run.',
    inputSchema: {
      type: 'object',
      properties: {
        api_key: API_KEY_PROP,
        project_id: {
          type: 'string',
          description: 'The project id to run against (from list_monitor_projects).',
        },
        base_url: BASE_URL_PROP,
      },
      required: ['api_key', 'project_id'],
    },
  },
  {
    name: 'get_monitor_run',
    description:
      'Get the status and summary of an Airlock Monitor run. ' +
      'Status is one of: queued, running, completed, failed.',
    inputSchema: {
      type: 'object',
      properties: {
        api_key: API_KEY_PROP,
        run_id: {
          type: 'string',
          description: 'The run id (from start_monitor_run).',
        },
        base_url: BASE_URL_PROP,
      },
      required: ['api_key', 'run_id'],
    },
  },
  {
    name: 'get_monitor_findings',
    description:
      'Get the findings (leaks, warnings) from a completed Airlock Monitor run. ' +
      'Each finding has kind, severity, object, detail and a suggested SQL fix.',
    inputSchema: {
      type: 'object',
      properties: {
        api_key: API_KEY_PROP,
        run_id: {
          type: 'string',
          description: 'The run id of a completed run.',
        },
        base_url: BASE_URL_PROP,
      },
      required: ['api_key', 'run_id'],
    },
  },
  {
    name: 'get_monitor_attestation',
    description:
      'Download the signed attestation (Ed25519) for a completed run. ' +
      'Returns the canonical JSON report, its SHA-256 hash, and the signature. ' +
      'Anyone can verify it at shipsealed.com/verify without an account.',
    inputSchema: {
      type: 'object',
      properties: {
        api_key: API_KEY_PROP,
        run_id: {
          type: 'string',
          description: 'The run id of a completed run.',
        },
        base_url: BASE_URL_PROP,
      },
      required: ['api_key', 'run_id'],
    },
  },
]

// ── Handlers ────────────────────────────────────────────────────────────────

async function handleListProjects(args) {
  const data = await apiCall('GET', '/api/v1/projects', {
    apiKey: args.api_key,
    baseUrl: args.base_url,
  })
  const projects = Array.isArray(data) ? data : data.projects || []
  const lines = projects.length
    ? projects.map((p) => `• ${p.label || p.id} (id: ${p.id}, last run: ${p.last_run_at || 'never'})`).join('\n')
    : 'No projects connected. Add one at the Monitor dashboard.'
  return {
    content: [{ type: 'text', text: `${projects.length} project(s):\n\n${lines}` }],
    structuredContent: { projects },
  }
}

async function handleStartRun(args) {
  const data = await apiCall('POST', '/api/v1/runs', {
    apiKey: args.api_key,
    baseUrl: args.base_url,
    body: { project_id: args.project_id },
  })
  return {
    content: [
      {
        type: 'text',
        text: `Run started: ${data.id || data.run_id}\nStatus: ${data.status || 'queued'}\n\nPoll with get_monitor_run to check progress.`,
      },
    ],
    structuredContent: data,
  }
}

async function handleGetRun(args) {
  const data = await apiCall('GET', `/api/v1/runs/${encodeURIComponent(args.run_id)}`, {
    apiKey: args.api_key,
    baseUrl: args.base_url,
  })
  const status = data.status || 'unknown'
  const summary =
    status === 'completed'
      ? `Completed: ${data.problems ?? '?'} problem(s), ${data.warnings ?? '?'} warning(s). ${data.passed ? 'PASSED' : 'FAILED'}.`
      : `Status: ${status}`
  return {
    content: [{ type: 'text', text: summary }],
    structuredContent: data,
  }
}

async function handleGetFindings(args) {
  const data = await apiCall('GET', `/api/v1/runs/${encodeURIComponent(args.run_id)}/findings`, {
    apiKey: args.api_key,
    baseUrl: args.base_url,
  })
  const findings = Array.isArray(data) ? data : data.findings || []
  const fails = findings.filter((f) => f.severity === 'fail')
  const warns = findings.filter((f) => f.severity === 'warn')
  const lines = []
  if (fails.length) {
    lines.push(`✗ ${fails.length} problem(s):`)
    for (const f of fails) lines.push(`   ✗ [${f.kind}] ${f.object} — ${f.detail}`)
  }
  if (warns.length) {
    lines.push(`! ${warns.length} warning(s):`)
    for (const f of warns) lines.push(`   ! [${f.kind}] ${f.object} — ${f.detail}`)
  }
  if (!fails.length && !warns.length) lines.push('✓ No findings — sealed.')
  return {
    content: [{ type: 'text', text: lines.join('\n') }],
    structuredContent: { findings },
  }
}

async function handleGetAttestation(args) {
  const data = await apiCall('GET', `/api/v1/runs/${encodeURIComponent(args.run_id)}/attestation`, {
    apiKey: args.api_key,
    baseUrl: args.base_url,
  })
  const lines = [
    `Airlock Attestation — Run ${args.run_id}`,
    '',
    `SHA-256: ${data.sha256 || '(not yet signed)'}`,
    `Ed25519 signature: ${data.signature || '(unsigned)'}`,
    '',
    data.verify_url ? `Verify: ${data.verify_url}` : 'Verify at shipsealed.com/verify',
  ]
  return {
    content: [{ type: 'text', text: lines.join('\n') }],
    structuredContent: data,
  }
}

export async function callMonitorTool(name, args) {
  if (!args?.api_key) throw new Error('api_key is required for Monitor tools.')
  switch (name) {
    case 'list_monitor_projects':
      return await handleListProjects(args)
    case 'start_monitor_run':
      return await handleStartRun(args)
    case 'get_monitor_run':
      return await handleGetRun(args)
    case 'get_monitor_findings':
      return await handleGetFindings(args)
    case 'get_monitor_attestation':
      return await handleGetAttestation(args)
    default:
      return null
  }
}
