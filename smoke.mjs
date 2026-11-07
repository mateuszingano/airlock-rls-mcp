// Smoke test — spawns the MCP server and speaks raw MCP JSON-RPC over stdio.
// Proves: initialize handshake, both tools advertised with object schemas, and
// a tools/call round-trips (error path, no database touched). Zero deps.

import { spawn } from 'node:child_process'

const child = spawn('node', ['index.mjs'], { stdio: ['pipe', 'pipe', 'inherit'] })
const byId = new Map()
let buf = ''
child.stdout.setEncoding('utf8')
child.stdout.on('data', (d) => {
  buf += d
  let nl
  while ((nl = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, nl).trim()
    buf = buf.slice(nl + 1)
    if (!line) continue
    try {
      const msg = JSON.parse(line)
      if (msg.id !== undefined) byId.set(msg.id, msg)
    } catch {
      /* ignore */
    }
  }
})

const send = (o) => child.stdin.write(JSON.stringify(o) + '\n')
const wait = (ms) => new Promise((r) => setTimeout(r, ms))

async function waitForId(id, timeoutMs = 5000) {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    if (byId.has(id)) return byId.get(id)
    await wait(25)
  }
  throw new Error(`timeout waiting for response id=${id}`)
}

let failed = false
const check = (cond, label) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${label}`)
  if (!cond) failed = true
}

try {
  send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'smoke', version: '0' } } })
  const init = await waitForId(1)
  check(init.result?.serverInfo?.name === 'airlock-mcp', 'initialize returns serverInfo airlock-mcp')
  check(!!init.result?.capabilities?.tools, 'server advertises tools capability')

  send({ jsonrpc: '2.0', method: 'notifications/initialized' })

  send({ jsonrpc: '2.0', id: 2, method: 'tools/list' })
  const list = await waitForId(2)
  const names = (list.result?.tools || []).map((t) => t.name).sort()
  console.log('     tools:', names.join(', '))
  check(names.includes('scan_site_for_exposed_key'), 'tool scan_site_for_exposed_key advertised')
  check(names.includes('audit_supabase_rls'), 'tool audit_supabase_rls advertised')
  check(names.includes('get_findings'), 'tool get_findings advertised')
  check(names.includes('explain_finding'), 'tool explain_finding advertised')
  check(names.includes('generate_fix'), 'tool generate_fix advertised')
  check((list.result?.tools || []).every((t) => t.inputSchema?.type === 'object'), 'every tool has an object inputSchema')

  // Error-path round-trip: call audit with no db_url. Must return isError, no crash, no DB.
  send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'audit_supabase_rls', arguments: {} } })
  const call = await waitForId(3)
  check(call.result?.isError === true, 'tools/call returns isError for missing db_url')
  check(/db_url is required/i.test(call.result?.content?.[0]?.text || ''), 'error message names the missing arg')

  // get_findings error path: no db_url.
  send({ jsonrpc: '2.0', id: 10, method: 'tools/call', params: { name: 'get_findings', arguments: {} } })
  const gfErr = await waitForId(10)
  check(gfErr.result?.isError === true, 'get_findings returns isError for missing db_url')

  // explain_finding: known kind returns structured explanation.
  send({ jsonrpc: '2.0', id: 11, method: 'tools/call', params: { name: 'explain_finding', arguments: { finding_kind: 'rls_disabled' } } })
  const explain = await waitForId(11)
  check(explain.result?.isError === false, 'explain_finding succeeds for rls_disabled')
  check(/RLS Disabled/i.test(explain.result?.content?.[0]?.text || ''), 'explain_finding returns title')
  check(explain.result?.structuredContent?.kind === 'rls_disabled', 'explain_finding structuredContent has kind')

  // explain_finding: unknown kind returns isError.
  send({ jsonrpc: '2.0', id: 12, method: 'tools/call', params: { name: 'explain_finding', arguments: { finding_kind: 'nonexistent_kind' } } })
  const explainBad = await waitForId(12)
  check(explainBad.result?.isError === true, 'explain_finding returns isError for unknown kind')

  // generate_fix: returns SQL for a known kind + table.
  send({ jsonrpc: '2.0', id: 13, method: 'tools/call', params: { name: 'generate_fix', arguments: { finding_kind: 'rls_disabled', table_name: 'profiles' } } })
  const fix = await waitForId(13)
  check(fix.result?.isError === false, 'generate_fix succeeds for rls_disabled + profiles')
  check(/ENABLE ROW LEVEL SECURITY/i.test(fix.result?.content?.[0]?.text || ''), 'generate_fix returns ALTER TABLE ... ENABLE RLS')
  check(fix.result?.structuredContent?.table === 'profiles', 'generate_fix structuredContent has table')

  // generate_fix: with policy_name.
  send({ jsonrpc: '2.0', id: 14, method: 'tools/call', params: { name: 'generate_fix', arguments: { finding_kind: 'permissive_true', table_name: 'notes', policy_name: 'read_all' } } })
  const fixPol = await waitForId(14)
  check(fixPol.result?.isError === false, 'generate_fix succeeds with policy_name')
  check(/read_all/.test(fixPol.result?.content?.[0]?.text || ''), 'generate_fix SQL includes the policy name')

  // generate_fix: unknown kind returns isError.
  send({ jsonrpc: '2.0', id: 15, method: 'tools/call', params: { name: 'generate_fix', arguments: { finding_kind: 'fake_kind', table_name: 'x' } } })
  const fixBad = await waitForId(15)
  check(fixBad.result?.isError === true, 'generate_fix returns isError for unknown kind')

  // Unknown method must yield a JSON-RPC error, not a crash.
  send({ jsonrpc: '2.0', id: 4, method: 'does/not/exist' })
  const bad = await waitForId(4)
  check(bad.error?.code === -32601, 'unknown method returns -32601')
} catch (err) {
  console.error('smoke failed:', err)
  failed = true
} finally {
  child.stdin.end()
  child.kill()
}

console.log(failed ? '\nSMOKE: FAIL' : '\nSMOKE: PASS')
process.exit(failed ? 1 : 0)
