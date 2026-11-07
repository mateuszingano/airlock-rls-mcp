# Airlock RLS MCP — Supabase leak checks inside your AI coding agent

> Let Cursor, Claude Code, or any MCP client **check a Supabase app for leaks while it builds it.** It catches the most common vibe-coding footgun: a `service_role` key shipped to the browser, and Row Level Security that's off or wide open.

The engine is [Airlock RLS](https://github.com/mateuszingano/airlock-rls) (`npm i airlock-rls`), the CI gate for Supabase RLS. This package is a thin MCP wrapper around it.

## Ten tools

### Local (no account needed)

**`scan_site_for_exposed_key`** — give it a deployed URL. It reads the page and its JS bundles for an exposed Supabase `service_role` key (a `service_role` JWT or an `sb_secret_...` key). No database, no credentials, just the public URL. A hit means anyone who reads it bypasses **every** RLS policy. It never prints the full key.

**`audit_supabase_rls`** — give it a Postgres connection string. It fails on RLS-off tables, permissive (always-true) policies, and anon/authenticated tenant leaks. It reads **only** catalog metadata (`pg_tables`, `pg_policies`, grants), never your row data, so a read-only role is enough. Returns a human-readable summary.

**`get_findings`** — same audit as `audit_supabase_rls`, but returns machine-readable structured JSON: findings grouped by severity, severity counts, table count, allowed (waived) findings, and stats. Built for agents that need to iterate over findings, generate fixes, or build reports programmatically.

**`explain_finding`** — pure lookup, no database needed. Give it a finding `kind` string (e.g. `rls_disabled`, `permissive_true`, `cross_tenant_read_leak`) and it returns: what it means, why it's dangerous, how to fix it with example SQL, and related finding kinds. Use after `get_findings` or `audit_supabase_rls` to understand a finding before fixing it.

**`generate_fix`** — pure function, no database needed. Give it a finding `kind`, a `table_name`, and optionally a `policy_name`, and it returns the exact SQL to fix that specific finding, ready to paste into a migration file.

### Hosted Monitor (needs an API key)

These tools talk to the [Airlock Monitor](https://shipsealed.com) REST API. Get an API key from the Monitor dashboard.

**`list_monitor_projects`** — list the Supabase projects connected to your Monitor account.

**`start_monitor_run`** — start an RLS audit + DAST run on a connected project. Returns a run id to poll.

**`get_monitor_run`** — check the status of a run (queued → running → completed/failed).

**`get_monitor_findings`** — get the findings (leaks, warnings, suggested SQL fixes) from a completed run.

**`get_monitor_attestation`** — download the signed attestation (Ed25519 + SHA-256) for a completed run. Anyone can verify it at shipsealed.com/verify without an account.

## Add it to your MCP client

```json
{
  "mcpServers": {
    "airlock": {
      "command": "npx",
      "args": ["-y", "airlock-rls-mcp"]
    }
  }
}
```

That's the same block for Cursor (`~/.cursor/mcp.json`), Claude Desktop (`claude_desktop_config.json`) and other MCP clients. With Claude Code:

```bash
claude mcp add airlock -- npx -y airlock-rls-mcp
```

Then ask the agent things like *"scan https://myapp.com for an exposed Supabase key"*, *"audit the RLS on this database"*, *"explain the rls_disabled finding"*, *"generate the fix for permissive_true on my profiles table"*, or *"run a Monitor check on my project and show the findings"* and it calls the tools.

## Requirements

Node.js 18 or newer.

## Develop

```bash
npm install
npm run smoke   # starts the server and checks all tools are advertised
```

## More

Guides on Supabase RLS, a live cross-tenant demo, and the hosted Airlock Monitor (continuous checks of your live database): [shipsealed.com](https://shipsealed.com/?utm_source=readme&utm_medium=referral&utm_campaign=airlock-rls-mcp)

## License

MIT © Mateus Zingano
