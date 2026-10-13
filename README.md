# Airlock RLS MCP — Supabase leak checks inside your AI coding agent

> Let Cursor, Claude Code, or any MCP client **check a Supabase app for leaks while it builds it.** It catches the most common vibe-coding footgun: a `service_role` key shipped to the browser, and Row Level Security that's off or wide open.

The engine is [Airlock RLS](https://github.com/mateuszingano/airlock-rls) (`npm i airlock-rls`), the CI gate for Supabase RLS. This package is a thin MCP wrapper around it.

## Two tools

**`scan_site_for_exposed_key`** — give it a deployed URL. It reads the page and its JS bundles for an exposed Supabase `service_role` key (a `service_role` JWT or an `sb_secret_...` key). No database, no credentials, just the public URL. A hit means anyone who reads it bypasses **every** RLS policy. It never prints the full key.

**`audit_supabase_rls`** — give it a Postgres connection string. It fails on RLS-off tables, permissive (always-true) policies, and anon/authenticated tenant leaks. It reads **only** catalog metadata (`pg_tables`, `pg_policies`, grants), never your row data, so a read-only role is enough.

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

Then ask the agent things like *"scan https://myapp.com for an exposed Supabase key"* or *"audit the RLS on this database"* and it calls the tools.

## Requirements

Node.js 18 or newer.

## Develop

```bash
npm install
npm run smoke   # starts the server and checks both tools are advertised
```

## More

Guides on Supabase RLS, a live cross-tenant demo, and the hosted Airlock Monitor (continuous checks of your live database): [shipsealed.com](https://shipsealed.com)

## License

MIT © Mateus Zingano
