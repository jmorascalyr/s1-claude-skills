# sentinelone-mgmt-console-api (Claude skill)

A Claude skill wrapping the SentinelOne Management Console API (Swagger 2.1, 781 operations, 113 tags) plus a natural-language wrapper over the console's undocumented Purple AI GraphQL endpoint.

## Install

Use this repo as-is in Claude Code/Cowork (project-local skills under `.claude/skills/`).

If you need to copy into a global skills directory, copy this folder and `shared/` together:

```bash
# Copy the skill instruction file
cp -r .claude/skills/sentinelone-mgmt-console-api ~/.claude/skills/

# The skill references resources in shared/ — copy or symlink them alongside
cp -r shared ~/.claude/skills/sentinelone-mgmt-console-api/
```

## Configure

Edit `shared/sentinelone-mgmt-console-api/config.json` (copy from `config.json.example`) and fill in:

```json
{
  "base_url": "https://YOURTENANT.sentinelone.net",
  "api_token": "eyJrIjoi..."
}
```

Or set env vars instead: `S1_BASE_URL`, `S1_API_TOKEN`.

Create the API token in the S1 console → Settings → Users → Service Users → Generate API Token. Scope it to the minimum permissions needed.

## Quick test

```bash
pip install requests
python shared/sentinelone-mgmt-console-api/scripts/s1_client.py
```

Should print the first 5 accounts.

Purple AI natural-language query (requires tenant entitlement for Purple AI):

```bash
python shared/sentinelone-mgmt-console-api/scripts/call_purple.py "show powershell.exe outbound connections in the last 24h, top 10"
```

Purple AI answers questions about SDL telemetry (process/network/file events, indicators, ingested logs). It does *not* answer questions about console entities (alerts, threats, agents) — those go through the REST endpoints.

## Layout

- `.claude/skills/sentinelone-mgmt-console-api/SKILL.md` — instructions Claude reads when the skill triggers
- `shared/sentinelone-mgmt-console-api/config.json` — credentials (gitignored; `config.json.example` is the template)
- `shared/sentinelone-mgmt-console-api/scripts/s1_client.py` — REST client (auth, retries, cursor pagination)
- `shared/sentinelone-mgmt-console-api/scripts/call_endpoint.py` — REST CLI wrapper
- `shared/sentinelone-mgmt-console-api/scripts/search_endpoints.py` — keyword search over the endpoint index
- `shared/sentinelone-mgmt-console-api/scripts/purple_ai.py` — Purple AI GraphQL wrapper (`purple_query()`, `PurpleAIError`)
- `shared/sentinelone-mgmt-console-api/scripts/call_purple.py` — Purple AI CLI wrapper
- `shared/sentinelone-mgmt-console-api/references/` — endpoint index + per-tag reference docs
- `shared/sentinelone-mgmt-console-api/spec/` — the original Swagger JSON
