---
description: Query or act on a SentinelOne Management Console — threats, alerts, agents, sites, RemoteOps, Deep Visibility, Hyperautomation, Purple AI, or any S1 Mgmt API resource
---

# SentinelOne Management Console API

Use this workflow whenever the user wants to query or act on a SentinelOne Management Console. Trigger on mentions of "SentinelOne", "S1", "S1 console", "Singularity", "Purple AI", `/web/api/v2.1/...`, S1 agent IDs, threat IDs, site IDs, account IDs, or requests like "list my endpoints", "get threats from the last 24h", "isolate an endpoint", "disconnect agent", "run RemoteOps script", "pull DV query results", or "ask Purple AI a natural-language question".

The resources live at `shared/sentinelone-mgmt-console-api/` and wrap the full S1 Mgmt Console API (781 operations across 113 tags, spec v2.1) with a Python client, cursor-based pagination, and a searchable endpoint index.

## Setup — verify credentials first

1. Check that `shared/sentinelone-mgmt-console-api/config.json` exists and is not still the placeholder template. If it contains `<your-tenant>` or `<PASTE_YOUR_API_TOKEN_HERE>`, stop and ask the user to fill it in.

```json
{
  "base_url": "https://REPLACE-ME.sentinelone.net",
  "api_token": "REPLACE_WITH_YOUR_API_TOKEN"
}
```

Environment variables override the file: `S1_BASE_URL`, `S1_API_TOKEN`, `S1_VERIFY_TLS`.

## Workflow

2. **Find the right endpoint.** Run `search_endpoints.py` with a keyword matching the user's intent:

```bash
python shared/sentinelone-mgmt-console-api/scripts/search_endpoints.py "isolate"
```

This returns method + path + tag + summary. Narrow with `--tag` if needed (e.g. `--tag Threats`, `--tag Agents`, `--tag Sites`).

3. **Read the per-tag reference.** Open the matching file at `shared/sentinelone-mgmt-console-api/references/tags/<Tag>.md` (tag names listed in `shared/sentinelone-mgmt-console-api/references/TAG_INDEX.md`). Only read the tag file(s) relevant to the current task — do not read them all.

4. **Call the endpoint.** For one-off calls:

```bash
python shared/sentinelone-mgmt-console-api/scripts/call_endpoint.py GET /web/api/v2.1/agents --param limit=5
```

For anything that needs loops, joins, or transforms, import `S1Client` from `shared/sentinelone-mgmt-console-api/scripts/s1_client.py` in a Python script:

```python
import sys
sys.path.insert(0, "shared/sentinelone-mgmt-console-api/scripts")
from s1_client import S1Client, S1APIError

c = S1Client()

# single page
r = c.get("/web/api/v2.1/threats", params={"limit": 100, "resolved": False})

# full iteration (handles cursor-based pagination automatically)
for threat in c.iter_items("/web/api/v2.1/threats", params={"limit": 200}):
    ...

# action endpoint
c.post("/web/api/v2.1/agents/actions/disconnect", json_body={"filter": {"ids": ["AGENT_ID"]}})
```

5. **Paginate correctly.** S1 list endpoints use cursor-based pagination. The client's `paginate()` and `iter_items()` handle this automatically — prefer them over manual `skip`/`limit` math, which caps at 1000 items.

6. **Summarize the result for the user.** Don't dump raw JSON unless asked. Prefer a short prose summary plus a table or CSV/XLSX if the volume warrants.

## Purple AI — natural-language query

Purple AI answers questions about SDL telemetry (process events, network events, file events, indicators, ingested third-party logs). It does NOT answer questions about console entities (alerts, threats, agents, sites, policies) — use the REST endpoints for those.

```bash
python shared/sentinelone-mgmt-console-api/scripts/call_purple.py "show powershell.exe outbound connections, top 10"
python shared/sentinelone-mgmt-console-api/scripts/call_purple.py --selector CLOUD --hours 48 "show s3 downloads by user"
python shared/sentinelone-mgmt-console-api/scripts/call_purple.py --json "..."   # machine-readable
python shared/sentinelone-mgmt-console-api/scripts/call_purple.py --raw  "..."   # full GraphQL response
```

Or in Python:

```python
import sys
sys.path.insert(0, "shared/sentinelone-mgmt-console-api/scripts")
from s1_client import S1Client
from purple_ai import purple_query, PurpleAIError

c = S1Client()
try:
    r = purple_query(c, "Show powershell.exe processes making outbound connections in the last 24h, top 10.", view_selector="EDR", hours=24)
except PurpleAIError as e:
    print(f"purple error: {e} (type={e.error_type})")
else:
    print(r["message"])            # natural-language answer
    print(r["power_query"])        # generated PQ (may be None)
    print(r["suggested_questions"])
```

## Destructive actions — ALWAYS confirm first

Many endpoints are destructive: disconnect/reconnect agent, uninstall, isolate, shutdown, decommission, script execution via RemoteOps, policy changes, user mutations, account/site deletion.

Before firing any `POST`/`PUT`/`DELETE` that affects agents, policies, or tenant config:
- Summarize exactly what will happen (endpoint, filter, estimated scope)
- Run the matching `GET` with `countOnly=true` first to show the blast radius
- Get explicit user confirmation before proceeding

A 200 response on a wrong filter can isolate thousands of endpoints — there is no undo on many of these.

## Authentication notes

The API uses header auth: `Authorization: ApiToken <token>`. The client injects this automatically. If a 403 comes back, the token lacks the required scope — the fix is a new token (not a code change). Surface this clearly to the user.

## Rate limits

The client retries automatically on 429 and 5xx with exponential backoff (max 30s). For bulk operations, prefer a single filtered action endpoint (`/agents/actions/...`) over a loop of per-ID calls.

## Reference files (read as needed)

- `shared/sentinelone-mgmt-console-api/references/TAG_INDEX.md` — table of all 113 tags with file pointers and op counts
- `shared/sentinelone-mgmt-console-api/references/endpoint_index.json` — compact machine-readable index
- `shared/sentinelone-mgmt-console-api/references/tags/<Tag>.md` — per-tag parameter reference
- `shared/sentinelone-mgmt-console-api/references/common_params.md` — shared query params and pagination pattern
- `shared/sentinelone-mgmt-console-api/spec/swagger_2_1.json` — full Swagger spec (14 MB, use only when per-tag reference is insufficient)

## Common high-value workflows

- **Threat triage** — `GET /threats` filtered by `createdAt__gte` + `resolved=false`; enrich with agent details from `/agents?ids=...`
- **Endpoint isolation** — find agent IDs (`/agents` with name/IP filter), confirm count, `POST /agents/actions/disconnect`
- **Hunt across DV** — `POST /dv/init-query` → poll `/dv/query-status/{queryId}` → `GET /dv/events`
- **Natural-language hunt via Purple AI** — `call_purple.py "..."` → review the generated PQ → execute via DV/PowerQuery
- **Site/Group inventory** — `/sites`, `/groups`, `/accounts`
- **Bulk action audit** — `/activities` filtered by `activityTypes` and `createdAt__gte`
