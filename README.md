# claude-skills

Claude skills for working with SentinelOne. Each subfolder is a standalone skill with its own `SKILL.md` that Claude will read when triggered.

## Skills

- **[sentinelone-mgmt-console-api](./sentinelone-mgmt-console-api/)** — Query and act on a SentinelOne Management Console (threats, alerts, agents, sites, RemoteOps, Deep Visibility, Hyperautomation, etc.). Wraps the full S1 Mgmt Console API (v2.1) with a Python client, cursor-based pagination, and a searchable endpoint index.
- **[sentinelone-powerquery](./sentinelone-powerquery/)** — Author, debug, optimize, and run SentinelOne PowerQuery (PQ) for Deep Visibility / Event Search, XDR/EDR threat hunting, STAR / Custom Detection rules, and Singularity Data Lake dashboards.
- **[sentinelone-sdl-api](./sentinelone-sdl-api/)** — Read and write the SentinelOne Singularity Data Lake (SDL) API: ingest events (`uploadLogs`, `addEvents`), run queries (`query`, `powerQuery`, `facetQuery`, `timeseriesQuery`, `numericQuery`), and manage configuration files (`listFiles`, `getFile`, `putFile`) — parsers, dashboards, alerts, lookups, datatables. Ships with a Python client, CLI, and an end-to-end smoke test.

## Installing

Drop a skill folder into your Claude skills directory (for Claude Code / Cowork, typically `~/.claude/skills/`). Claude will pick it up on next session.
OR
Clone and zip the folder, upload the skill to Claude Cowork. Note: the sentinelone-mgmt-console-api and sentinelone-sdl-api need a valid config.json - ensure you use it responsibly with an RO token, plan and validate actions before executing any changes. 

## Configuration

`sentinelone-mgmt-console-api` and `sentinelone-sdl-api` both need tenant credentials. Copy each example config and fill in your values:

```bash
cd sentinelone-mgmt-console-api
cp config.json.example config.json
# edit config.json with your tenant URL and API token

cd ../sentinelone-sdl-api
cp config.json.example config.json
# edit config.json with your tenant URL and SDL API key(s)
```

`config.json` is gitignored — do not commit real tokens.
