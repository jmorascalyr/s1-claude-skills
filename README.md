# claude-skills

Claude skills for working with SentinelOne. Each subfolder is a standalone skill with its own `SKILL.md` that Claude will read when triggered.

## Skills

- **[sentinelone-mgmt-console-api](./sentinelone-mgmt-console-api/)** — Query and act on a SentinelOne Management Console (threats, alerts, agents, sites, RemoteOps, Deep Visibility, Hyperautomation, etc.). Wraps the full S1 Mgmt Console API (v2.1) with a Python client, cursor-based pagination, and a searchable endpoint index.
- **[sentinelone-powerquery](./sentinelone-powerquery/)** — Author, debug, optimize, and run SentinelOne PowerQuery (PQ) for Deep Visibility / Event Search, XDR/EDR threat hunting, STAR / Custom Detection rules, and Singularity Data Lake dashboards.
- **[sentinelone-sdl-api](./sentinelone-sdl-api/)** — Read and write the SentinelOne Singularity Data Lake (SDL) API: ingest events (`uploadLogs`, `addEvents`), run queries (`query`, `powerQuery`, `facetQuery`, `timeseriesQuery`, `numericQuery`), and manage configuration files (`listFiles`, `getFile`, `putFile`) — parsers, dashboards, alerts, lookups, datatables. Ships with a Python client, CLI, and an end-to-end smoke test.
- **[sentinelone-sdl-log-parser](./sentinelone-sdl-log-parser/)** — Author, edit, debug, and validate SentinelOne Singularity Data Lake (SDL) log parsers — the augmented-JSON definitions at `/logParsers/` that extract fields from raw log text before ingestion. **Maps to OCSF by default:** every parser emits Open Cybersecurity Schema Framework field names (`src_endpoint.ip`, `actor.user.email_addr`, `file.hashes[].value`, …) so downstream PowerQuery hunts, STAR rules, dashboards, and Marketplace content work out of the box across vendors. Covers CEF, syslog, JSON, key=value, CSV, and multi-line formats with strategy templates, the ai-siem catalog recipe, and end-to-end validation (putFile → uploadLogs → query) via the `sentinelone-sdl-api` skill.

  How it works: Claude reads the raw log sample, picks a strategy (alias a built-in parser, single-line format with named-regex patterns, repeating key/value catch-all, JSON envelope with `{parse=json}`, multi-line `lineGroupers`, or a `gron` + `mappings` block for full OCSF restructuring), then drafts a parser that either captures directly into OCSF dotted names or captures vendor-native fields and renames them via `mappings`. Every parser ships the four required default attributes (`metadata.version`, `dataSource.category`, `dataSource.vendor`, `class_uid`/`class_name`), is deployed to `/logParsers/` via `putFile`, exercised with a sample via `uploadLogs`, and confirmed by querying the parsed OCSF fields back out — so the skill never reports done until the live ingest path works.

## Installing

Drop a skill folder into your Claude skills directory (for Claude Code / Cowork, typically `~/.claude/skills/`). Claude will pick it up on next session.
OR
Clone and zip the folder, upload the skill to Claude Cowork. Note: the sentinelone-mgmt-console-api and sentinelone-sdl-api need a valid config.json - ensure you use it responsibly with an RO token, plan and validate actions before executing any changes. 

## Windsurf

This repo includes Windsurf workflow files in `.windsurf/workflows/`. Each workflow is a thin pointer that directs Cascade to read the canonical `SKILL.md` and reference docs in the matching skill folder — no duplicated content.

- `sentinelone-api.md` — Management Console API (agents, threats, alerts, sites, Purple AI, UAM).
- `sentinelone-powerquery.md` — PowerQuery authoring, debugging, and detection rules.
- `sentinelone-sdl-api.md` — Singularity Data Lake API (ingest, query, config files).
- `sentinelone-sdl-log-parser.md` — SDL log parser authoring with OCSF mapping.

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
