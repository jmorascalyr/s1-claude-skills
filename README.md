# s1-ai-skills

AI coding assistant skills for working with SentinelOne. Organized by agent, with shared resources that all agents reference.

## Skills

- **sentinelone-mgmt-console-api** — Query and act on a SentinelOne Management Console (threats, alerts, agents, sites, RemoteOps, Deep Visibility, Hyperautomation, etc.). Wraps the full S1 Mgmt Console API (v2.1) with a Python client, cursor-based pagination, and a searchable endpoint index.
- **sentinelone-powerquery** — Author, debug, optimize, and run SentinelOne PowerQuery (PQ) for Deep Visibility / Event Search, XDR/EDR threat hunting, STAR / Custom Detection rules, and Singularity Data Lake dashboards.

## Repository structure

```
shared/                                 ← Agent-agnostic resources (scripts, references, examples)
  sentinelone-mgmt-console-api/
    config.json.example
    scripts/                            (s1_client.py, call_endpoint.py, search_endpoints.py, purple_ai.py, call_purple.py)
    references/                         (TAG_INDEX.md, endpoint_index.json, tags/*.md, common_params.md)
    spec/                               (swagger_2_1.json)
  sentinelone-powerquery/
    references/                         (syntax, commands, functions, fields, detection-rules, pitfalls)
    examples/                           (investigations.md, detection-library.md)
.claude/                                ← Claude runtime skill definitions (plug-and-play)
  skills/
    sentinelone-mgmt-console-api/
      SKILL.md
      README.md
    sentinelone-powerquery/
      SKILL.md
.windsurf/                              ← Windsurf runtime workflows (plug-and-play)
  workflows/
    sentinelone-api.md
    sentinelone-powerquery.md
```

## Installing

### Claude Code / Cowork

This repo is already structured for plug-and-play use with project-local skills:

- `.claude/skills/sentinelone-mgmt-console-api/SKILL.md`
- `.claude/skills/sentinelone-powerquery/SKILL.md`

Open the repo in Claude Code/Cowork and invoke the skills normally.

### Windsurf

This repo is already structured for plug-and-play use with project-local workflows:

- `.windsurf/workflows/sentinelone-api.md`
- `.windsurf/workflows/sentinelone-powerquery.md`

Open the repo in Windsurf and use:

- `/sentinelone-api`
- `/sentinelone-powerquery`

## Configuration

The `sentinelone-mgmt-console-api` skill needs tenant credentials. Copy the example config and fill in your values:

```bash
cp shared/sentinelone-mgmt-console-api/config.json.example shared/sentinelone-mgmt-console-api/config.json
# edit config.json with your tenant URL and API token
```

`config.json` is gitignored — do not commit real tokens.

## Adding a new agent

To support another AI coding assistant (e.g. Cursor, Copilot):

1. Create a new top-level directory (e.g. `cursor/`)
2. Write the agent-specific instruction files, referencing `shared/` for resources
3. Update this README with installation instructions
