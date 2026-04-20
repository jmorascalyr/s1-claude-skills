# ai-siem Parser Catalog — Always Check First

Before writing a parser from scratch, check the **`Sentinel-One/ai-siem`** GitHub repo. It is the canonical open catalog of community + marketplace SDL parsers maintained by S1 and partners, and a large fraction of the sources a prospect will ask about already have a working parser there.

- Repo root: <https://github.com/Sentinel-One/ai-siem>
- Parsers tree: <https://github.com/Sentinel-One/ai-siem/tree/main/parsers>
- File extension: every parser is a single `.conf` file in augmented-JSON (same format as `/logParsers/<name>` on the tenant).

## Workflow

**Step 0** of authoring any parser:

1. Search ai-siem for the vendor or product name (e.g. "juniper", "okta", "fortigate", "palo alto", "corelight", "abnormal").
2. If a parser exists, download it. It becomes your starting point.
3. Diff what the user asked for against what the catalog parser emits — add the four required default attributes if missing, shift to OCSF field names if the parser uses vendor-native, bump `metadata.version`.
4. Validate end-to-end via `sentinelone-sdl-api` (the usual loop).

Only write from scratch when no catalog parser matches.

## Repo layout (as of 2026-04)

Two buckets:

- `parsers/marketplace/<name>-latest/` — supported, version-tagged parsers shipped in the S1 Marketplace (cloudflare, fortinet fortigate, aws rds, corelight-conn, palo alto networks firewall, and ~60 others).
- `parsers/community/<name>-<version>/` — community-contributed, less polished, more varied in style (abnormal_security_logs, juniper_networks_logs, okta_ocsf_logs, cisco_asa, pfsense_firewall, etc.).

Each folder typically contains:

- The `.conf` parser file.
- A `samples/` directory with raw log lines (use these as your validation input — real vendor samples are hard to synthesize correctly).
- Sometimes a `README.md` with field mapping or known-issues.

## Useful reference parsers by shape

When you need a template for a specific log shape, start from one of these:

- **JSON-per-line, dottedJson envelope** — `community/json_generic/`. Two-line parser, pure `${parse=dottedJson}$ repeat:true`.
- **JSON with nested KV body** — `community/json_nested_kv/`. Outer JSON then repeating KV sub-format against a nested `message` field.
- **CEF over syslog** — `community/generic_access/` header + KV extension cascade.
- **LEEF** — `community/leef_template/`. Timestamp prefix + repeating KV patterns.
- **Positional CSV with complex mapping** — `marketplace/palo_alto_networks_firewall-latest/`. Uses `{parse=commaSeparatedvalues}` + `skipNumericConversion: true` + `attr[N]` positional indexing in mappings.
- **Multi-format progressive extraction** — `community/pfsense_firewall/`. Frame → subtype → protocol-specific cascade; uses `discard: true` to drop IPv6 and a final-format rewrite for computed fields.
- **Multiple per-format OCSF class tagging** — `community/abnormal_security_logs/` and `community/juniper_networks_logs/`. Each format has its own `attributes: { class_uid, ... }` so one parser emits multiple OCSF classes.
- **Gron-capture + mappings template** — `community/PARSER_TEMPLATE/`. The "capture everything via `$unmapped.{parse=gron}$`, then rename/copy/cast in mappings" idiom. Great scaffold when the source is JSON-ish and you want all rewrites in one block.
- **Format-id sentinel for mapping fan-out** — `marketplace/awsrdslogs-latest/`. Names each format (`id: "mySqlErrorLog"`, `id: "mySqlGeneralLog"`, `id: "postgresqlLog"`) and then fans mapping predicates out via `predicate: "mySqlErrorLog='true'"` — elegant way to apply different OCSF class rules to different sub-shapes of the same source.
- **Plural-grouped mapping syntax** — `marketplace/corelight-conn-latest/` and `marketplace/awsrdslogs-latest/`. `renames: [...], copies: [...], constants: [...]` arrays inside a single mapping entry (see `mappers.md` §"Two equivalent syntaxes").
- **Rewrite-first legacy style (pre-mappings)** — `community/okta_ocsf_logs/`. Pure `rewrites:` on the format (no `mappings` block). Still works — useful when you need a minimal diff from a published parser.

## Style variance to expect (and tolerate)

The repo predates the current mapper engine, and not every author hand-converges on the same style. When copying from the catalog:

- **Two mapping syntaxes coexist.** Older parsers use `version: 0` with plural grouped arrays (`renames`, `copies`, `constants`). Newer tenant-validated parsers use `version: 1` with `transformations: [{<op>: {...}}]`. Both work. Pick one and stick to it within a parser — do not mix.
- **`class_uid` as string vs integer.** Both appear. String form (`"4001"`) is tolerated by the ingest pipeline, integer (`4001`) is the OCSF spec. Prefer integers in new work.
- **Predicate equality `=` vs `==`.** Marketplace parsers use `=`. Tenant `computeFields` and the newer `version:1` mappings style use `==`. If one fails validation, try the other — the engine error message will tell you. (See `mappers.md` for the split.)
- **Required default attributes often missing.** The catalog predates the current four-attribute requirement (`metadata.version`, `dataSource.category/name/vendor`). Add them to the top-level `attributes:` block on every parser you ship, even when copying verbatim from the catalog.

## Quick recipe for downloading a parser

The repo is public, so `curl` + the GitHub raw URL works without auth:

```bash
# Find the folder you want:
#   https://github.com/Sentinel-One/ai-siem/tree/main/parsers/<bucket>/<name>-<version>/
# Then raw-download the .conf:

curl -sSL \
  https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/parsers/community/juniper_networks_logs-latest/juniper_networks_logs.conf \
  -o juniper_networks_logs.conf
```

If you are inside Cowork without network access to github raw, use `WebFetch` against the github.com tree URL and extract filenames from the rendered listing, then fetch individual `raw.githubusercontent.com` URLs.

## When the catalog is wrong

Common issues in catalog parsers that you should fix before shipping:

1. **Missing the four required default attributes** — add them.
2. **Emitting vendor-native field names instead of OCSF** — add a `mappings` block that renames them, or update capture names directly (see `ocsf-mapping.md`).
3. **Stray `class_uid` as a string** — change to integer.
4. **Using deprecated `rewrites:` on the format for what should be `mappings`** — modern parsers do this in `mappings`. Prefer `mappings` for anything that would run after field capture. Leave `rewrites:` for timestamp normalization (the one thing it still does well).
5. **Hard-coded tenant-specific attributes** — e.g. `"site.id": "..."` in pfSense. Strip these before shipping to a different tenant.
6. **Predicates that match a vendor-native field after that field has already been renamed to OCSF.** Order matters inside `transformations: [...]`.
