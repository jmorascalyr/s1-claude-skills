---
description: Author, debug, optimize, and run SentinelOne PowerQuery (PQ) for Deep Visibility, XDR/EDR threat hunting, STAR / Custom Detection rules, and Singularity Data Lake dashboards
---

# SentinelOne PowerQuery

Use this workflow when the user wants to author, debug, optimize, explain, or run a SentinelOne PowerQuery (PQ). Trigger on: PowerQuery, PQ, Event Search, Deep Visibility, S1QL, SDL, STAR rule, Custom Detection rule, PowerQuery Alert; on queries using fields like `event.type`, `src.process.*`, `tgt.file.*`, `indicator.*`, `agent.uuid`; on pipes like `| group`, `| filter`, `| let`, `| join`, `| parse`, `| columns`, `| compare`, `| top`, `| union`, `| lookup`, `| savelookup`, `| dataset`. Also trigger when asked to hunt a TTP, IOC, behavior, or alert pattern — even casually ("find powershell reaching out to the internet", "write a detection for lsass access").

This is SentinelOne's pipeline query language for security telemetry — NOT Microsoft Power Query / M / Excel and NOT Splunk SPL.

The reference files live at `shared/sentinelone-powerquery/`.

## Workflow

1. **Clarify the intent** if it's ambiguous (time range, data view, what the output should look like). A good PQ is scoped — not everything needs to be hunted over 30 days.

2. **Draft the query** following the grammar and rules below. Favor `filter | group | sort | limit | columns` as the default shape.

3. **Run it against the tenant.** TODO: MCP integration pending. For now, the user can paste the query into the S1 console Event Search, or use the Purple AI scripts from `shared/sentinelone-mgmt-console-api/scripts/` to execute DV queries programmatically.

4. **Iterate**: if the query errors or returns wrong results, read the error, fix, rerun. If the query returns nothing, that is a legitimate result — check the time range and filter logic first.

5. **Explain the result briefly** and cite fields you relied on. If you used a non-obvious pattern (subquery, `savelookup`, `transpose`, `compare`), explain why.

## The grammar in one page

```
initial-filter-expression
| command
| command
| …
```

**Initial filter** (everything before the first `|`) is the only place where `* contains "x"` and `* matches "regex"` multi-field search works. It can be empty — start the query with `|` and it is treated as "all events".

**Commands** (each starts with `|`):
- `filter expr` — keep matching rows
- `columns f1, "Renamed f2"=f2, …` — select, rename, compute output columns (creates a new record set)
- `let f = expr, …` — add computed fields without discarding existing ones
- `group agg(x), name2=agg2(y) by f1, "grouped name"=f2` — aggregate (creates a new record set)
- `sort +f1, -f2` — `-` = descending
- `limit N` — truncate
- `parse "…$field$…" from srcField` — extract fields from unstructured text
- `lookup col, … from tableName by key=expr` — join against a config data table
- `dataset 'config://datatables/<name>'` — read a lookup table as the source
- `savelookup 'tableName'[, 'merge']` — persist result as a reusable lookup
- `| [inner|left|outer|sql inner|sql left|sql outer] join (q1), (q2), … on k1, a.x = b.y` — correlate subqueries
- `| union (q1), (q2), …` — merge heterogeneous result sets (up to 10)
- `| transpose colName on keyCol, …` — pivot (must be LAST command)
- `| compare [name=]timeshift('-1w')` — re-run shifted in time (must be LAST command)
- `| top K agg(x) by f1, f2` — probabilistic top-N
- `| nolimit` — raise row cap to 3 GB (slow; never use in Dashboards or PowerQuery Alerts)

**Expressions** use: `=`/`==`/`!=`, `<`/`<=`/`>`/`>=`, `&&`/`||`/`!` (or `AND`/`OR`/`NOT`), ternary `a ? b : c`, arithmetic `+ - * / %`, and these text operators:

| Operator | Meaning |
|---|---|
| `x contains 'sub'` | substring (case-insensitive) — also `contains ('a','b','c')` for OR |
| `x contains:matchcase 'Sub'` | case-sensitive substring |
| `x matches 'regex'` | regex (case-insensitive, double-escape) |
| `x matches:matchcase '…'` | case-sensitive regex |
| `x in ('a','b',123,true)` | exact equals any; case-sensitive; `in:anycase` for insensitive; does NOT match null |
| `x = *` | field is present/non-null |
| `!(x = *)` | field is null/missing |
| `$"regex"` | shorthand for `message matches "regex"` (initial filter only) |
| `#shortcut = 'value'` | pre-defined multi-field shortcut (`#ip`, `#hash`, `#name`, `#cmdline`, `#storylineid`, `#username`) |

## The most important rules

These are where queries go wrong. Follow them strictly.

1. **`*` is NOT a valid standalone initial filter.** `* | limit 5` returns 500. Use `| limit 5` (empty initial filter) or target a real field like `event.type=*`.
2. **Double-escape regex almost everywhere.** `src.process.cmdline matches "\\d+"`. The only exception is the `$"…"` shorthand.
3. **After `columns` or `group`, previous fields are gone.** Carry fields through explicitly: `group ct=count(), host=any(endpoint.name) by src.process.storyline.id`.
4. **Subqueries can't go after `group`, `sort`, or `limit`.** The subquery must produce the column named in the `in (...)` expression (via `columns` or `group`).
5. **`compare` and `transpose` must be the LAST command.**
6. **`join` must start with a pipe.** `| join (…), (…) on x` — without the `|`, "join" is interpreted as a search term.
7. **`null` behaves like false in boolean context.** `filter x = null` works after the field is defined; before then, use `!(x = *)`.
8. **`contains` is case-insensitive by default; `in` is case-sensitive by default.** `:matchcase` / `:anycase` suffixes reverse this.
9. **Filter early, group narrow.** Push filters above the first pipe when possible.
10. **Alerts and Dashboards have tighter limits.** PowerQuery Alert: 1,000 rows / 1 MB RAM. No `nolimit` in dashboard panels.
11. **Shortcut fields (`#cmdline`, etc.) don't work reliably as initial filters.** Prefer explicit field names.
12. **Prefer `min_by`/`max_by` over `first`/`last`.** `first(x)` fails on many tenants; `min_by(x, timestamp)` always works.
13. **Use `p50`/`p95`/`p99`, not `percentile(x, N)`.** The latter isn't a real function.
14. **`filter x = null` before `x` is computed returns 500.** Use `filter !(x = *)` until after a `let`/`join`/`lookup` has produced `x`.

## When to use join vs union vs subquery

- **Subquery** (`field in (inner | columns field)`) — single-field "is this value in that set" filtering. Simplest and usually fastest.
- **Join** — multi-field correlation where you need to bring columns from both sides into one row.
- **Union** — heterogeneous result sets stacked as rows, possibly with rename/unification.

## Writing detection rules vs ad-hoc hunts

Detection rules (STAR / Custom Detection / PowerQuery Alert) are more constrained:
- Intermediate and output tables: ≤ 1,000 rows, ≤ 1 MB RAM
- No `nolimit`, usually no `compare` or `transpose`
- One row per finding, with stable columns (`agent.uuid`, `endpoint.name`, `src.process.storyline.id`, `timestamp`)
- Initial filter must be as specific as possible

For detection patterns, read `shared/sentinelone-powerquery/references/detection-rules.md`.

## A minimal but realistic example

Hunt: PowerShell that made an outbound connection to a non-RFC1918 IP in the last 24 hours, with command line.

```
src.process.name contains 'powershell' dst.ip.address = *
| let is_private = net_rfc1918(dst.ip.address)
| filter is_private = false
| group hits = count(),
        ips  = array_agg_distinct(dst.ip.address, 20),
        cmdline = any(src.process.cmdline)
  by endpoint.name, src.process.storyline.id
| sort -hits
| limit 50
```

## Reference files (read as needed, not upfront)

- `shared/sentinelone-powerquery/references/syntax-and-operators.md` — full operator reference, identifier rules, regex dialect, date/time formats
- `shared/sentinelone-powerquery/references/commands-reference.md` — deep dive on every command (join, subqueries, lookup, transpose, compare, top, nolimit)
- `shared/sentinelone-powerquery/references/functions-reference.md` — all built-in functions: string, numeric, JSON, network, aggregate, array, geolocation, timestamp
- `shared/sentinelone-powerquery/references/fields-and-schema.md` — common EDR/XDR field paths and OCSF conventions
- `shared/sentinelone-powerquery/references/detection-rules.md` — PowerQuery Alert / STAR / Custom Detection rule authoring guide
- `shared/sentinelone-powerquery/references/pitfalls.md` — curated list of common failures and fixes

## Examples library (read when a hunt matches)

- `shared/sentinelone-powerquery/examples/investigations.md` — ready-to-run investigation queries (PowerShell outbound, lateral movement, LOLBins, credential access, etc.)
- `shared/sentinelone-powerquery/examples/detection-library.md` — PQ bodies for STAR / Custom Detection / PowerQuery Alerts with MITRE technique mappings
