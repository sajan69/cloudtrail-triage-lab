# Timelines, dashboard and exports

## Read-only timeline

```sh
triage timeline --db data/demo.duckdb --source bedrock.amazonaws.com --limit 100
triage timeline --db data/demo.duckdb --from 2026-01-01T00:00:00Z --until 2026-01-02T00:00:00Z
```

Filters are exact account, full actor identifier, Region and service matches, with inclusive timezone-aware time bounds. Values are SQL-bound parameters. Pages contain at most 1,000 events (100 by default), a total count and an offset. Ordering is UTC time, recipient account and event ID. Unknown actors remain null and are never combined into a synthetic identity.

## Dashboard

```sh
triage serve --db data/demo.duckdb
```

Open the complete URL printed in the terminal, including its fragment token. The process binds only to `127.0.0.1` and creates a new access token each time it starts. The token is kept in the browser fragment and sent as a request header, rather than a query parameter. Do not share the URL. Stop the process with Ctrl+C. `--port 0` selects an available local port.

The dashboard shows stored-event counts, filtered findings, an event timeline and the full evidence for a selected finding. Account, actor and time filters affect findings and events. Service/Region affect the event timeline only; rule/priority affect findings only. Evidence pages retain the full selected finding's context rather than applying unrelated timeline filters. Option lists are capped at 200 distinct values; exact identifiers can still be queried through the CLI.

Do not import into the database while investigating it. Queries and findings are recomputed from read-only connections, not a distributed snapshot; a changing database can invalidate a selected finding. Export count checks detect some changes but are not a transactional multi-query snapshot.

## Export files

```sh
mkdir exports
triage export --db data/demo.duckdb --kind events --format json --out exports/events.json
triage export --db data/demo.duckdb --kind findings --rule CT002 --format csv --out exports/findings.csv
# Use an ID returned by triage detect:
triage export --db data/demo.duckdb --kind evidence --finding-id ct-REPLACE_WITH_FINDING_ID --out exports/evidence.json
```

The placeholder above must be replaced with an actual finding ID. The dashboard also provides JSON/CSV download buttons. CLI writes create new files exclusively, with mode 0600 on POSIX; existing files and symlinks are refused. The parent directory must already exist. Windows access rights depend on the directory/user ACL.

Exports refuse more than 10,000 records instead of silently truncating; use event filters to reduce scope. Findings support account/actor/time/rule/priority filters, but not service/Region filters because those can remove a finding's context. Evidence export takes only a finding ID and retains its finding metadata in JSON.

CSV quotes every cell and prefixes formula-like values with an apostrophe, including leading-whitespace and common full-width variants. This intentionally changes those CSV cell values. JSON preserves the normalized values and should be used for machine processing. Spreadsheet applications and re-saving can change how protections are interpreted; CSV output is not an authenticity guarantee. See [OWASP CSV Injection](https://community.owasp.org/attacks/CSV_Injection).

Exports still contain sensitive account, identity, IP and infrastructure information. They are minimized analytical projections, not original forensic log records. Protect the files, verify source integrity separately and retain original evidence through an appropriate process.
