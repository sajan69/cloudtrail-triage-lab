# Architecture and security boundaries

The local workflow is: CloudTrail-shaped JSON/JSONL -> validation and normalization -> DuckDB -> detection/query functions -> CLI or loopback dashboard -> local exports. Synthetic fixture labels take a separate path into the evaluator and never enter the detector.

| Component | Responsibility |
| --- | --- |
| model.py / ingest.py | Bounded parsing, normalized schema, transactional deduplication and data minimization |
| detect.py | Three fixed, explainable signals with event-ID evidence |
| queries.py | Parameter-bound investigation filters, pagination and evidence retrieval |
| exports.py | Bounded JSON/CSV rendering, formula mitigation and exclusive file writes |
| dashboard.py / static/ | Loopback-only HTTP API and dependency-free browser interface |
| scenarios.py / evaluate.py | Reproducible labeled fixtures and case-level confusion counts |
| demo.py / benchmark.py | Integrated credential-free checks and local workload measurements |

## Boundaries and controls

- Input files are untrusted data, not executable content. The importer limits input size/record count, rejects duplicate JSON keys and stores an allowlisted field projection. It does not validate CloudTrail digest signatures.
- DuckDB opens with external access disabled, fixed schemas and parameter-bound values. Do not open third-party database binaries. Database files are not encrypted by this application; local filesystem permissions remain important.
- The dashboard accepts data requests only with a per-process token, an exact loopback Host and, when provided, the same Origin. It offers no write/upload endpoint, CORS access or arbitrary file browsing. Request logging is suppressed to avoid recording identifiers/tokens.
- Browser data uses text nodes rather than HTML interpretation. Content Security Policy permits only same-origin scripts/styles/connections and blocks framing, forms and external resources. No CDN, analytics or hosted APIs are used.
- Static assets reveal no database contents or token. Data endpoints require the token. The printed access URL can still leak through terminal access or local browser history; a trusted local user is assumed.
- Export writes refuse replacement; CSV includes formula-prefix mitigation. Exports and query results remain sensitive and should not be committed. Ignore rules do not replace data review or secret scanning.

## Operational limits

This is a bounded, single-user local investigation tool. Python's standard-library HTTP server is not a production Internet service; do not reverse-proxy it, expose it to a LAN or treat the token as multi-user authentication. Resource caps do not provide a complete denial-of-service defense against an authorized local user. Ingestion is capped per file, while multiple imports can create a larger database and increase query cost.

No live AWS collection, signature verification, account remediation, automatic alert delivery, continuous streaming or billing investigation is implemented. Identity correlation is conservative and session-specific. Missing/forged telemetry and legitimate lookalikes affect findings. A finding's severity is review priority, not confirmed impact.

The application performs no credential lookup or AWS calls. Network activity during normal investigation is limited to the local browser/HTTP server; installing dependencies is a separate setup step.
