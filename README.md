# CloudTrail Triage Lab

[![CI](https://github.com/sajan69/cloudtrail-triage-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/sajan69/cloudtrail-triage-lab/actions/workflows/ci.yml)

A local Python/SQL toolkit for turning CloudTrail-shaped audit events into explainable findings and an investigation timeline. It validates imports, stores a minimized DuckDB projection, correlates three security signals, and provides a read-only browser dashboard and JSON/CSV exports.

It runs entirely locally and does not collect live AWS logs, verify log signatures or establish that an account is compromised.

## Quick start (Python 3.11+)

```sh
python -m venv .venv
# macOS/Linux:
. .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e .
triage demo
```

The demo runs a real local import/query/detection/export/HTTP workflow using temporary synthetic data, checks its results, and removes the temporary files. No AWS account, credentials or paid services are required.

To open the dashboard:

```sh
triage generate --out data/demo --seed 42
triage ingest data/demo/events.json --db data/demo.duckdb
triage serve --db data/demo.duckdb
```

Open the complete local URL printed by `serve`, including its fragment token. Stop with Ctrl+C. The generator requires a fresh destination directory; retain an existing fixture or choose a new directory rather than overwriting it.

## Features

- Bounded UTF-8 Records JSON/JSONL imports, explicit invalid-record handling, atomic writes, exact deduplication and conflicting-duplicate rollback.
- Normalized, data-minimized DuckDB storage; no raw request bodies, access-key fields or arbitrary payloads.
- CT001: IAM denial bursts with action diversity in a rolling five-minute window.
- CT002: explicit successful IAMUser/Root console sign-ins without MFA; unknown/federated MFA excluded.
- CT003: a different-Region Bedrock invocation after an IAM denial for the same actor/account within 15 minutes.
- Filtered UTC timelines, full finding evidence, pagination, local dashboard and bounded JSON/CSV exports.
- Seeded synthetic scenarios, reserved-seed case evaluation, integrated demo and measured local workloads.

Findings are investigation leads, not proof of compromise. Unknown actors, missing events, incomplete Region coverage, identity changes and legitimate lookalikes affect results.

## Investigation commands

```sh
triage summary --db data/demo.duckdb
triage detect --db data/demo.duckdb
triage timeline --db data/demo.duckdb --source bedrock.amazonaws.com
mkdir exports
triage export --db data/demo.duckdb --kind findings --format csv --out exports/findings.csv
```

Inputs are limited to 10 MiB and 20,000 records per file. Imports are strict by default; `--skip-invalid` skips record-validation errors but syntax errors and conflicting duplicates still abort. Exports refuse more than 10,000 records instead of silently truncating. CSV mitigates formula-like cells; JSON retains normalized values. Existing export files are never replaced.

The dashboard binds only to 127.0.0.1 and requires a per-process token for data access. It uses same-origin assets, Host/Origin checks, a restrictive Content Security Policy and text-only rendering of log values. Do not expose it as a public/multi-user service or modify its database during investigation. Real logs, databases and exports remain sensitive; keep them out of version control.

## Evaluation and measurements

```sh
triage evaluate
triage benchmark --background 1000 --repeats 3
```

Five reserved synthetic seeds cover 660 events and 65 cases. CT001 and CT002 each have 5 true positives and 5 false positives (50% precision); CT003 has 5 true positives and no false positives in this small suite. Development and reserved seeds share scenario templates, so these results do not establish real-world generalization. False positives are retained and documented.

The [evaluation guide](docs/EVALUATION.md) records the method, confusion counts, software/environment details, measured import/query times and limitations. [Machine-readable reports](docs/reports/) allow inspection without relying on summary claims. No production performance or accuracy claim is made.

## Verification

```sh
python -m unittest discover -s tests -v
triage demo
```

60 Python tests cover ingestion, data minimization, identity/MFA semantics, rolling-window boundaries, timeline filters, exports, dashboard access and evaluation. CI runs Python 3.11–3.13 plus a separate installed-package browser check for controls, downloads, mobile layout and inert HTML rendering. The browser job uploads a dashboard screenshot. See the [CI results](https://github.com/sajan69/cloudtrail-triage-lab/actions/workflows/ci.yml) for the current revision and [local browser-check instructions](docs/EVALUATION.md#integrated-checks).

## Documentation

- [Input and storage contract](docs/INPUT_FORMAT.md)
- [Detection rules and logging prerequisites](docs/DETECTIONS.md)
- [Timelines, dashboard and exports](docs/INVESTIGATION.md)
- [Scenario design and label limitations](docs/SCENARIOS.md)
- [Evaluation and measured results](docs/EVALUATION.md)
- [Architecture and security boundaries](docs/ARCHITECTURE.md)
