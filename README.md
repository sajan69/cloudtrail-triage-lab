# CloudTrail Triage Lab

**Status: active development.** JSON/JSONL ingestion and DuckDB summaries are implemented. Reproducible synthetic fixtures are available; detection, dashboard and evaluation work is in progress.

A local tool for turning CloudTrail-style audit events into an explainable investigation timeline. It combines Python/SQL data analysis, defensive security investigation and tested software engineering.

## Problem and intended users

An analyst needs to connect audit events into a useful investigation rather than inspect isolated alerts. This lab will demonstrate a reproducible workflow using synthetic events, clear detection logic and documented false positives. Suspicious activity is an investigation lead, not proof of compromise.

## Bounded MVP

1. Validate and ingest CloudTrail Records JSON or JSONL into DuckDB using Python; handle malformed input and duplicates explicitly.
2. Generate seeded synthetic datasets with scenario labels and benign lookalikes.
3. Implement three explainable detection rules: permission-probing bursts, console sign-in without MFA, and suspicious same-principal activity across regions involving AI services.
4. Provide a lightweight local dashboard with filters, an evidence timeline and CSV/JSON investigation exports.
5. Evaluate rules on held-out scenarios separately from threshold tuning. Report actual confusion counts, precision, recall and false positives.
6. Add automated tests, CI, a credential-free demo, architecture and security documentation.

The detection rules and thresholds will be documented and tested during implementation. Logging prerequisites and incomplete telemetry must be explicit; no blanket claim of detecting every attack is intended.

No performance or detection results exist yet. See [implementation status](ROADMAP.md) and the [input contract](docs/INPUT_FORMAT.md).

## Data and execution

Ingestion runs locally with no AWS account, paid APIs or cloud deployment. Real audit logs and normalized databases contain sensitive identities and infrastructure details; keep them out of version control.

## Install and use (Python 3.11+)

```sh
python -m venv .venv
# macOS/Linux:
. .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e .
mkdir data
triage ingest path/to/events.json --db data/events.duckdb
triage summary --db data/events.duckdb
python -m unittest discover -s tests -v
```

## Synthetic fixture

```sh
triage generate --out data/demo --seed 42
triage ingest data/demo/events.json --db data/demo.duckdb
triage summary --db data/demo.duckdb
# Re-importing the equivalent JSONL adds no new events:
triage ingest data/demo/events.jsonl --db data/demo.duckdb
```

The default fixture has 132 synthetic events in 13 labeled cases. Labels remain separate from events and include benign lookalikes that should remain visible in later false-positive analysis. The generator requires a fresh output directory. See [scenario design](docs/SCENARIOS.md).

Inputs are limited to 10 MiB and 20,000 records. Imports are strict by default; `--skip-invalid` skips schema-invalid records, while syntax errors or conflicting duplicates still abort. An exact re-import is a no-op with duplicate counts. Errors report codes without echoing input values. See [supported fields and atomicity](docs/INPUT_FORMAT.md).

## Progress and finish line

- [x] Confirm repository access and agree a bounded scope.
- [x] Add project scaffolding and safe local-data ignore rules.
- [x] Implement ingestion and data-quality tests.
- [ ] Add seeded scenarios and three detection rules.
- [ ] Add dashboard, evidence timeline and exports.
- [ ] Publish held-out evaluation and reproducible demo.
- [ ] Pass CI and document setup, architecture, evaluation methods and limitations.

## Design reference

[AWS incident-response guide for CloudTrail investigations](https://aws.amazon.com/blogs/security/incident-response-guide-for-aws-cloudtrail-investigations-part-2/) informs the proposed investigation workflow. Implementation will verify current AWS event fields and logging prerequisites against official documentation.

