# Implementation status

Status: complete for the bounded local investigation workflow.

- [x] Python packaging, local-data ignore rules and CI configuration.
- [x] Bounded JSON/JSONL validation, normalized DuckDB storage and summaries.
- [x] Atomic imports, exact deduplication and conflicting-duplicate rollback.
- [x] Seeded scenarios with separate labels and benign lookalikes.
- [x] Three explainable detection rules with event-ID evidence.
- [x] Filtered UTC timelines, pagination and full finding evidence.
- [x] Token-protected loopback dashboard, responsive controls and downloads.
- [x] Bounded JSON/CSV exports with exclusive writes and formula mitigation.
- [x] Reserved-seed evaluation, measured workloads and integrated local demo.
- [x] Architecture, security, setup and limitation documentation.
- [x] 60 local Python tests and real-browser interaction checks.

CI checks the current revision on Python 3.11/3.12/3.13 and installs the built package for a separate browser regression job. Consult the CI badge/results before treating a revision as validated.

The default development fixture has 132 synthetic events and five findings, including two deliberate benign lookalikes. Reserved-seed evaluation and local timing samples are recorded in docs/reports/ and explained in docs/EVALUATION.md.

Live AWS collection, signature verification, multi-user/public hosting, automatic response and production-scale detection are outside this scope. Additional real-world datasets and independent scenario designs would be required for broader detection claims.
