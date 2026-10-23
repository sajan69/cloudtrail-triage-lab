# Implementation status

Status: active. The ingestion, synthetic data and command-line detection layers are implemented. Dashboard and evaluation remain in progress.

- [x] Python packaging, local-data ignore rules and CI configuration.
- [x] JSON/JSONL validation, normalized DuckDB storage and aggregate summary.
- [x] Atomic imports, exact deduplication and conflicting-duplicate rollback.
- [x] Seeded synthetic scenarios with separate labels and benign lookalikes.
- [x] Three explainable detections and evidence output.
- [ ] Dashboard, investigation timeline and CSV/JSON exports.
- [ ] Held-out evaluation, measured performance and reproducible end-to-end demo.
- [ ] Complete architecture/security documentation and final validation.

36 tests cover malformed data, rollback, data minimization, fixtures, rule boundaries and identity/MFA semantics. The 132-event development fixture imports once, re-imports as 132 duplicates, and produces five findings including two deliberate benign lookalikes. This is not an independent accuracy measurement.

Next: build the local evidence timeline/dashboard and safe exports, then implement a held-out evaluator with confusion counts and per-rule false positives. Document development-versus-holdout separation and shared-template limitations. Add query/ingestion measurements before making performance claims. See docs/INPUT_FORMAT.md, docs/SCENARIOS.md and docs/DETECTIONS.md.
