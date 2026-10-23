# Implementation status

Status: active. The command-line ingestion layer is implemented; investigation features are in progress.

- [x] Python packaging, local-data ignore rules and CI configuration.
- [x] JSON/JSONL validation, normalized DuckDB storage and aggregate summary.
- [x] Atomic imports, exact deduplication and conflicting-duplicate rollback.
- [ ] Seeded synthetic scenarios with separate labels and benign lookalikes.
- [ ] Three explainable detections and evidence output.
- [ ] Dashboard, investigation timeline and CSV/JSON exports.
- [ ] Held-out evaluation, measured performance and reproducible end-to-end demo.
- [ ] Complete architecture/security documentation and final validation.

The input layer has 16 tests covering malformed data, idempotence, rollback, identity isolation and data minimization. No detection or performance results exist yet. See docs/INPUT_FORMAT.md for the supported input subset and limitations.
