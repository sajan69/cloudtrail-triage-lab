# CloudTrail Triage Lab

**Status: scoped; implementation has not started.**

A local portfolio project for turning CloudTrail-style audit events into an explainable investigation timeline. It combines Python/SQL data analysis, defensive security investigation and tested software engineering.

## Problem and intended users

An analyst needs to connect audit events into a useful investigation rather than inspect isolated alerts. This lab will demonstrate a reproducible workflow using synthetic events, clear detection logic and documented false positives. Suspicious activity is an investigation lead, not proof of compromise.

## Bounded MVP

1. Validate and ingest CloudTrail Records JSON or JSONL into DuckDB using Python; handle malformed input and duplicates explicitly.
2. Generate seeded synthetic datasets with scenario labels and benign lookalikes.
3. Implement three explainable detection rules: permission-probing bursts, console sign-in without MFA, and suspicious same-principal activity across regions involving AI services.
4. Provide a lightweight local dashboard with filters, an evidence timeline and CSV/JSON investigation exports.
5. Evaluate rules on held-out scenarios separately from threshold tuning. Report actual confusion counts, precision, recall and false positives.
6. Add automated tests, CI, a credential-free demo, an architecture/security guide and evidence-based resume bullet candidates.

The detection rules and thresholds will be documented and tested during implementation. Logging prerequisites and incomplete telemetry must be explicit; no blanket claim of detecting every attack is intended.

## Portfolio evidence

| Target role | Planned evidence |
| --- | --- |
| Data analyst | Data validation, SQL analysis, data quality reporting and useful visual findings |
| Security analyst | Evidence timelines, explainable detections, false-positive analysis and investigation notes |
| Software engineer | Maintainable Python modules, clear interfaces, automated tests and CI |

No performance or detection results exist yet. This repo is not resume-ready until its working demo and evaluation can be reproduced.

## Data and execution

The default demo will run locally with synthetic fixtures and no AWS account, production logs, paid APIs or cloud deployment. Real audit logs can contain sensitive identities and infrastructure details; they must never be committed. Setup commands will be added when they have been implemented and tested.

## Progress and finish line

- [x] Confirm repository access and agree a bounded scope.
- [ ] Add project scaffolding and safe local-data ignore rules.
- [ ] Implement ingestion and data-quality tests.
- [ ] Add seeded scenarios and three detection rules.
- [ ] Add dashboard, evidence timeline and exports.
- [ ] Publish held-out evaluation and reproducible demo.
- [ ] Pass CI and document limitations, resume candidates and an interview walkthrough.

A finished project must meet these criteria; it will not grow indefinitely to generate commits. Daily work targets 5–6 substantive commits when justified, with no empty or cosmetic filler commits.

## Design reference

[AWS incident-response guide for CloudTrail investigations](https://aws.amazon.com/blogs/security/incident-response-guide-for-aws-cloudtrail-investigations-part-2/) informs the proposed investigation workflow. Implementation will verify current AWS event fields and logging prerequisites against official documentation.

## Assistance

This project is being developed with an AI coding assistant under Sajan Adhikari's direction. Claims about testing, performance, deployment and personal contributions must remain verifiable.
