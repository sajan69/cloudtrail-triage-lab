# Synthetic scenarios

`triage generate --out data/demo --seed 42` writes CloudTrail-shaped `events.json`, equivalent `events.jsonl`, and a separate `labels.json`. The destination must be a new directory; existing data is never replaced. All generated data is synthetic, uses documentation account/address values, and requires no AWS account.

The default development fixture contains 132 events in 13 cases: three suspicious sequences, routine activity, boundary cases and benign lookalikes. The seed controls event IDs, ordering, small timestamp jitter and background Regions. Repeating the same options produces the same data. `--background` accepts 0–10,000 events; the default is 100.

## Cases

| Case | Intended behavior |
| --- | --- |
| permission_probe | Six denied IAM actions spanning three operations |
| console_without_mfa | Successful direct IAM sign-in explicitly reporting no MFA |
| cross_region_sequence | IAM denial followed by successful Bedrock activity in a different Region |
| federated_signin | A federated no-MFA field must not be interpreted as a direct IAM-user finding |
| mfa_unknown / mfa_present | Missing MFA evidence and explicitly used MFA remain distinct |
| failed_signin | Failed sign-in must not be reported as a successful no-MFA sign-in |
| low_volume_denials / single_action_retry | Below-count and below-diversity burst lookalikes |
| planned_multi_region | Routine multi-Region AI use without the preceding denial signal |
| approved_break_glass | Legitimate sign-in that deliberately resembles the no-MFA rule |
| authorized_permission_audit | Authorized permission checks that deliberately resemble a denial burst |
| routine_activity | Successful background read operations |

Labels associate event IDs with case-level judgments and expected rule IDs. They are not embedded in events or imported into the analysis database. Actor identifiers are opaque; detections must not use case names or labels as features. Cases judged benign can still produce alerts: those are false positives to report, not fixtures to remove for a better score.

## Evaluation boundary

`--split holdout` produces separate IDs and a separate time range. Keep development fixtures for debugging and any threshold decisions; reserve independent seeds and scenario variants for final evaluation. Both splits currently share the same hand-authored scenario templates. Consequently, a split alone does not establish independent real-world validation or generalization. Reserved-seed case metrics are published in [EVALUATION.md](EVALUATION.md) with this limitation. Fixtures must not be described as real attacks or verified incident logs.
