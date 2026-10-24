# Detection rules and evidence

`triage detect --db data/demo.duckdb` reads the normalized database and writes JSON findings to stdout. It never reads `labels.json` and does not alter the database. Results include rule ID, priority, recipient account, actor, UTC time range, event IDs, reason and rule metrics. Finding IDs are deterministic hashes of the rule, actor/account and evidence IDs; they can change as evidence grows.

## CT001 — IAM permission-denial burst

At least five denied IAM operations across at least three distinct action names within an inclusive rolling five-minute window. Supported denial codes are AccessDenied, AccessDeniedException, UnauthorizedOperation and Client.UnauthorizedOperation. SQL windows are partitioned by account and full actor identifier; missing actors are excluded. This is not fixed five-minute binning.

Overlapping qualifying windows merge into one episode, preserving the matching denial event IDs. An episode can span longer than five minutes; its metrics describe peak counts inside individual five-minute windows. Counts of denials and distinct actions can peak at different anchors. A long episode does not imply all its events occurred in one window.

Expected false positives include authorized permission audits and deployment troubleshooting. Repeated rejection of only one operation does not qualify. Other services' denied operations are outside this rule's current scope.

## CT002 — Successful direct console sign-in without MFA

Requires `signin.amazonaws.com`, ConsoleLogin, explicit `responseElements.ConsoleLogin=Success`, `additionalEventData.MFAUsed=No`, no error code, an actor identifier and identity type IAMUser or Root. Root findings receive high priority; IAMUser findings receive medium priority.

Missing MFA is unknown. Federated/assumed-role sign-ins are excluded because the no-MFA field does not establish whether an upstream identity provider required MFA. Authorized emergency access can still trigger this rule. Region is not interpreted as the user's physical location.

## CT003 — Cross-Region AI invocation after an IAM denial

An IAM denial precedes an invocation event with no error code in a different Region, for the same recipient account and actor, within 15 minutes inclusive. Supported invocation names are Converse, ConverseStream, InvokeModel and InvokeModelWithResponseStream under `bedrock.amazonaws.com`. The predecessor must be strictly earlier; equal timestamps do not establish ordering. The most recent eligible different-Region denial is retained as evidence.

Each qualifying invocation produces one finding with the preceding denial and invocation IDs. This is a temporal association, not proof of credential theft, a causal chain or incurred costs. Approved cross-Region testing after permission checks can trigger it. Different assumed-role sessions are not joined automatically, and reconnaissance-only calls do not qualify.

## Logging coverage and limitations

The rules see only the imported projection. Missing accounts/invalid records, unknown actors, changes in identity representation, incomplete time ranges and omitted Regions affect coverage. No findings does not imply no compromise. Severity is a review priority, not a verified incident classification.

Check the current event configuration for every service/action. AWS currently documents the four CT003 invocation operations as management events for the Bedrock Runtime endpoint. Other operations, including agent invocations, can require explicitly enabled data-event selectors; they are not supported by CT003. Bedrock Mantle has separate logging guidance. Do not assume default event history contains every AI-service operation.

## Development fixture and evaluation status

The seed-42 development fixture contains 132 synthetic events. It produces five findings: two CT001, two CT002 and one CT003. Three correspond to the suspicious scenario templates; the other two are deliberately benign permission-audit and emergency-access lookalikes. These are reproducible development checks, not a held-out accuracy estimate. The dashboard, exports, reserved-seed case metrics and local measurements are documented in [INVESTIGATION.md](INVESTIGATION.md) and [EVALUATION.md](EVALUATION.md). The reserved seeds share templates and do not constitute independent real-world validation.

## Primary references (reviewed 24 October 2026)

- [CloudTrail record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)
- [Console sign-in fields and federated identity caveats](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html)
- [CloudTrail identity semantics](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html)
- [Bedrock CloudTrail management/data event coverage](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html)
- [CloudTrail investigation workflow](https://aws.amazon.com/blogs/security/incident-response-guide-for-aws-cloudtrail-investigations-part-2/)
