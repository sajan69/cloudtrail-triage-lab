# Input and storage contract

The importer accepts UTF-8 CloudTrail files with a top-level `Records` array, or one event object per non-empty JSONL line. JSONL is selected by `.jsonl` extension or `--format jsonl`. Bare arrays, empty inputs, duplicate JSON keys, non-finite JSON numbers and invalid UTF-8 are rejected. Files are limited to 10 MiB and 20,000 records; this is bounded local batch ingestion, not a streaming collector. Gzip and CloudTrail LookupEvents response envelopes are not supported.

## Required fields

- `eventID`: UUID; normalized to its canonical representation.
- `eventTime`: ISO date/time with an explicit timezone; normalized to UTC.
- `eventSource`, `eventName`, `awsRegion`: bounded non-empty strings without control characters.
- An identifiable 12-digit recipient account, using `recipientAccountId` or falling back to `userIdentity.accountId`. Records that lack both are rejected rather than merged into an unknown account.

The importer validates this subset, not the full CloudTrail schema. Unknown extra fields are ignored. A record without an actor identifier is retained and counted as uncorrelatable; it must not be grouped with other unknown actors.

Identity correlation uses the full ARN, otherwise `principalId`, otherwise an Identity Center identity-store/user tuple. It does not merge assumed-role sessions by role name. Correlation is always additionally scoped to the recipient account. These choices can miss activity when identifier representations or sessions change.

MFA is three-valued: `additionalEventData.MFAUsed` of `Yes` or `No` becomes true or false; missing/unrecognized values remain unknown. Upstream federation MFA cannot be inferred from this field. `responseElements.ConsoleLogin` is retained separately from general API errors.

## Atomicity and duplicates

By default, any invalid record aborts before the database is opened. `--skip-invalid` explicitly skips record-validation errors and reports their ordinal/code, with details capped at 25 issues. JSON syntax/encoding errors still abort the whole file. JSONL syntax errors identify the physical line; validation errors identify the non-empty record ordinal.

The stored key is `(recipient account, eventID)`. Re-importing an identical normalized event is a counted no-op. A duplicate key with a different normalized fingerprint aborts and rolls back every insert in the current batch, even with `--skip-invalid`. Fingerprints cover retained normalized fields only, so changes to discarded payload fields are not detected. Input and uncorrelatable counts describe valid/invalid input records, including repeats; `summary` describes stored unique events.

Only a new database or this tool's version-1 database is accepted. Do not open third-party database files. DuckDB external file/network access is disabled for analysis connections, and input values are bound as SQL parameters. A transaction protects event writes; creating a new database can leave an empty initialized database if a later import conflict occurs.

## Data handling

Storage is an allowlisted projection: event/account/time, actor identifier/type, service/action/region, source address, error code, console result and MFA state. Access-key fields, raw request/response bodies, user agents and arbitrary extra fields are not stored. The projection still contains sensitive identity and infrastructure information; keep databases and exports local and access-controlled. Ignore rules are a convenience, not a secret scanner.

This tool does not verify CloudTrail digest signatures or establish the authenticity/completeness of supplied logs. Forged or missing events affect every downstream result. No AWS credentials, API calls, remote collection or cloud resources are involved in importing local files.

## References

- [CloudTrail record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)
- [CloudTrail userIdentity](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html)
- [Console sign-in fields and federation caveats](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html)
