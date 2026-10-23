"""Reproducible synthetic CloudTrail-shaped data; labels are never event fields."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import random
from uuid import NAMESPACE_URL, uuid5

from .model import InputError

ACCOUNT = "111122223333"


def build_dataset(*, seed: int = 42, split: str = "development", background: int = 100):
    if type(seed) is not int or not 0 <= seed < 2 ** 32:
        raise InputError("invalid_seed")
    if split not in {"development", "holdout"}:
        raise InputError("invalid_split")
    if type(background) is not int or not 0 <= background <= 10000:
        raise InputError("invalid_background_count")
    rng = random.Random(seed)
    base = datetime(2026, 1, 1 if split == "development" else 15, tzinfo=timezone.utc)
    records, cases = [], []

    def case(name, expected, description, specifications, *, kind="IAMUser"):
        number = len(cases)
        actor = uuid5(NAMESPACE_URL, f"triage:{split}:{seed}:{name}").hex[:12]
        arn = (f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-{actor}/session"
            if kind == "AssumedRole" else f"arn:aws:iam::{ACCOUNT}:user/synthetic-{actor}")
        ids = []
        for index, spec in enumerate(specifications):
            offset, source, action, region, error, login, mfa = spec
            identifier = str(uuid5(NAMESPACE_URL, f"triage:{split}:{seed}:{name}:{index}"))
            timestamp = base + timedelta(hours=number, seconds=offset + rng.randrange(3))
            record = {"eventVersion": "1.11", "eventID": identifier,
                "eventTime": timestamp.isoformat().replace("+00:00", "Z"),
                "eventSource": source, "eventName": action, "awsRegion": region,
                "recipientAccountId": ACCOUNT, "sourceIPAddress": "192.0.2.10",
                "userIdentity": {"type": kind, "arn": arn, "accountId": ACCOUNT},
                "eventCategory": "Management"}
            if error is not None:
                record["errorCode"] = error
            if login is not None:
                record["responseElements"] = {"ConsoleLogin": login}
            if mfa is not None:
                record["additionalEventData"] = {"MFAUsed": mfa}
            ids.append(identifier); records.append(record)
        cases.append({"case_id": name, "expected_rules": expected,
            "disposition": "suspicious" if expected else "benign", "description": description, "event_ids": ids})

    def denial(index, action=None):
        return (index * 20, "iam.amazonaws.com", action or ["CreateUser", "AttachUserPolicy", "CreateRole"][index % 3],
            "us-east-1", "AccessDenied", None, None)

    def console(mfa, result="Success"):
        return [(0, "signin.amazonaws.com", "ConsoleLogin", "us-east-1", None, result, mfa)]

    case("permission_probe", ["CT001"], "Rapid attempts against several IAM actions.", [denial(i) for i in range(6)])
    case("console_without_mfa", ["CT002"], "Successful direct IAM sign-in explicitly reporting no MFA.", console("No"))
    case("cross_region_sequence", ["CT003"], "IAM denial followed by a successful AI invocation in another Region.",
        [denial(0), (180, "bedrock.amazonaws.com", "Converse", "us-west-2", None, None, None)], kind="AssumedRole")
    case("federated_signin", [], "Federated MFA cannot be inferred from MFAUsed=No.", console("No"), kind="AssumedRole")
    case("mfa_unknown", [], "Missing MFA evidence remains unknown.", console(None))
    case("mfa_present", [], "Direct sign-in reports MFA used.", console("Yes"))
    case("failed_signin", [], "Failed sign-in is not a successful no-MFA sign-in.", console("No", "Failure"))
    case("low_volume_denials", [], "Four denials fall below the burst count threshold.", [denial(i) for i in range(4)])
    case("single_action_retry", [], "Repeated rejection of one operation lacks action diversity.", [denial(i, "GetRole") for i in range(6)])
    case("planned_multi_region", [], "Routine multi-Region invocations have no preceding IAM-denial signal.",
        [(0, "bedrock.amazonaws.com", "Converse", "us-east-1", None, None, None),
         (180, "bedrock.amazonaws.com", "Converse", "us-west-2", None, None, None)])
    # These legitimate workflows intentionally resemble the positive rule patterns.
    # They must remain in later evaluation rather than being silently filtered out.
    case("approved_break_glass", [], "Authorized emergency direct sign-in without MFA; expected CT002 false positive.", console("No"))
    case("authorized_permission_audit", [], "Approved IAM permission checks; expected CT001 false positive.", [denial(i) for i in range(6)])
    background_specs = [(i * 30, "ec2.amazonaws.com", "DescribeInstances", rng.choice(["us-east-1", "us-west-2"]), None, None, None)
        for i in range(background)]
    if background_specs:
        case("routine_activity", [], "Routine successful read operations.", background_specs, kind="AssumedRole")
    rng.shuffle(records)
    labels = {"schema_version": 1, "synthetic": True, "seed": seed, "split": split,
        "cases": cases, "notes": ["Rule-pattern labels are synthetic scenario judgments, not verified incidents.",
            "Benign lookalikes intentionally produce some alerts; report their false positives.",
            "Do not pass this label manifest to the detector or use holdout labels to tune thresholds."]}
    return {"Records": records}, labels


def write_dataset(directory: Path, **options):
    document, labels = build_dataset(**options)
    # A fresh output directory prevents accidental replacement of local evidence.
    directory.mkdir(parents=True, exist_ok=False)
    with (directory / "events.json").open("x", encoding="utf8") as stream:
        json.dump(document, stream, indent=2, sort_keys=True)
    with (directory / "events.jsonl").open("x", encoding="utf8") as stream:
        for event in document["Records"]:
            stream.write(json.dumps(event, sort_keys=True) + "\n")
    with (directory / "labels.json").open("x", encoding="utf8") as stream:
        json.dump(labels, stream, indent=2, sort_keys=True)
    return {"synthetic": True, "events": len(document["Records"]), "cases": len(labels["cases"]), "split": labels["split"]}
