from contextlib import redirect_stdout
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cloudtrail_triage.cli import main
from cloudtrail_triage.detect import detect
from cloudtrail_triage.ingest import ingest_file
from cloudtrail_triage.scenarios import build_dataset
from helpers import event


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.db = self.root / "events.duckdb"

    def ingest(self, records):
        source = self.root / "events.json"
        source.write_text(json.dumps({"Records": records}))
        ingest_file(source, self.db)

    def denials(self, seconds):
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        return [event(i + 1, eventTime=(base + timedelta(seconds=value)).isoformat(),
            eventName=["CreateUser", "CreateRole", "AttachUserPolicy"][i % 3], errorCode="AccessDenied")
            for i, value in enumerate(seconds)]

    def findings(self, rule):
        return [finding for finding in detect(self.db)["findings"] if finding["rule_id"] == rule]

    def test_development_scenarios_include_expected_signals_and_benign_false_positives(self):
        document, labels = build_dataset()
        self.ingest(document["Records"])
        result = detect(self.db)
        self.assertEqual(len(result["findings"]), 5)
        hits = {}
        for case in labels["cases"]:
            ids = set(case["event_ids"])
            hits[case["case_id"]] = {f["rule_id"] for f in result["findings"] if set(f["evidence_ids"]) & ids}
            self.assertTrue(set(case["expected_rules"]) <= hits[case["case_id"]])
        self.assertEqual(hits["approved_break_glass"], {"CT002"})
        self.assertEqual(hits["authorized_permission_audit"], {"CT001"})
        for name in ["federated_signin", "mfa_unknown", "mfa_present", "failed_signin", "low_volume_denials", "single_action_retry", "planned_multi_region"]:
            self.assertEqual(hits[name], set(), name)

    def test_rolling_window_includes_exact_boundary(self):
        self.ingest(self.denials([0, 60, 120, 180, 300]))
        self.assertEqual(len(self.findings("CT001")), 1)

    def test_rolling_window_excludes_just_outside_boundary(self):
        self.ingest(self.denials([0, 60, 120, 180, 300.000001]))
        self.assertEqual(self.findings("CT001"), [])

    def test_rolling_window_is_not_fixed_five_minute_binning(self):
        self.ingest(self.denials([240, 270, 300, 330, 360]))
        self.assertEqual(len(self.findings("CT001")), 1)

    def test_overlapping_windows_merge_without_losing_evidence(self):
        records = self.denials([i * 40 for i in range(10)])
        self.ingest(records)
        findings = self.findings("CT001")
        self.assertEqual(len(findings), 1)
        self.assertEqual(set(findings[0]["evidence_ids"]), {r["eventID"] for r in records})

    def test_denial_bursts_do_not_merge_accounts_principals_or_unknown_actors(self):
        records = self.denials([0, 10, 20, 30, 40, 50])
        records[3]["recipientAccountId"] = "444455556666"
        records[4]["userIdentity"]["arn"] += "-other"
        records[5]["userIdentity"] = {}
        self.ingest(records)
        self.assertEqual(self.findings("CT001"), [])
        self.assertEqual(detect(self.db)["uncorrelatable_events"], 1)

    def test_one_action_retry_is_not_a_permission_probe_burst(self):
        records = self.denials([0, 10, 20, 30, 40, 50])
        for record in records:
            record["eventName"] = "GetRole"
        self.ingest(records)
        self.assertEqual(self.findings("CT001"), [])

    def test_console_rule_scopes_mfa_to_successful_direct_signins(self):
        records = []
        variants = [("IAMUser", "No", "Success"), ("Root", "No", "Success"),
            ("AssumedRole", "No", "Success"), ("IAMUser", None, "Success"),
            ("IAMUser", "Yes", "Success"), ("IAMUser", "No", "Failure")]
        for i, (kind, mfa, result) in enumerate(variants, 1):
            record = event(i, eventSource="signin.amazonaws.com", eventName="ConsoleLogin",
                responseElements={"ConsoleLogin": result}, additionalEventData={} if mfa is None else {"MFAUsed": mfa})
            record["userIdentity"]["type"] = kind
            records.append(record)
        self.ingest(records)
        self.assertEqual(len(self.findings("CT002")), 2)
        self.assertEqual({f["metrics"]["identity_type"] for f in self.findings("CT002")}, {"IAMUser", "Root"})

    def test_wrong_service_console_event_does_not_trigger(self):
        self.ingest([event(eventSource="ec2.amazonaws.com", eventName="ConsoleLogin",
            responseElements={"ConsoleLogin": "Success"}, additionalEventData={"MFAUsed": "No"})])
        self.assertEqual(self.findings("CT002"), [])

    def test_region_sequence_includes_exact_gap_and_selects_latest_eligible_probe(self):
        records = self.denials([0, 60])
        records[1]["awsRegion"] = "us-west-2"
        records.append(event(3, eventSource="bedrock.amazonaws.com", eventName="Converse", awsRegion="us-west-2",
            eventTime="2026-01-01T00:15:00Z"))
        self.ingest(records)
        findings = self.findings("CT003")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["evidence_ids"], [records[0]["eventID"], records[2]["eventID"]])

    def test_region_sequence_requires_time_order_and_different_region(self):
        records = self.denials([0])
        for i, (time, region) in enumerate([("2026-01-01T00:00:00Z", "us-west-2"),
            ("2026-01-01T00:01:00Z", "us-east-1"), ("2026-01-01T00:15:01Z", "us-west-2")], 2):
            records.append(event(i, eventSource="bedrock.amazonaws.com", eventName="Converse", awsRegion=region, eventTime=time))
        self.ingest(records)
        self.assertEqual(self.findings("CT003"), [])

    def test_region_sequence_excludes_different_accounts_actors_errors_and_recon(self):
        records = self.denials([0])
        base = event(2, eventSource="bedrock.amazonaws.com", eventName="Converse", awsRegion="us-west-2", eventTime="2026-01-01T00:01:00Z")
        for i, change in enumerate(["account", "actor", "error", "action"], 2):
            record = deepcopy(base); record["eventID"] = event(i)["eventID"]
            if change == "account": record["recipientAccountId"] = "444455556666"
            elif change == "actor": record["userIdentity"]["arn"] += "-other"
            elif change == "error": record["errorCode"] = "ThrottlingException"
            else: record["eventName"] = "ListFoundationModels"
            records.append(record)
        self.ingest(records)
        self.assertEqual(self.findings("CT003"), [])

    def test_detector_is_deterministic_read_only_and_cli_emits_json(self):
        document, _ = build_dataset(background=0)
        self.ingest(list(reversed(document["Records"])))
        before = self.db.read_bytes()
        expected = detect(self.db)
        self.assertEqual(expected, detect(self.db))
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["detect", "--db", str(self.db)]), 0)
        self.assertEqual(json.loads(output.getvalue()), expected)
        self.assertEqual(self.db.read_bytes(), before)
        self.assertEqual(len({f["id"] for f in expected["findings"]}), len(expected["findings"]))
