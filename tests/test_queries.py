from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest

from cloudtrail_triage.detect import detect
from cloudtrail_triage.ingest import ingest_file
from cloudtrail_triage.model import InputError
from cloudtrail_triage.queries import Filters, timeline, evidence, overview
from cloudtrail_triage.scenarios import build_dataset


class QueryTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.db = self.root / "events.duckdb"
        document, _ = build_dataset()
        source = self.root / "events.json"; source.write_text(json.dumps(document))
        ingest_file(source, self.db)

    def test_pagination_is_complete_ordered_and_has_no_overlap(self):
        a = timeline(self.db, limit=100); b = timeline(self.db, limit=100, offset=100)
        self.assertEqual((a["total"], len(a["events"]), len(b["events"])), (132, 100, 32))
        ids = [r["event_id"] for r in a["events"] + b["events"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(timeline(self.db, offset=999)["events"], [])

    def test_bound_filters_are_exact_and_not_sql_expressions(self):
        result = timeline(self.db, Filters(source="bedrock.amazonaws.com", region="us-west-2"))
        self.assertEqual(result["total"], 2)
        self.assertEqual(timeline(self.db, Filters(principal="' OR 1=1 --"))["total"], 0)
        self.assertEqual(timeline(self.db, Filters(account="444455556666"))["total"], 0)

    def test_time_filters_normalize_offsets_and_include_endpoints(self):
        event = timeline(self.db, limit=1)["events"][0]
        result = timeline(self.db, Filters(started_at=event["event_time"], ended_at=event["event_time"]))
        self.assertEqual(result["events"][0]["event_id"], event["event_id"])

    def test_invalid_filters_and_pagination_fail_explicitly(self):
        for options in [{"account": "wrong"}, {"started_at": "2026-01-01"}, {"principal": "x\n"},
                {"started_at": "2026-02-01T00:00:00Z", "ended_at": "2026-01-01T00:00:00Z"}]:
            with self.subTest(options=options), self.assertRaises(InputError): Filters(**options)
        for options in [{"limit": 0}, {"limit": 1001}, {"limit": True}, {"offset": -1}]:
            with self.subTest(options=options), self.assertRaises(InputError): timeline(self.db, **options)

    def test_evidence_matches_finding_ids_and_ignores_unrelated_events(self):
        for finding in detect(self.db)["findings"]:
            result = evidence(self.db, finding["id"], limit=1000)
            self.assertEqual({r["event_id"] for r in result["events"]}, set(finding["evidence_ids"]))
            self.assertTrue(all(r["principal"] == finding["principal"] for r in result["events"]))
        with self.assertRaisesRegex(InputError, "finding_not_found"):
            evidence(self.db, "ct-" + "0" * 20)

    def test_overview_and_timeline_leave_database_unchanged(self):
        before = self.db.read_bytes(); result = overview(self.db)
        self.assertEqual(result["events"], 132)
        self.assertEqual(result["accounts_available"], ["111122223333"])
        timeline(self.db)
        self.assertEqual(self.db.read_bytes(), before)
