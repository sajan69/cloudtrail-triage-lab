import csv
import io
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from cloudtrail_triage.detect import detect
from cloudtrail_triage.exports import csv_cell, render_export, write_export
from cloudtrail_triage.ingest import ingest_file
from cloudtrail_triage.model import InputError, normalize
from cloudtrail_triage.queries import Filters
from cloudtrail_triage.scenarios import build_dataset
from helpers import event


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.db = self.root / "events.duckdb"
        document, _ = build_dataset()
        source = self.root / "input.json"; source.write_text(json.dumps(document)); ingest_file(source, self.db)

    def test_json_export_preserves_data_and_exact_filters(self):
        export = render_export(self.db, filters=Filters(source="bedrock.amazonaws.com"))
        result = json.loads(export.content)
        self.assertEqual(export.total, 3)
        self.assertEqual(result["total"], 3)
        self.assertTrue(all(r["event_source"] == "bedrock.amazonaws.com" for r in result["records"]))

    def test_csv_uses_one_quoted_cell_and_neutralizes_formula_prefixes(self):
        for value in ["=1+1", " +SUM(1)", "-1+2", "@cmd", "\t=1", "\uff1d1+1"]:
            self.assertEqual(csv_cell(value), "'" + value)
        self.assertEqual(csv_cell('ordinary,"text"'), 'ordinary,"text"')
        rows = list(csv.reader(io.StringIO(render_export(self.db, output_format="csv").content.decode())))
        self.assertEqual(len(rows), 133)
        self.assertTrue(all(len(row) == len(rows[0]) for row in rows))

    def test_findings_filters_and_evidence_exports_are_complete(self):
        result = json.loads(render_export(self.db, kind="findings", rule="CT002").content)
        self.assertEqual(result["total"], 2)
        finding = detect(self.db)["findings"][0]
        evidence = json.loads(render_export(self.db, kind="evidence", finding_id=finding["id"]).content)
        self.assertEqual({r["event_id"] for r in evidence["records"]}, set(finding["evidence_ids"]))
        self.assertEqual(evidence["finding"], finding)

    def test_exports_refuse_silent_truncation_and_ambiguous_filters(self):
        with patch("cloudtrail_triage.exports.MAX_EXPORT", 2):
            with self.assertRaisesRegex(InputError, "export_too_large"):
                render_export(self.db)
        for options in [{"kind": "findings", "filters": Filters(region="us-east-1")},
                {"kind": "evidence", "finding_id": "ct-" + "0" * 20, "filters": Filters(source="x")},
                {"kind": "events", "rule": "CT001"}]:
            with self.subTest(options=options), self.assertRaises(InputError): render_export(self.db, **options)

    def test_new_files_are_private_and_existing_files_or_symlinks_are_not_replaced(self):
        target = self.root / "report.json"; export = render_export(self.db)
        write_export(target, export)
        if os.name == "posix": self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError): write_export(target, export)
        link = self.root / "link.json"
        if os.name == "posix":
            link.symlink_to(target)
            with self.assertRaises(FileExistsError): write_export(link, export)
        self.assertEqual(target.read_bytes(), export.content)

    def test_unpaired_unicode_surrogates_are_rejected_before_storage(self):
        with self.assertRaises(InputError): normalize(event(eventName="\ud800"))
