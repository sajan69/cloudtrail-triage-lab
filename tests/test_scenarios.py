import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cloudtrail_triage.ingest import ingest_file, summarize
from cloudtrail_triage.model import normalize, InputError
from cloudtrail_triage.scenarios import build_dataset, write_dataset


class ScenarioTests(unittest.TestCase):
    def test_seed_is_reproducible_and_different_seeds_change_events(self):
        self.assertEqual(build_dataset(seed=42), build_dataset(seed=42))
        self.assertNotEqual(build_dataset(seed=42), build_dataset(seed=43))

    def test_splits_have_disjoint_ids_and_separate_time_ranges(self):
        development, _ = build_dataset(split="development")
        holdout, _ = build_dataset(split="holdout")
        self.assertFalse({r["eventID"] for r in development["Records"]} & {r["eventID"] for r in holdout["Records"]})
        self.assertLess(max(r["eventTime"] for r in development["Records"]), min(r["eventTime"] for r in holdout["Records"]))

    def test_every_record_validates_and_labels_cover_events_once_without_leaking(self):
        document, labels = build_dataset()
        ids = []
        for record in document["Records"]:
            normalize(record)
            self.assertNotIn("expected_rules", record)
            self.assertNotIn("disposition", record)
            self.assertNotIn("case_id", record)
        for case in labels["cases"]:
            ids.extend(case["event_ids"])
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(ids), {r["eventID"] for r in document["Records"]})
        self.assertEqual(len([c for c in labels["cases"] if c["expected_rules"]]), 3)

    def test_benign_lookalikes_remain_labeled_benign(self):
        _, labels = build_dataset()
        cases = {case["case_id"]: case for case in labels["cases"]}
        for name in ["approved_break_glass", "authorized_permission_audit"]:
            self.assertEqual(cases[name]["expected_rules"], [])
            self.assertEqual(cases[name]["disposition"], "benign")

    def test_file_round_trip_and_output_directory_cannot_be_overwritten(self):
        with TemporaryDirectory() as directory:
            root = Path(directory); output = root / "fixtures"; database = root / "test.duckdb"
            result = write_dataset(output, background=5)
            self.assertEqual(ingest_file(output / "events.json", database).inserted, result["events"])
            report = ingest_file(output / "events.jsonl", database)
            self.assertEqual(report.duplicates, result["events"])
            self.assertEqual(summarize(database)["events"], result["events"])
            original = (output / "events.json").read_bytes()
            with self.assertRaises(FileExistsError):
                write_dataset(output)
            self.assertEqual((output / "events.json").read_bytes(), original)

    def test_invalid_generator_options_are_rejected(self):
        for options in [{"seed": -1}, {"seed": True}, {"split": "bad"}, {"background": -1}, {"background": 10001}]:
            with self.subTest(options=options), self.assertRaises(InputError):
                build_dataset(**options)
