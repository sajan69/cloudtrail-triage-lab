from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cloudtrail_triage.evaluate import evaluate_fixture, evaluate_suite, metrics, score_cases, validate_labels
from cloudtrail_triage.model import InputError
from cloudtrail_triage.scenarios import build_dataset, write_dataset


class EvaluationTests(unittest.TestCase):
    def test_confusion_counts_and_undefined_ratios(self):
        cases = [{"case_id": "positive", "event_ids": ["a"], "expected_rules": ["CT001"]},
            {"case_id": "negative", "event_ids": ["b"], "expected_rules": []}]
        counts, _, _ = score_cases(cases, [{"rule_id": "CT001", "evidence_ids": ["b"]}])
        self.assertEqual(counts["CT001"], {"tp": 0, "fp": 1, "fn": 1, "tn": 0})
        self.assertEqual(metrics(counts["CT001"])["f1"], 0.0)
        self.assertIsNone(metrics({"tp": 0, "fp": 0, "fn": 0, "tn": 2})["recall"])

    def test_labels_must_exactly_partition_unique_events(self):
        document, labels = build_dataset(split="holdout")
        ids = {r["eventID"] for r in document["Records"]}
        self.assertEqual(len(validate_labels(labels, ids)), 13)
        for change in ["overlap", "missing", "rule", "development"]:
            bad = deepcopy(labels)
            if change == "overlap": bad["cases"][1]["event_ids"].append(bad["cases"][0]["event_ids"][0])
            elif change == "missing": bad["cases"].pop()
            elif change == "rule": bad["cases"][0]["expected_rules"] = ["UNKNOWN"]
            else: bad["split"] = "development"
            with self.subTest(change=change), self.assertRaises(InputError): validate_labels(bad, ids)

    def test_cross_case_evidence_is_counted_conservatively(self):
        cases = [{"case_id": "a", "event_ids": ["a"], "expected_rules": []},
            {"case_id": "b", "event_ids": ["b"], "expected_rules": ["CT003"]}]
        counts, _, cross = score_cases(cases, [{"rule_id": "CT003", "evidence_ids": ["a", "b"]}])
        self.assertEqual(cross, 1); self.assertEqual(counts["CT003"]["fp"], 1); self.assertEqual(counts["CT003"]["tp"], 1)

    def test_holdout_fixture_retains_benign_false_positives(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "fixture"; write_dataset(output, seed=101, split="holdout")
            result = evaluate_fixture(output / "events.json", output / "labels.json")
        self.assertEqual((result["events"], result["cases"], result["findings"]), (132, 13, 5))
        self.assertEqual(result["counts"]["CT001"], {"tp": 1, "fp": 1, "fn": 0, "tn": 11})
        self.assertEqual(result["counts"]["CT002"]["fp"], 1)
        self.assertEqual(result["counts"]["CT003"]["fp"], 0)

    def test_seed_suite_is_deterministic_and_rejects_duplicates(self):
        a = evaluate_suite((101,)); b = evaluate_suite((101,))
        self.assertEqual(a, b)
        self.assertEqual(a["rule_metrics"]["CT001"]["precision"], 0.5)
        self.assertIn("shared templates", " ".join(a["limitations"]))
        with self.assertRaises(InputError): evaluate_suite((101, 101))
