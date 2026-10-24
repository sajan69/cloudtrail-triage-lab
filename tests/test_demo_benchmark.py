import unittest

from cloudtrail_triage.benchmark import benchmark
from cloudtrail_triage.demo import demo
from cloudtrail_triage.model import InputError


class DemoBenchmarkTests(unittest.TestCase):
    def test_demo_runs_the_real_local_pipeline_and_http_access_check(self):
        result = demo()
        self.assertEqual(result["events_inserted"], 132)
        self.assertEqual(result["duplicate_records_skipped"], 132)
        self.assertEqual(result["findings_by_rule"], {"CT001": 2, "CT002": 2, "CT003": 1})
        self.assertEqual((result["http_without_token"], result["http_with_token"]), (403, 200))

    def test_measurement_records_workload_and_real_nonnegative_durations(self):
        result = benchmark(background=0, repeats=1)
        self.assertEqual(result["workload"]["events"], 32)
        self.assertEqual(result["workload"]["repeats"], 1)
        self.assertTrue(all(value >= 0 for value in result["samples"][0].values()))
        with self.assertRaises(InputError): benchmark(repeats=0)
