from contextlib import redirect_stdout, redirect_stderr
from copy import deepcopy
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import duckdb

from cloudtrail_triage.cli import main
from cloudtrail_triage.ingest import ingest_file, read_records, summarize, open_database
from cloudtrail_triage.model import normalize, InputError
from helpers import event


class IngestionTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "input.json"
        self.db = self.root / "events.duckdb"

    def write(self, records):
        self.source.write_text(json.dumps({"Records": records}), encoding="utf8")

    def test_json_and_jsonl_are_idempotent_across_formats(self):
        self.write([event(1), event(2)])
        self.assertEqual(ingest_file(self.source, self.db).inserted, 2)
        jsonl = self.root / "input.jsonl"
        jsonl.write_text("\n" + "\n".join(json.dumps(event(i)) for i in (2, 1)) + "\n")
        report = ingest_file(jsonl, self.db)
        self.assertEqual((report.inserted, report.duplicates), (0, 2))
        self.assertEqual(summarize(self.db)["events"], 2)

    def test_record_validation_is_atomic_by_default(self):
        bad = event(2, eventTime="not-a-time")
        self.write([event(1), bad])
        with self.assertRaises(InputError) as raised:
            ingest_file(self.source, self.db)
        self.assertEqual((raised.exception.code, raised.exception.record), ("invalid_event_time", 2))
        self.assertFalse(self.db.exists())

    def test_skip_invalid_reports_safe_codes_and_retains_valid_records(self):
        self.write([event(), {"secret": "do-not-echo"}, None])
        report = ingest_file(self.source, self.db, skip_invalid=True)
        self.assertEqual((report.inserted, report.invalid), (1, 2))
        self.assertNotIn("do-not-echo", str(report))

    def test_all_invalid_does_not_create_database(self):
        self.write([None])
        with self.assertRaisesRegex(InputError, "no_valid_records"):
            ingest_file(self.source, self.db, skip_invalid=True)
        self.assertFalse(self.db.exists())

    def test_conflicting_duplicate_rolls_back_other_inserts(self):
        self.write([event(1)])
        ingest_file(self.source, self.db)
        self.write([event(2), event(1, eventName="DeleteUser")])
        with self.assertRaisesRegex(InputError, "conflicting_duplicate"):
            ingest_file(self.source, self.db)
        self.assertEqual(summarize(self.db)["events"], 1)

    def test_same_id_in_different_accounts_remains_separate(self):
        self.write([event(), event(recipientAccountId="444455556666")])
        self.assertEqual(ingest_file(self.source, self.db).inserted, 2)
        self.assertEqual(summarize(self.db)["accounts"], 2)

    def test_equivalent_timezone_values_deduplicate(self):
        self.write([event(), event(eventTime="2026-01-01T10:00:00+10:00")])
        report = ingest_file(self.source, self.db)
        self.assertEqual((report.inserted, report.duplicates), (1, 1))

    def test_bad_json_utf8_duplicate_keys_and_nan_fail_without_writes(self):
        for raw in [b'{', b'\xff', b'{"Records":[],"Records":[]}', b'{"Records":[NaN]}']:
            with self.subTest(raw=raw):
                self.source.write_bytes(raw)
                with self.assertRaises(InputError):
                    ingest_file(self.source, self.db)
                self.assertFalse(self.db.exists())

    def test_jsonl_syntax_error_reports_physical_line_and_never_skips_it(self):
        source = self.root / "input.jsonl"
        source.write_text(json.dumps(event()) + "\n\n{broken")
        with self.assertRaises(InputError) as raised:
            ingest_file(source, self.db, skip_invalid=True)
        self.assertEqual((raised.exception.code, raised.exception.record), ("invalid_json", 3))
        self.assertFalse(self.db.exists())

    def test_size_and_record_caps_are_enforced(self):
        self.write([event(), event(2)])
        with patch("cloudtrail_triage.ingest.MAX_BYTES", 10):
            with self.assertRaisesRegex(InputError, "input_too_large"):
                read_records(self.source)
        with patch("cloudtrail_triage.ingest.MAX_RECORDS", 1):
            with self.assertRaisesRegex(InputError, "too_many_records"):
                read_records(self.source)

    def test_unrelated_database_is_not_modified(self):
        with duckdb.connect(str(self.db)) as connection:
            connection.execute("CREATE TABLE unrelated (value INTEGER)")
        self.write([event()])
        with self.assertRaisesRegex(InputError, "unsupported_database_schema"):
            ingest_file(self.source, self.db)
        with duckdb.connect(str(self.db)) as connection:
            self.assertEqual(connection.execute("SHOW TABLES").fetchall(), [("unrelated",)])

    def test_raw_requests_credentials_and_response_payloads_are_not_stored(self):
        record = event(requestParameters={"secret": "sensitive-raw-value"})
        record["userIdentity"]["accessKeyId"] = "sensitive-access-key"
        self.write([record]); ingest_file(self.source, self.db)
        with open_database(self.db, read_only=True) as connection:
            rows = str(connection.execute("SELECT * FROM events").fetchall())
        self.assertNotIn("sensitive", rows)

    def test_missing_identity_is_retained_but_counted_as_uncorrelatable(self):
        self.write([event(userIdentity={})])
        self.assertEqual(ingest_file(self.source, self.db).uncorrelatable, 1)
        self.assertEqual(summarize(self.db)["uncorrelatable"], 1)

    def test_identity_center_components_do_not_collide(self):
        a = event(userIdentity={"type": "IdentityCenterUser", "onBehalfOf": {"identityStoreArn": "store:a", "userId": "b"}})
        b = event(userIdentity={"type": "IdentityCenterUser", "onBehalfOf": {"identityStoreArn": "store", "userId": "a:b"}})
        self.assertNotEqual(normalize(a).principal, normalize(b).principal)

    def test_arn_is_preserved_and_cannot_alias_principal_id_namespace(self):
        self.assertEqual(normalize(event()).principal, event()["userIdentity"]["arn"])
        record = event(); record["userIdentity"]["arn"] = "id:synthetic"
        with self.assertRaisesRegex(InputError, "invalid_principal_arn"):
            normalize(record)

    def test_bad_fields_are_rejected_and_unknown_mfa_is_not_false(self):
        for changes in [{"eventTime": "2026-01-01T00:00:00"}, {"recipientAccountId": "wrong"},
                        {"eventID": "bad"}, {"eventName": "x\nsecret"}, {"userIdentity": []}]:
            with self.subTest(changes=changes), self.assertRaises(InputError):
                normalize(event(**changes))
        self.assertIsNone(normalize(event()).mfa_used)
        self.assertIsNone(normalize(event(additionalEventData={"MFAUsed": []})).mfa_used)

    def test_cli_success_and_errors_are_json_without_paths_or_raw_values(self):
        self.write([event()])
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["ingest", str(self.source), "--db", str(self.db)]), 0)
        self.assertEqual(json.loads(output.getvalue())["inserted"], 1)
        self.source.write_text('{"secret":"do-not-echo"}')
        error = io.StringIO()
        with redirect_stderr(error):
            self.assertEqual(main(["ingest", str(self.source), "--db", str(self.db)]), 2)
        self.assertEqual(json.loads(error.getvalue())["error"], "expected_records_array")
        self.assertNotIn(str(self.source), error.getvalue())
        self.assertNotIn("do-not-echo", error.getvalue())
