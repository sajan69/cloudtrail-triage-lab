from http.client import HTTPConnection
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import unittest

from cloudtrail_triage.dashboard import create_dashboard
from cloudtrail_triage.ingest import ingest_file
from cloudtrail_triage.scenarios import build_dataset


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = TemporaryDirectory(); cls.root = Path(cls.temp.name); cls.db = cls.root / "events.duckdb"
        document, _ = build_dataset(); source = cls.root / "events.json"; source.write_text(json.dumps(document)); ingest_file(source, cls.db)
        cls.server = create_dashboard(cls.db, 0)
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True); cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join(); cls.temp.cleanup()

    def request(self, path, *, authorized=True, method="GET", extra=None):
        connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        headers = {"X-Triage-Token": self.server.token} if authorized else {}
        headers.update(extra or {})
        connection.request(method, path, headers=headers)
        response = connection.getresponse(); body = response.read(); headers = dict(response.getheaders()); status = response.status
        connection.close(); return status, headers, body

    def test_assets_are_packaged_and_security_headers_are_set(self):
        for path in ["/", "/app.js", "/style.css"]:
            status, headers, body = self.request(path, authorized=False)
            self.assertEqual(status, 200); self.assertTrue(body)
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_data_requires_token_and_rejects_cross_origin_or_rebound_hosts(self):
        self.assertEqual(self.request("/api/overview", authorized=False)[0], 403)
        self.assertEqual(self.request("/api/overview", extra={"X-Triage-Token": "wrong"})[0], 403)
        self.assertEqual(self.request("/api/overview", extra={"Origin": "https://example.com"})[0], 403)
        self.assertEqual(self.request("/api/overview", extra={"Host": "attacker.invalid"})[0], 403)
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_findings_timeline_evidence_and_export_round_trip(self):
        before = self.db.read_bytes()
        status, _, body = self.request("/api/findings?rule=CT003")
        finding = json.loads(body)["findings"][0]; self.assertEqual(status, 200)
        status, _, body = self.request("/api/evidence?id=" + finding["id"])
        self.assertEqual(json.loads(body)["total"], 2)
        status, _, body = self.request("/api/timeline?source=bedrock.amazonaws.com&limit=2")
        self.assertEqual((status, json.loads(body)["total"]), (200, 3))
        status, headers, body = self.request("/api/export?kind=evidence&format=csv&id=" + finding["id"])
        self.assertEqual(status, 200); self.assertIn("attachment", headers["Content-Disposition"])
        self.assertIn(b"Converse", body)
        self.assertEqual(self.db.read_bytes(), before)

    def test_bad_queries_and_writes_do_not_expose_data_or_paths(self):
        for path in ["/api/timeline?limit=no", "/api/timeline?limit=1&limit=2", "/api/timeline?sql=select", "/api/overview?unexpected=x"]:
            status, _, body = self.request(path)
            self.assertEqual(status, 400); self.assertNotIn(str(self.db).encode(), body)
        self.assertEqual(self.request("/../../pyproject.toml")[0], 404)
        self.assertEqual(self.request("/api/timeline", method="POST")[0], 405)

    def test_static_frontend_uses_text_nodes_not_html_injection(self):
        _, _, script = self.request("/app.js")
        self.assertNotIn(b"innerHTML", script)
        self.assertNotIn(b"eval(", script)
        self.assertIn(b"textContent", script)
