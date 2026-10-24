"""Credential-free integrated smoke demonstration with temporary local data."""

from collections import Counter
from http.client import HTTPConnection
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread

from .dashboard import create_dashboard
from .detect import detect
from .exports import render_export, write_export
from .ingest import ingest_file
from .model import InputError
from .queries import Filters, evidence, timeline
from .scenarios import write_dataset


def demo():
    with TemporaryDirectory() as directory:
        root = Path(directory); fixture = root / "fixture"; database = root / "demo.duckdb"
        write_dataset(fixture)
        imported = ingest_file(fixture / "events.json", database)
        repeated = ingest_file(fixture / "events.jsonl", database)
        findings = detect(database)["findings"]
        selected = next(f for f in findings if f["rule_id"] == "CT003")
        context = evidence(database, selected["id"])
        filtered = timeline(database, Filters(source="bedrock.amazonaws.com"))
        for fmt in ("json", "csv"):
            export = render_export(database, kind="evidence", output_format=fmt, finding_id=selected["id"])
            write_export(root / export.filename, export)
        server = create_dashboard(database, 0)
        thread = Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            statuses = []
            for authorized in (False, True):
                client = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                client.request("GET", "/api/overview", headers={"X-Triage-Token": server.token} if authorized else {})
                response = client.getresponse(); statuses.append(response.status); response.read(); client.close()
        finally:
            server.shutdown(); server.server_close(); thread.join()
        if (imported.inserted, repeated.duplicates, len(findings), len(context["events"]), filtered["total"], statuses) != (132, 132, 5, 2, 3, [403, 200]):
            raise InputError("demo_invariant_failed")
        return {"synthetic": True, "events_inserted": imported.inserted, "duplicate_records_skipped": repeated.duplicates,
            "findings_by_rule": dict(Counter(f["rule_id"] for f in findings)), "selected_finding_evidence_events": len(context["events"]),
            "filtered_timeline_events": filtered["total"], "exports_verified": ["json", "csv"],
            "http_without_token": statuses[0], "http_with_token": statuses[1],
            "notice": "Five development findings include two deliberate benign lookalikes. No AWS calls; temporary data removed."}
