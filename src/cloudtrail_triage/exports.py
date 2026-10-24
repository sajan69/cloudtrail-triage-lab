"""Bounded JSON/CSV investigation exports and exclusive local file writes."""

import csv
from dataclasses import asdict, dataclass
import io
import json
import os
from pathlib import Path

from .detect import detect
from .model import InputError
from .queries import EVENT_FIELDS, Filters, evidence, parse_time, timeline

MAX_EXPORT = 10000
FINDING_FIELDS = ("id", "rule_id", "severity", "account_id", "principal", "started_at", "ended_at", "reason", "evidence_ids", "metrics")


@dataclass(frozen=True)
class Export:
    content: bytes
    content_type: str
    filename: str
    total: int


def csv_cell(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, bool)):
        value = json.dumps(value, sort_keys=True, ensure_ascii=True)
    value = str(value)
    # CSV quoting alone does not prevent spreadsheet formula evaluation.
    if value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@", "\uff1d", "\uff0b", "\uff0d", "\uff20")):
        value = "'" + value
    return value


def select_findings(database, filters=None, *, rule=None, severity=None):
    filters = filters or Filters()
    if filters.region is not None or filters.source is not None:
        raise InputError("finding_filters_do_not_support_region_or_source")
    if rule is not None and rule not in {"CT001", "CT002", "CT003"}:
        raise InputError("invalid_rule_filter")
    if severity is not None and severity not in {"medium", "high"}:
        raise InputError("invalid_severity_filter")
    start, end = parse_time(filters.started_at), parse_time(filters.ended_at)
    rows = []
    for finding in detect(database)["findings"]:
        if filters.account is not None and finding["account_id"] != filters.account: continue
        if filters.principal is not None and finding["principal"] != filters.principal: continue
        if rule is not None and finding["rule_id"] != rule: continue
        if severity is not None and finding["severity"] != severity: continue
        if start and parse_time(finding["ended_at"]) < start: continue
        if end and parse_time(finding["started_at"]) > end: continue
        rows.append(finding)
    return rows


def _all_events(database, filters=None, finding_id=None):
    query = (lambda offset: evidence(database, finding_id, limit=1000, offset=offset)) if finding_id else (
        lambda offset: timeline(database, filters, limit=1000, offset=offset))
    page = query(0)
    if page["total"] > MAX_EXPORT:
        raise InputError("export_too_large_use_filters")
    rows = page["events"]
    for offset in range(1000, page["total"], 1000):
        rows.extend(query(offset)["events"])
    if len(rows) != page["total"]:
        raise InputError("database_changed_during_export")
    return rows, page.get("finding")


def render_export(database: Path, *, kind="events", output_format="json", filters=None, finding_id=None, rule=None, severity=None):
    if kind not in {"events", "findings", "evidence"} or output_format not in {"json", "csv"}:
        raise InputError("invalid_export_format_or_kind")
    filters = filters or Filters()
    finding = None
    if kind == "findings":
        if finding_id is not None: raise InputError("unexpected_finding_id")
        rows = select_findings(database, filters, rule=rule, severity=severity)
        fields = FINDING_FIELDS
    elif kind == "evidence":
        if not finding_id or filters != Filters() or rule is not None or severity is not None:
            raise InputError("evidence_export_requires_only_finding_id")
        rows, finding = _all_events(database, finding_id=finding_id)
        fields = EVENT_FIELDS
    else:
        if finding_id is not None or rule is not None or severity is not None:
            raise InputError("unexpected_finding_filters")
        rows, _ = _all_events(database, filters)
        fields = EVENT_FIELDS
    if len(rows) > MAX_EXPORT:
        raise InputError("export_too_large_use_filters")
    if output_format == "json":
        document = {"schema_version": 1, "kind": kind, "filters": asdict(filters), "total": len(rows), "records": rows}
        if finding is not None: document["finding"] = finding
        content = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True).encode("utf8")
        content_type = "application/json; charset=utf-8"
    else:
        stream = io.StringIO(newline="")
        writer = csv.writer(stream, quoting=csv.QUOTE_ALL)
        writer.writerow(fields)
        for row in rows:
            writer.writerow([csv_cell(row.get(field)) for field in fields])
        content = stream.getvalue().encode("utf8")
        content_type = "text/csv; charset=utf-8"
    return Export(content, content_type, f"triage-{kind}.{output_format}", len(rows))


def write_export(destination: Path, export: Export):
    # O_EXCL also refuses existing symlinks; this never overwrites an evidence file.
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(export.content)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
