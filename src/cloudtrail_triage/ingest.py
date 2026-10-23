"""Bounded file parsing and transactional normalized-event storage."""

from dataclasses import dataclass, field
import json
from pathlib import Path

import duckdb

from .model import InputError, normalize

MAX_BYTES = 10 * 1024 * 1024
MAX_RECORDS = 20000
COLUMNS = "event_id,event_time,account_id,principal,identity_type,event_source,event_name,region,source_ip,error_code,login_result,mfa_used,fingerprint"


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("duplicate_json_key")
        result[key] = value
    return result


def _invalid_constant(_):
    raise InputError("invalid_json_number")


def _decode(value):
    try:
        return json.loads(value, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except (json.JSONDecodeError, RecursionError):
        raise InputError("invalid_json") from None


def read_records(path: Path, input_format: str = "auto") -> list:
    if input_format not in {"auto", "json", "jsonl"}:
        raise InputError("invalid_input_format")
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise InputError("input_too_large")
    try:
        content = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise InputError("invalid_utf8") from None
    mode = ("jsonl" if path.suffix.lower() == ".jsonl" else "json") if input_format == "auto" else input_format
    if mode == "jsonl":
        records = []
        for number, line in enumerate(content.splitlines(), 1):
            if line.strip():
                try:
                    records.append(_decode(line))
                except InputError as error:
                    raise InputError(error.code, number) from None
                if len(records) > MAX_RECORDS:
                    raise InputError("too_many_records")
    else:
        document = _decode(content)
        if not isinstance(document, dict) or not isinstance(document.get("Records"), list):
            raise InputError("expected_records_array")
        records = document["Records"]
    if not records:
        raise InputError("empty_input")
    if len(records) > MAX_RECORDS:
        raise InputError("too_many_records")
    return records


def open_database(path: Path, *, read_only: bool = False):
    """Only initialize new databases or open this tool's schema; no arbitrary SQL."""
    connection = duckdb.connect(str(path), read_only=read_only,
        config={"enable_external_access": False, "threads": 2, "memory_limit": "256MB"})
    try:
        tables = {row[0] for row in connection.execute("SHOW TABLES").fetchall()}
        if not tables and not read_only:
            connection.execute("BEGIN")
            connection.execute("CREATE TABLE triage_meta (version INTEGER NOT NULL)")
            connection.execute("INSERT INTO triage_meta VALUES (1)")
            connection.execute("""CREATE TABLE events (
                event_id VARCHAR NOT NULL, event_time TIMESTAMPTZ NOT NULL,
                account_id VARCHAR NOT NULL, principal VARCHAR, identity_type VARCHAR NOT NULL,
                event_source VARCHAR NOT NULL, event_name VARCHAR NOT NULL, region VARCHAR NOT NULL,
                source_ip VARCHAR, error_code VARCHAR, login_result VARCHAR, mfa_used BOOLEAN,
                fingerprint VARCHAR NOT NULL, PRIMARY KEY (account_id, event_id))""")
            connection.execute("COMMIT")
        elif tables != {"events", "triage_meta"} or connection.execute("SELECT version FROM triage_meta").fetchall() != [(1,)]:
            raise InputError("unsupported_database_schema")
        # Verify columns even if a different database claims the same version.
        connection.execute(f"SELECT {COLUMNS} FROM events LIMIT 0")
        return connection
    except Exception:
        connection.close()
        raise


@dataclass
class IngestReport:
    input_records: int
    inserted: int = 0
    duplicates: int = 0
    invalid: int = 0
    uncorrelatable: int = 0
    issues: list[dict] = field(default_factory=list)


def ingest_file(source: Path, database: Path, *, input_format: str = "auto", skip_invalid: bool = False) -> IngestReport:
    records = read_records(source, input_format)
    report = IngestReport(input_records=len(records))
    events = []
    for number, record in enumerate(records, 1):
        try:
            event = normalize(record)
        except InputError as error:
            if not skip_invalid:
                raise InputError(error.code, number) from None
            report.invalid += 1
            if len(report.issues) < 25:
                report.issues.append({"record": number, "code": error.code})
            continue
        events.append(event)
        report.uncorrelatable += event.principal is None
    if not events:
        raise InputError("no_valid_records")
    connection = open_database(database)
    try:
        connection.execute("BEGIN")
        for event in events:
            existing = connection.execute("SELECT fingerprint FROM events WHERE account_id=? AND event_id=?",
                [event.account_id, event.event_id]).fetchone()
            if existing:
                if existing[0] != event.fingerprint:
                    raise InputError("conflicting_duplicate")
                report.duplicates += 1
            else:
                connection.execute(f"INSERT INTO events ({COLUMNS}) VALUES ({','.join(['?'] * 13)})", event.row())
                report.inserted += 1
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()
    return report


def summarize(database: Path) -> dict:
    connection = open_database(database, read_only=True)
    try:
        count, accounts, principals, unknown = connection.execute("""SELECT count(*), count(DISTINCT account_id),
            count(DISTINCT (account_id, principal)) FILTER (WHERE principal IS NOT NULL),
            count(*) FILTER (WHERE principal IS NULL) FROM events""").fetchone()
        return {"events": count, "accounts": accounts, "principals": principals, "uncorrelatable": unknown,
            "sources": dict(connection.execute("SELECT event_source,count(*) FROM events GROUP BY event_source ORDER BY event_source").fetchall())}
    finally:
        connection.close()
