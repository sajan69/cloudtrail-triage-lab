"""Read-only, bounded investigation queries with parameter-bound filters."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
import re

from .detect import detect
from .ingest import open_database, summarize
from .model import InputError, text

EVENT_FIELDS = ("event_id", "event_time", "account_id", "principal", "identity_type", "event_source",
    "event_name", "region", "source_ip", "error_code", "login_result", "mfa_used")


def utc(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value):
    if value is None:
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None or result.utcoffset() is None:
            raise ValueError
        return result.astimezone(timezone.utc)
    except (AttributeError, TypeError, ValueError, OverflowError):
        raise InputError("invalid_time_filter") from None


@dataclass(frozen=True)
class Filters:
    account: str | None = None
    principal: str | None = None
    region: str | None = None
    source: str | None = None
    started_at: str | None = None
    ended_at: str | None = None

    def __post_init__(self):
        if self.account is not None and (not isinstance(self.account, str) or not re.fullmatch(r"[0-9]{12}", self.account)):
            raise InputError("invalid_account_filter")
        for name, limit in [("principal", 1024), ("region", 64), ("source", 256)]:
            text(getattr(self, name), name + "_filter", limit=limit)
        start, end = parse_time(self.started_at), parse_time(self.ended_at)
        if start and end and start > end:
            raise InputError("reversed_time_filters")


def _where(filters, event_ids=None):
    predicates, values = [], []
    for attribute, column in [("account", "account_id"), ("principal", "principal"), ("region", "region"), ("source", "event_source")]:
        value = getattr(filters, attribute)
        if value is not None:
            predicates.append(column + "=?"); values.append(value)
    for attribute, operator in [("started_at", ">="), ("ended_at", "<=")]:
        value = parse_time(getattr(filters, attribute))
        if value is not None:
            predicates.append("event_time" + operator + "?"); values.append(value)
    if event_ids is not None:
        if len(event_ids) > 20000:
            raise InputError("too_many_evidence_ids")
        if not event_ids:
            predicates.append("false")
        else:
            predicates.append("event_id IN (" + ",".join("?" for _ in event_ids) + ")")
            values.extend(event_ids)
    return " AND ".join(predicates) or "true", values


def timeline(database: Path, filters: Filters | None = None, *, limit=100, offset=0, event_ids=None):
    if type(limit) is not int or not 1 <= limit <= 1000 or type(offset) is not int or not 0 <= offset <= 10000000:
        raise InputError("invalid_pagination")
    filters = filters or Filters()
    predicate, values = _where(filters, event_ids)
    connection = open_database(database, read_only=True)
    try:
        total = connection.execute("SELECT count(*) FROM events WHERE " + predicate, values).fetchone()[0]
        rows = connection.execute("SELECT " + ",".join(EVENT_FIELDS) + " FROM events WHERE " + predicate
            + " ORDER BY event_time,account_id,event_id LIMIT ? OFFSET ?", [*values, limit, offset]).fetchall()
        records = []
        for row in rows:
            event = dict(zip(EVENT_FIELDS, row))
            event["event_time"] = utc(event["event_time"])
            records.append(event)
        return {"total": total, "limit": limit, "offset": offset, "filters": asdict(filters), "events": records}
    finally:
        connection.close()


def evidence(database: Path, finding_id: str, *, limit=100, offset=0):
    if not isinstance(finding_id, str) or not re.fullmatch(r"ct-[0-9a-f]{20}", finding_id):
        raise InputError("invalid_finding_id")
    finding = next((f for f in detect(database)["findings"] if f["id"] == finding_id), None)
    if finding is None:
        raise InputError("finding_not_found")
    result = timeline(database, Filters(account=finding["account_id"], principal=finding["principal"]),
        limit=limit, offset=offset, event_ids=finding["evidence_ids"])
    return {"finding": finding, **result}


def overview(database: Path):
    result = summarize(database)
    connection = open_database(database, read_only=True)
    try:
        start, end = connection.execute("SELECT min(event_time),max(event_time) FROM events").fetchone()
        result["started_at"] = utc(start) if start else None
        result["ended_at"] = utc(end) if end else None
        for field, column in [("accounts_available", "account_id"), ("regions_available", "region"), ("sources_available", "event_source")]:
            result[field] = [r[0] for r in connection.execute(f"SELECT DISTINCT {column} FROM events ORDER BY {column} LIMIT 200").fetchall()]
        result["option_limit"] = 200
        return result
    finally:
        connection.close()
