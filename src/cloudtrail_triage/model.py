"""Normalize a deliberately limited subset of CloudTrail fields."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from uuid import UUID


class InputError(ValueError):
    """A safe error code and optional one-based record number; never raw input."""

    def __init__(self, code: str, record: int | None = None):
        self.code = code
        self.record = record
        super().__init__(code)


def text(value, field: str, *, required: bool = False, limit: int = 1024):
    if value is None and not required:
        return None
    if (not isinstance(value, str) or not value or len(value) > limit
            or value != value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise InputError(f"invalid_{field}")
    try:
        value.encode("utf8")
    except UnicodeEncodeError:
        raise InputError(f"invalid_{field}") from None
    return value


def mapping(value, field: str):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise InputError(f"invalid_{field}")
    return value


@dataclass(frozen=True)
class Event:
    event_id: str
    event_time: datetime
    account_id: str
    principal: str | None
    identity_type: str
    event_source: str
    event_name: str
    region: str
    source_ip: str | None
    error_code: str | None
    login_result: str | None
    mfa_used: bool | None

    @property
    def fingerprint(self):
        projection = asdict(self)
        projection["event_time"] = self.event_time.isoformat()
        encoded = json.dumps(projection, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(encoded.encode()).hexdigest()

    def row(self):
        return (*asdict(self).values(), self.fingerprint)


def normalize(record) -> Event:
    if not isinstance(record, dict):
        raise InputError("record_must_be_object")
    event_id = text(record.get("eventID"), "event_id", required=True, limit=36)
    try:
        event_id = str(UUID(event_id))
    except ValueError:
        raise InputError("invalid_event_id") from None
    time = text(record.get("eventTime"), "event_time", required=True, limit=64)
    try:
        timestamp = datetime.fromisoformat(time.replace("Z", "+00:00"))
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError
        timestamp = timestamp.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise InputError("invalid_event_time") from None
    identity = mapping(record.get("userIdentity"), "user_identity")
    account = record.get("recipientAccountId") or identity.get("accountId")
    if not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account):
        raise InputError("invalid_account_id")
    identity_type = text(identity.get("type", "Unknown"), "identity_type", required=True, limit=64)
    principal = None
    if identity.get("arn") is not None:
        principal = text(identity["arn"], "principal", required=True)
        if not principal.startswith("arn:"):
            raise InputError("invalid_principal_arn")
    elif identity.get("principalId") is not None:
        principal = "id:" + text(identity["principalId"], "principal", required=True)
    elif identity.get("onBehalfOf") is not None:
        behalf = mapping(identity["onBehalfOf"], "on_behalf_of")
        store = text(behalf.get("identityStoreArn"), "identity_store", required=True)
        user = text(behalf.get("userId"), "user_id", required=True)
        # A JSON tuple avoids ambiguous concatenation of identity components.
        principal = "identity-center:" + json.dumps([store, user], separators=(",", ":"))
    additional = mapping(record.get("additionalEventData"), "additional_event_data")
    response = mapping(record.get("responseElements"), "response_elements")
    mfa = additional.get("MFAUsed")
    # No inference from a missing field, sessionContext, or upstream federation.
    mfa_used = {"Yes": True, "No": False}.get(mfa) if isinstance(mfa, str) else None
    return Event(
        event_id, timestamp, account, principal, identity_type,
        text(record.get("eventSource"), "event_source", required=True, limit=256),
        text(record.get("eventName"), "event_name", required=True, limit=128),
        text(record.get("awsRegion"), "region", required=True, limit=64),
        text(record.get("sourceIPAddress"), "source_ip", limit=256),
        text(record.get("errorCode"), "error_code", limit=256),
        text(response.get("ConsoleLogin"), "login_result", limit=64), mfa_used,
    )
