"""Explainable investigation signals over normalized events; no label access."""

from datetime import timezone
import hashlib
import json
from pathlib import Path

from .ingest import open_database

DENIED = """event_source='iam.amazonaws.com' AND principal IS NOT NULL
    AND error_code IN ('AccessDenied','AccessDeniedException','UnauthorizedOperation','Client.UnauthorizedOperation')"""


def _utc(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _finding(rule, account, principal, start, end, evidence, reason, metrics, severity="medium"):
    stable_key = json.dumps([rule, account, principal, sorted(evidence)], separators=(",", ":"))
    return {"id": "ct-" + hashlib.sha256(stable_key.encode()).hexdigest()[:20],
        "rule_id": rule, "severity": severity, "account_id": account, "principal": principal,
        "started_at": _utc(start), "ended_at": _utc(end), "evidence_ids": evidence,
        "reason": reason, "metrics": metrics}


def _bursts(connection):
    candidates = connection.execute(f"""WITH denied AS (SELECT * FROM events WHERE {DENIED}),
        scored AS (
            SELECT account_id, principal, event_time,
                min(event_time) OVER w AS first_seen,
                count(*) OVER w AS denial_count,
                count(DISTINCT event_name) OVER w AS action_count
            FROM denied
            WINDOW w AS (PARTITION BY account_id,principal ORDER BY event_time
                RANGE BETWEEN INTERVAL '5 minutes' PRECEDING AND CURRENT ROW)
        ) SELECT account_id,principal,first_seen,event_time,denial_count,action_count
          FROM scored WHERE denial_count>=5 AND action_count>=3
          ORDER BY account_id,principal,event_time""").fetchall()
    episodes = []
    for account, principal, start, end, count, actions in candidates:
        if (episodes and episodes[-1]["account"] == account and episodes[-1]["principal"] == principal
                and start <= episodes[-1]["end"]):
            episode = episodes[-1]
            episode["end"] = max(end, episode["end"])
            episode["peak_count"] = max(count, episode["peak_count"])
            episode["peak_actions"] = max(actions, episode["peak_actions"])
        else:
            episodes.append({"account": account, "principal": principal, "start": start, "end": end,
                "peak_count": count, "peak_actions": actions})
    result = []
    for episode in episodes:
        evidence = connection.execute(f"""SELECT event_id FROM events WHERE {DENIED}
            AND account_id=? AND principal=? AND event_time BETWEEN ? AND ?
            ORDER BY event_time,event_id""", [episode["account"], episode["principal"], episode["start"], episode["end"]]).fetchall()
        result.append(_finding("CT001", episode["account"], episode["principal"], episode["start"], episode["end"],
            [row[0] for row in evidence], "At least 5 IAM denials across 3 actions in a rolling 5-minute window.",
            {"peak_denials_in_window": episode["peak_count"], "peak_distinct_actions_in_window": episode["peak_actions"],
                "window_seconds": 300, "merged_overlapping_windows": True}))
    return result


def _console_signins(connection):
    rows = connection.execute("""SELECT account_id,principal,event_time,event_id,identity_type
        FROM events WHERE event_source='signin.amazonaws.com' AND event_name='ConsoleLogin'
        AND login_result='Success' AND mfa_used=false AND error_code IS NULL
        AND identity_type IN ('IAMUser','Root') AND principal IS NOT NULL
        ORDER BY event_time,event_id""").fetchall()
    return [_finding("CT002", account, principal, time, time, [event_id],
        "Successful direct IAM/root console sign-in explicitly reports MFAUsed=No.",
        {"identity_type": kind, "mfa_used": False}, "high" if kind == "Root" else "medium")
        for account, principal, time, event_id, kind in rows]


def _region_sequences(connection):
    # Choose the most recent eligible different-Region probe for each invocation.
    # Filtering before LIMIT avoids losing an earlier eligible probe to a newer same-Region event.
    rows = connection.execute("""SELECT a.account_id,a.principal,d.event_time,d.event_id,d.region,
            a.event_time,a.event_id,a.region,a.event_name
        FROM events a
        JOIN LATERAL (
            SELECT event_time,event_id,region FROM events d
            WHERE d.account_id=a.account_id AND d.principal=a.principal
                AND d.event_source='iam.amazonaws.com'
                AND d.error_code IN ('AccessDenied','AccessDeniedException','UnauthorizedOperation','Client.UnauthorizedOperation')
                AND d.region<>a.region AND d.event_time<a.event_time
                AND d.event_time>=a.event_time-INTERVAL '15 minutes'
            ORDER BY d.event_time DESC,d.event_id LIMIT 1
        ) d ON true
        WHERE a.event_source='bedrock.amazonaws.com' AND a.error_code IS NULL AND a.principal IS NOT NULL
            AND a.event_name IN ('Converse','ConverseStream','InvokeModel','InvokeModelWithResponseStream')
        ORDER BY a.event_time,a.event_id""").fetchall()
    return [_finding("CT003", account, principal, start, end, [probe_id, invoke_id],
        "IAM denial precedes a Bedrock invocation without an error code in a different Region within 15 minutes.",
        {"probe_region": source, "invocation_region": destination, "invocation_action": action,
            "maximum_gap_seconds": 900}, "high")
        for account, principal, start, probe_id, source, end, invoke_id, destination, action in rows]


def detect(database: Path) -> dict:
    connection = open_database(database, read_only=True)
    try:
        count, unknown = connection.execute("SELECT count(*),count(*) FILTER (WHERE principal IS NULL) FROM events").fetchone()
        findings = _bursts(connection) + _console_signins(connection) + _region_sequences(connection)
        findings.sort(key=lambda item: (item["started_at"], item["rule_id"], item["account_id"], item["principal"], item["id"]))
        return {"schema_version": 1, "events_analyzed": count, "uncorrelatable_events": unknown,
            "findings": findings, "notice": "Investigation signals, not proof of compromise. Missing telemetry can hide activity."}
    finally:
        connection.close()
