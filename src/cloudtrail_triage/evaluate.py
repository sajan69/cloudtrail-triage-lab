"""Case-level evaluation of fixed rules on reserved synthetic fixture seeds."""

from importlib.metadata import version
import json
from pathlib import Path
import platform
import re
from tempfile import TemporaryDirectory

from .detect import detect
from .ingest import ingest_file, read_records, MAX_BYTES
from .model import InputError, normalize
from .scenarios import write_dataset

RULES = ("CT001", "CT002", "CT003")
HOLDOUT_SEEDS = (101, 203, 307, 409, 503)


def metrics(counts):
    tp, fp, fn, tn = (counts[key] for key in ("tp", "fp", "fn", "tn"))
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    fpr = fp / (fp + tn) if fp + tn else None
    f1 = (2 * precision * recall / (precision + recall) if precision + recall else 0.0) if precision is not None and recall is not None else None
    return {**counts, "precision": precision, "recall": recall, "false_positive_rate": fpr, "f1": f1}


def validate_labels(labels, event_ids):
    if (not isinstance(labels, dict) or labels.get("schema_version") != 1 or labels.get("synthetic") is not True
            or labels.get("split") != "holdout" or not isinstance(labels.get("cases"), list) or not labels["cases"]):
        raise InputError("invalid_holdout_labels")
    covered, case_names = set(), set()
    for case in labels["cases"]:
        if not isinstance(case, dict): raise InputError("invalid_label_case")
        name, ids, expected = case.get("case_id"), case.get("event_ids"), case.get("expected_rules")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", name) or name in case_names:
            raise InputError("invalid_or_duplicate_case_id")
        if not isinstance(ids, list) or not ids or any(not isinstance(value, str) for value in ids):
            raise InputError("invalid_case_event_ids")
        if len(ids) != len(set(ids)) or covered.intersection(ids): raise InputError("overlapping_case_labels")
        if not isinstance(expected, list) or any(not isinstance(rule, str) or rule not in RULES for rule in expected) or len(expected) != len(set(expected)):
            raise InputError("invalid_expected_rules")
        covered.update(ids); case_names.add(name)
    if covered != event_ids: raise InputError("labels_do_not_partition_events")
    return labels["cases"]


def score_cases(cases, findings):
    counts = {rule: {key: 0 for key in ("tp", "fp", "fn", "tn")} for rule in RULES}
    outcomes = []
    for case in cases:
        ids = set(case["event_ids"])
        predicted = {finding["rule_id"] for finding in findings if ids.intersection(finding["evidence_ids"])}
        expected = set(case["expected_rules"])
        for rule in RULES:
            key = "tp" if rule in expected and rule in predicted else "fn" if rule in expected else "fp" if rule in predicted else "tn"
            counts[rule][key] += 1
        outcomes.append({"case_id": case["case_id"], "expected_rules": sorted(expected), "predicted_rules": sorted(predicted)})
    cross_case = sum(sum(bool(set(case["event_ids"]).intersection(finding["evidence_ids"])) for case in cases) > 1 for finding in findings)
    return counts, outcomes, cross_case


def evaluate_fixture(source: Path, label_path: Path):
    if label_path.stat().st_size > MAX_BYTES: raise InputError("labels_too_large")
    try:
        labels = json.loads(label_path.read_text(encoding="utf8"))
    except (ValueError, UnicodeError, RecursionError):
        raise InputError("invalid_label_json") from None
    records = read_records(source)
    ids = [normalize(record).event_id for record in records]
    if len(ids) != len(set(ids)): raise InputError("evaluation_requires_unique_events")
    cases = validate_labels(labels, set(ids))
    # Only the event file goes through ingestion/detection; labels never reach the rules.
    with TemporaryDirectory() as directory:
        database = Path(directory) / "evaluation.duckdb"
        ingest_file(source, database)
        findings = detect(database)["findings"]
    counts, outcomes, cross_case = score_cases(cases, findings)
    return {"seed": labels.get("seed"), "events": len(ids), "cases": len(cases), "findings": len(findings),
        "counts": counts, "outcomes": outcomes, "cross_case_findings": cross_case}


def evaluate_suite(seeds=HOLDOUT_SEEDS):
    if not seeds or len(seeds) > 20 or len(set(seeds)) != len(seeds): raise InputError("invalid_evaluation_seeds")
    runs = []
    with TemporaryDirectory() as directory:
        for seed in seeds:
            folder = Path(directory) / f"seed-{seed}"
            write_dataset(folder, seed=seed, split="holdout", background=100)
            runs.append(evaluate_fixture(folder / "events.json", folder / "labels.json"))
    combined = {rule: {key: sum(run["counts"][rule][key] for run in runs) for key in ("tp", "fp", "fn", "tn")} for rule in RULES}
    return {"schema_version": 1, "synthetic": True, "split": "holdout", "unit": "scenario case per rule",
        "environment": {"python": platform.python_version(), "duckdb": version("duckdb"), "package": version("cloudtrail-triage-lab")},
        "seeds": list(seeds), "events": sum(r["events"] for r in runs), "cases": sum(r["cases"] for r in runs),
        "rule_metrics": {rule: metrics(counts) for rule, counts in combined.items()}, "runs": runs,
        "method": "Fixed rule thresholds; any finding evidence intersecting a case marks that case positive for the rule. Cross-case findings mark every intersected case.",
        "limitations": ["Synthetic labels are scenario judgments, not independently verified incidents.",
            "Development and holdout seeds use shared templates; this does not measure real-world generalization.",
            "Rules were not tuned using these reserved seeds. Background volume and case prevalence are artificial.",
            "Undefined ratios are null; results are case-level, not event-level or production accuracy."]}
