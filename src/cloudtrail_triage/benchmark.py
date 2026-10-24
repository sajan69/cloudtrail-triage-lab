"""Small, reproducible local workload measurements; no production claims."""

from importlib.metadata import version
import json
import os
from pathlib import Path
import platform
import statistics
from tempfile import TemporaryDirectory
from time import perf_counter

from .detect import detect
from .ingest import ingest_file
from .model import InputError
from .queries import Filters, timeline
from .scenarios import write_dataset


def benchmark(*, background=1000, repeats=3):
    if type(repeats) is not int or not 1 <= repeats <= 10: raise InputError("invalid_benchmark_repeats")
    samples = []
    with TemporaryDirectory() as directory:
        root = Path(directory); fixture = root / "fixture"
        info = write_dataset(fixture, seed=42, background=background)
        size = (fixture / "events.json").stat().st_size
        for repeat in range(repeats):
            database = root / f"trial-{repeat}.duckdb"
            start = perf_counter(); report = ingest_file(fixture / "events.json", database); ingest_ms = (perf_counter() - start) * 1000
            start = perf_counter(); findings = detect(database); detection_ms = (perf_counter() - start) * 1000
            start = perf_counter(); filtered = timeline(database, Filters(source="bedrock.amazonaws.com")); query_ms = (perf_counter() - start) * 1000
            if report.inserted != info["events"] or len(findings["findings"]) != 5 or filtered["total"] != 3:
                raise InputError("benchmark_invariant_failed")
            samples.append({"ingest_ms": round(ingest_ms, 3), "detect_ms": round(detection_ms, 3), "filtered_timeline_ms": round(query_ms, 3)})
    keys = samples[0].keys()
    return {"schema_version": 1, "synthetic": True,
        "environment": {"python": platform.python_version(), "duckdb": version("duckdb"), "package": version("cloudtrail-triage-lab"),
            "system": platform.system(), "machine": platform.machine(), "logical_cpu_count": os.cpu_count()},
        "workload": {"seed": 42, "events": info["events"], "input_bytes": size, "repeats": repeats, "expected_findings": 5},
        "samples": samples, "median_ms": {key: round(statistics.median(sample[key] for sample in samples), 3) for key in keys},
        "method": "Fresh database per import; wall-clock timings include validation, connections and SQL. Repeated input can benefit from OS caches.",
        "limitations": ["Single shared environment and synthetic workload; no AWS latency or collection measured.",
            "No competitor/baseline speedup comparison, load test or throughput guarantee.", "Hardware, storage, cache state and concurrent load affect these measurements."]}
