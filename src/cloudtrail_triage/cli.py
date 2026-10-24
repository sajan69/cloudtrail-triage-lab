"""Command-line entry point. Errors deliberately omit log values and paths."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

import duckdb

from .ingest import ingest_file, summarize
from .model import InputError
from .scenarios import write_dataset
from .detect import detect
from .queries import Filters, timeline


def main(argv=None):
    parser = argparse.ArgumentParser(prog="triage")
    commands = parser.add_subparsers(dest="command", required=True)
    ingest = commands.add_parser("ingest", help="Validate and ingest CloudTrail Records JSON or JSONL")
    ingest.add_argument("source", type=Path)
    ingest.add_argument("--db", type=Path, required=True)
    ingest.add_argument("--format", choices=["auto", "json", "jsonl"], default="auto")
    ingest.add_argument("--skip-invalid", action="store_true", help="Skip invalid records; syntax errors still abort")
    summary = commands.add_parser("summary", help="Read aggregate database counts")
    summary.add_argument("--db", type=Path, required=True)
    generate = commands.add_parser("generate", help="Write synthetic events and separate labels to a fresh directory")
    generate.add_argument("--out", type=Path, required=True)
    generate.add_argument("--seed", type=int, default=42)
    generate.add_argument("--split", choices=["development", "holdout"], default="development")
    generate.add_argument("--background", type=int, default=100)
    detection = commands.add_parser("detect", help="Emit explainable investigation findings as JSON")
    detection.add_argument("--db", type=Path, required=True)
    investigation = commands.add_parser("timeline", help="Read a filtered UTC event timeline")
    investigation.add_argument("--db", type=Path, required=True)
    for field in ["account", "principal", "region", "source"]:
        investigation.add_argument("--" + field)
    investigation.add_argument("--from", dest="started_at")
    investigation.add_argument("--until", dest="ended_at")
    investigation.add_argument("--limit", type=int, default=100)
    investigation.add_argument("--offset", type=int, default=0)
    args = parser.parse_args(argv)
    try:
        if args.command == "ingest":
            result = asdict(ingest_file(args.source, args.db, input_format=args.format, skip_invalid=args.skip_invalid))
        elif args.command == "generate":
            result = write_dataset(args.out, seed=args.seed, split=args.split, background=args.background)
        elif args.command == "detect":
            result = detect(args.db)
        elif args.command == "timeline":
            filters = Filters(**{key: getattr(args, key) for key in ["account", "principal", "region", "source", "started_at", "ended_at"]})
            result = timeline(args.db, filters, limit=args.limit, offset=args.offset)
        else:
            result = summarize(args.db)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except InputError as error:
        print(json.dumps({"error": error.code, "record": error.record}), file=sys.stderr)
    except OSError:
        print(json.dumps({"error": "file_access_error"}), file=sys.stderr)
    except duckdb.Error:
        print(json.dumps({"error": "database_error"}), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
