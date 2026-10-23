"""Command-line entry point. Errors deliberately omit log values and paths."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

import duckdb

from .ingest import ingest_file, summarize
from .model import InputError


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
    args = parser.parse_args(argv)
    try:
        if args.command == "ingest":
            result = asdict(ingest_file(args.source, args.db, input_format=args.format, skip_invalid=args.skip_invalid))
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
