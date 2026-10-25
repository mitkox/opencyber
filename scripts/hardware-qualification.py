#!/usr/bin/env python3
"""Prepare and verify operator-attested hardware evidence; never operates devices."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from lib.qualification import collect_qualification, qualification_template, validate_qualification


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    template = commands.add_parser("template", help="write an incomplete per-domain checklist")
    template.add_argument("--commit", required=True)
    template.add_argument("--candidate-run-id", required=True, type=int)
    template.add_argument("--output", required=True, type=Path)
    collect = commands.add_parser("collect", help="copy and checksum completed operator observations")
    collect.add_argument("manifest", type=Path)
    collect.add_argument("--evidence-root", required=True, type=Path)
    collect.add_argument("--output", required=True, type=Path)
    verify = commands.add_parser("verify", help="verify the complete portable qualification bundle")
    verify.add_argument("bundle", type=Path)
    verify.add_argument("--commit", required=True)
    for command in (template, collect, verify):
        command.add_argument("--records", required=True, type=Path, help="validated candidate receipt list")
    args = parser.parse_args()
    try:
        records = json.loads(args.records.read_text(encoding="utf-8"))
        if args.action == "template":
            bundle = qualification_template(commit=args.commit, candidate_run_id=args.candidate_run_id, records=records)
            with args.output.open("x", encoding="utf-8") as handle:
                handle.write(json.dumps(bundle, indent=2, sort_keys=True) + "\n")
            print(json.dumps({"status": "pending", "path": str(args.output)}))
        elif args.action == "collect":
            path = collect_qualification(args.manifest, evidence_root=args.evidence_root, output=args.output, records=records)
            print(json.dumps({"status": "collected", "path": str(path)}))
        else:
            bundle = validate_qualification(args.bundle, commit=args.commit, records=records)
            print(json.dumps(bundle, sort_keys=True))
    except (OSError, ValueError, TypeError) as exc:
        print("hardware qualification refused: " + str(exc), file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
