"""Container health and capability probe.

`opencyber-doctor` answers the question an operator or agent actually asks:
"is this image able to do the work, and what is missing?" It exits non-zero
when degraded, so it is safe to use as a healthcheck or a release gate.
"""

from __future__ import annotations

import argparse
import json
import sys

from .diagnostics import doctor_report, format_report


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="opencyber-doctor",
        description="Report OpenCyber Harness readiness and exit non-zero when degraded.",
    )
    parser.add_argument("--quiet", action="store_true", help="print only problems")
    parser.add_argument("--json", action="store_true", help="emit the full report as JSON")
    args = parser.parse_args()

    report = doctor_report()

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    elif args.quiet:
        for problem in report["problems"]:
            print(f"opencyber-doctor: {problem}", file=sys.stderr)
    else:
        print(format_report(report))

    raise SystemExit(0 if report["status"] == "ok" else 1)


if __name__ == "__main__":
    main()
