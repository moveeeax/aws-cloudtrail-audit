"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .report import render_json, render_text
from .rules import RULE_NAMES, SEVERITIES, evaluate

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-cloudtrail-audit",
        description=(
            "Audit CloudTrail configuration for the gaps that make an "
            "incident uninvestigable."
        ),
    )
    parser.add_argument("--version", action="version", version=__version__)

    source = parser.add_argument_group("source")
    source.add_argument("--profile", help="AWS profile to collect with")
    source.add_argument("--region", action="append", dest="regions", metavar="REGION",
                        help="limit collection to this region (repeatable)")
    source.add_argument("--from-json", metavar="FILE",
                        help="replay a cached payload instead of calling AWS")
    source.add_argument("--dump-json", metavar="FILE",
                        help="write the collected payload to FILE")

    output = parser.add_argument_group("output")
    output.add_argument("--format", choices=("text", "json"), default="text")
    output.add_argument("--severity", choices=SEVERITIES, default="low",
                        help="minimum severity to report (default: low)")

    control = parser.add_argument_group("filtering")
    control.add_argument("--ignore-rule", action="append", default=[], metavar="RULE")
    control.add_argument("--ignore-trail", action="append", default=[], metavar="TRAIL")
    control.add_argument("--fail-on", default="", metavar="RULES",
                         help="comma-separated rules that make the run exit 1")
    control.add_argument("--list-rules", action="store_true",
                         help="print the rule names and exit")

    return parser


def _split(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _unknown(names: Sequence[str]) -> list[str]:
    return [name for name in names if name not in RULE_NAMES]


def _load_payload(args: argparse.Namespace) -> dict[str, Any]:
    if args.from_json:
        with open(args.from_json, encoding="utf-8") as handle:
            return json.load(handle)

    import boto3  # imported lazily so the rule engine stays dependency-free

    from .collect import collect

    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
    return collect(session, regions=args.regions)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        for name in RULE_NAMES:
            print(name)
        return EXIT_OK

    fail_on = _split(args.fail_on)
    bad = _unknown(fail_on) + _unknown(args.ignore_rule)
    if bad:
        parser.error("unknown rule name(s): " + ", ".join(sorted(set(bad))))

    try:
        payload = _load_payload(args)
    except FileNotFoundError as exc:
        print(f"aws-cloudtrail-audit: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except json.JSONDecodeError as exc:
        print(f"aws-cloudtrail-audit: invalid payload JSON: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.dump_json:
        Path(args.dump_json).write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8"
        )

    findings = evaluate(
        payload,
        ignore_rules=args.ignore_rule,
        ignore_trails=args.ignore_trail,
        min_severity=args.severity,
    )

    render = render_json if args.format == "json" else render_text
    sys.stdout.write(render(findings, payload))

    if fail_on and any(f.rule in fail_on for f in findings):
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
