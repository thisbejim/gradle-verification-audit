from __future__ import annotations

import argparse
import sys

from .engine import audit_file
from .report import json_report, sarif_report, text_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gradle-verification-audit",
        description="Audit Gradle dependency verification metadata offline, without running Gradle or using a network.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default="gradle/verification-metadata.xml",
        help="metadata file, or a project directory containing gradle/verification-metadata.xml",
    )
    parser.add_argument(
        "--format", choices=("text", "json", "sarif"), default="text", help="output format"
    )
    parser.add_argument(
        "--secure",
        action="store_true",
        help="require sha256/sha512 and fail on weak-only verification",
    )
    parser.add_argument("--strict", action="store_true", help="treat warnings as failures")
    parser.add_argument(
        "--quiet", action="store_true", help="suppress human output when the audit passes"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = audit_file(args.path, secure=args.secure)
    failed = bool(result.errors) or (args.strict and bool(result.warnings))
    if args.format == "json":
        output = json_report(result)
    elif args.format == "sarif":
        output = sarif_report(result)
    else:
        output = text_report(result)
    if not (args.quiet and not failed and args.format == "text"):
        sys.stdout.write(output)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
