import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from .reporting import diff_reports, render_markdown, render_sarif
from .scanner import ScanError, Scanner
from .scope import Scope, ScopeError


def _write(path: Optional[str], content: str) -> None:
    if path:
        Path(path).write_text(content)
    else:
        print(content)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="surfaceproof", description="Evidence-first public artifact auditor")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan explicitly scoped public artifacts")
    scan.add_argument("urls", nargs="+")
    scan.add_argument("--scope", required=True)
    scan.add_argument("--json", dest="json_output", required=True)
    scan.add_argument("--markdown")
    scan.add_argument("--sarif")
    diff = sub.add_parser("diff", help="compare finding fingerprints in two reports")
    diff.add_argument("old")
    diff.add_argument("new")
    diff.add_argument("--output")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "diff":
            old = json.loads(Path(args.old).read_text())
            new = json.loads(Path(args.new).read_text())
            _write(args.output, json.dumps(diff_reports(old, new), indent=2) + "\n")
            return 0
        scope = Scope.from_file(Path(args.scope))
        report = Scanner(scope).scan(args.urls)
        Path(args.json_output).write_text(json.dumps(report.to_dict(), indent=2) + "\n")
        if args.markdown:
            Path(args.markdown).write_text(render_markdown(report))
        if args.sarif:
            Path(args.sarif).write_text(json.dumps(render_sarif(report), indent=2) + "\n")
        return 0
    except (ScopeError, ScanError, OSError, json.JSONDecodeError) as exc:
        print(f"surfaceproof: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
