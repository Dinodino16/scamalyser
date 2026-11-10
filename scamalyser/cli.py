"""Command-line interface.

    scamalyser suspicious.eml            # human-readable report
    scamalyser suspicious.eml --json     # machine-readable, for scripts/the web UI
    scamalyser suspicious.eml --online   # also verify DKIM and look up DMARC in DNS
    scamalyser suspicious.eml --no-banner  # skip the start-up banner

The banner is only printed to an interactive terminal, never with --json or
when output is piped or redirected.

Exit code is 0 for LOW, 1 for SUSPICIOUS, 2 for LIKELY PHISHING, so the tool
can be used in scripts (e.g. a mail filter) without parsing output.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap

from . import __version__
from .analyser import Report, Verdict, analyse
from .banner import BANNER
from .findings import Severity
from .parser import parse_file

EXIT_CODES = {Verdict.LOW: 0, Verdict.SUSPICIOUS: 1, Verdict.PHISHING: 2}

_COLOURS = {
    Severity.HIGH: "\033[31m", Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m", Severity.INFO: "\033[2m",
    Verdict.PHISHING: "\033[1;31m", Verdict.SUSPICIOUS: "\033[1;33m", Verdict.LOW: "\033[1;32m",
}
_RESET = "\033[0m"


def _use_colour(stream) -> bool:
    return stream.isatty() and "NO_COLOR" not in os.environ


def format_report(report: Report, colour: bool = False, show_info: bool = True) -> str:
    def c(key, text: str) -> str:
        return f"{_COLOURS[key]}{text}{_RESET}" if colour else text

    lines = [
        f"Subject: {report.subject}",
        f"From:    {report.sender}",
        f"Links:   {report.links_checked} checked",
        "",
        c(report.verdict, f"Risk score: {report.score}/100  ->  {report.verdict.value}"),
        "",
    ]
    shown = [f for f in report.findings if show_info or f.severity is not Severity.INFO]
    if not shown:
        lines.append("No warning signs found.")
    for f in shown:
        points = f"+{f.points}" if f.points else "  ."
        lines.append(c(f.severity, f"[{points:>3}] {f.severity.value.upper():<6} {f.title}"))
        lines.extend(textwrap.wrap(f.detail, width=78, initial_indent="       ",
                                   subsequent_indent="       "))
    return "\n".join(lines)


def should_show_banner(args: argparse.Namespace, stream) -> bool:
    """Only greet humans: skip the banner for JSON, pipes/redirects and --no-banner,
    so scripts that read Scamalyser's output never have to strip it."""
    return not (args.no_banner or args.json) and stream.isatty()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scamalyser",
        description="Analyse a .eml file for signs of phishing and explain the risk score.",
    )
    p.add_argument("eml", help="path to an email saved as .eml")
    p.add_argument("--json", action="store_true", help="output the report as JSON")
    p.add_argument("--online", action="store_true",
                   help="verify DKIM and look up the sender's DMARC policy via DNS")
    p.add_argument("--no-banner", action="store_true", help="don't print the start-up banner")
    p.add_argument("--quiet", "-q", action="store_true",
                   help="hide informational findings that carry no points")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if should_show_banner(args, sys.stdout):
        colour = _use_colour(sys.stdout)
        print(f"\033[1;36m{BANNER}{_RESET}" if colour else BANNER)
    try:
        email = parse_file(args.eml)
    except OSError as exc:
        print(f"scamalyser: cannot read {args.eml}: {exc.strerror}", file=sys.stderr)
        return 3

    report = analyse(email, online=args.online)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(format_report(report, colour=_use_colour(sys.stdout), show_info=not args.quiet))
    return EXIT_CODES[report.verdict]


if __name__ == "__main__":
    sys.exit(main())
