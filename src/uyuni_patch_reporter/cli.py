"""Command-line interface."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence

from . import __version__
from .banner import maybe_print_banner, maybe_print_banner_for_info
from .client import ApiError, ProxyFactory, UyuniClient, default_proxy
from .config import ConfigError, from_env
from .output import RENDERERS
from .report import Report, build

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE, EXIT_API = 0, 1, 2, 3

EPILOG = """\
configuration (environment variables only):
  UYUNI_URL            https://uyuni.example.com  (https is mandatory)
  UYUNI_USER           API user; a read-only account is sufficient
  UYUNI_PASSWORD_FILE  file containing the password (mode 0600), or
  UYUNI_PASSWORD       the password itself
  UYUNI_CA_FILE        CA bundle for a private CA (verification cannot be disabled)
  UYUNI_TIMEOUT        socket timeout in seconds (default 30)

exit codes: 0 report produced, 1 --fail-on condition met, 2 usage or configuration error,
            3 API, TLS or connection error
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="uyuni-patch-reporter",
        description="Read-only report of pending patches, outdated systems and required reboots "
        "from Uyuni / SUSE Manager.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-f", "--format", choices=sorted(RENDERERS), default="table", help="output format")
    p.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE instead of stdout")
    p.add_argument(
        "-s",
        "--system",
        action="append",
        default=[],
        metavar="PATTERN",
        help="only systems whose name matches the shell pattern (repeatable), e.g. 'web*'",
    )
    p.add_argument(
        "--with-severity",
        action="store_true",
        help="look up the severity of each security advisory (one extra API call per advisory)",
    )
    p.add_argument(
        "--inactive-days",
        type=int,
        default=7,
        metavar="N",
        help="flag systems without check-in for more than N days as stale (0 = off, default 7)",
    )
    p.add_argument(
        "--fail-on",
        choices=["never", "security", "reboot", "outdated", "any"],
        default="never",
        help="exit 1 if a system has pending security patches / needs a reboot / is outdated",
    )
    p.add_argument(
        "--no-banner", action="store_true", help="do not print the startup banner (or set NO_BANNER=1)"
    )
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def findings(report: Report, fail_on: str) -> bool:
    s = report.summary
    checks = {
        "security": s["with_security_patches"] > 0,
        "reboot": s["reboot_required"] > 0,
        "outdated": s["outdated"] > 0,
    }
    if fail_on == "any":
        return any(checks.values())
    return checks.get(fail_on, False)


def write_output(path: str, text: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o640)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def main(argv: Sequence[str] | None = None, proxy_factory: ProxyFactory = default_proxy) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    maybe_print_banner_for_info(argv)
    args = build_parser().parse_args(argv)
    if args.format == "table":  # never mix the banner with machine-readable output
        maybe_print_banner(args.no_banner)
    if args.inactive_days < 0:
        print("uyuni-patch-reporter: error: --inactive-days must be >= 0", file=sys.stderr)
        return EXIT_USAGE

    try:
        config = from_env()
    except ConfigError as exc:
        print(f"uyuni-patch-reporter: configuration error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        with UyuniClient(config, proxy_factory) as client:
            report = build(
                client,
                server=config.host,
                patterns=args.system,
                with_severity=args.with_severity,
                inactive_days=args.inactive_days,
            )
    except ApiError as exc:
        print(f"uyuni-patch-reporter: error: {exc}", file=sys.stderr)
        return EXIT_API

    text = RENDERERS[args.format](report)
    if args.output:
        try:
            write_output(args.output, text)
        except OSError as exc:
            print(f"uyuni-patch-reporter: cannot write {args.output}: {exc.strerror}", file=sys.stderr)
            return EXIT_USAGE
    else:
        sys.stdout.write(text)
    return EXIT_FINDINGS if findings(report, args.fail_on) else EXIT_OK
