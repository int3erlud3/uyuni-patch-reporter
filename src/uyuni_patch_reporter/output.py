"""Render a report as an aligned text table, JSON or CSV."""

from __future__ import annotations

import csv
import io
import json
import re

from .report import SEVERITIES, Report

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def clean(text: str) -> str:
    """Strip control characters (terminal escape injection via system names)."""
    return _CONTROL.sub("?", text)


def csv_safe(value: object) -> object:
    """Neutralise spreadsheet formula injection (CWE-1236) in text cells."""
    if isinstance(value, str) and value.startswith(_FORMULA_START):
        return "'" + value
    return value


def _yn(flag: bool) -> str:
    return "yes" if flag else "-"


def render_table(report: Report) -> str:
    s = report.summary
    out = [
        (
            f"Uyuni patch report - {clean(report.server)} (API {clean(report.api_version)})"
            f" - {report.generated_at}"
        ),
        (
            f"Systems: {s['systems']} | with security patches: {s['with_security_patches']} | "
            f"outdated: {s['outdated']} | reboot required: {s['reboot_required']} | "
            f"stale (>{report.inactive_days}d): {s['stale']}"
        ),
        (
            f"Pending: {s['pending_security']} security, {s['pending_bugfix']} bugfix, "
            f"{s['pending_enhancement']} enhancement "
            f"({s['security_advisories']} distinct security advisories)"
        ),
        "",
    ]
    if not report.systems:
        out.append("No systems matched.")
        return "\n".join(out) + "\n"
    header = [
        "SYSTEM",
        "ID",
        "SECURITY",
        "BUGFIX",
        "ENHANCE",
        "OTHER",
        "TOTAL",
        "OUTDATED",
        "REBOOT",
        "LAST CHECK-IN",
    ]
    rows = []
    for r in report.systems:
        sec = str(r.security)
        if r.severity is not None and r.security:
            parts = [f"{k[0].upper()}{r.severity[k]}" for k in SEVERITIES if r.severity[k]]
            sec += f" ({' '.join(parts)})"
        checkin = r.last_checkin[:16].replace("T", " ") + (" STALE" if r.stale else "")
        rows.append(
            [
                clean(r.name),
                str(r.id),
                sec,
                str(r.bugfix),
                str(r.enhancement),
                str(r.other),
                str(r.total),
                _yn(r.outdated),
                _yn(r.reboot_required),
                checkin,
            ]
        )
    widths = [max(len(x) for x in col) for col in zip(header, *rows, strict=True)]
    for line in [header, *rows]:
        out.append("  ".join(cell.ljust(w) for cell, w in zip(line, widths, strict=True)).rstrip())
    if report.with_severity:
        out.append("")
        out.append(
            "Severity of security advisories: C critical, I important, M moderate, L low, U unspecified"
        )
    return "\n".join(out) + "\n"


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"


CSV_FIELDS = [
    "system_id",
    "name",
    "last_checkin",
    "security",
    "bugfix",
    "enhancement",
    "other",
    "total",
    "outdated",
    "reboot_required",
    "stale",
    *SEVERITIES,
    "security_advisories",
]


def render_csv(report: Report) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(CSV_FIELDS)
    for r in report.systems:
        sev = [r.severity[k] if r.severity is not None else "" for k in SEVERITIES]
        row = [
            r.id,
            r.name,
            r.last_checkin,
            r.security,
            r.bugfix,
            r.enhancement,
            r.other,
            r.total,
            str(r.outdated).lower(),
            str(r.reboot_required).lower(),
            str(r.stale).lower(),
            *sev,
            " ".join(r.security_advisories),
        ]
        writer.writerow([csv_safe(v) for v in row])
    return buf.getvalue()


RENDERERS = {"table": render_table, "json": render_json, "csv": render_csv}
