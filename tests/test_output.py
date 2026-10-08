import csv
import io
import json
from datetime import timezone

from conftest import NOW
from uyuni_patch_reporter.client import UyuniClient
from uyuni_patch_reporter.config import from_env
from uyuni_patch_reporter.output import CSV_FIELDS, clean, csv_safe, render_csv, render_json, render_table
from uyuni_patch_reporter.report import Report, SystemRow, build

ENV = {
    "UYUNI_URL": "https://uyuni.example.com",
    "UYUNI_USER": "ro",
    "UYUNI_PASSWORD": "test-only-not-a-secret",
}


def make_report(fake, **kw):
    with UyuniClient(from_env(ENV), lambda c: fake) as client:
        return build(client, server="uyuni.example.com", now=NOW.replace(tzinfo=timezone.utc), **kw)


def test_table(fake):
    text = render_table(make_report(fake, with_severity=True))
    lines = text.splitlines()
    assert lines[0].startswith("Uyuni patch report - uyuni.example.com (API 25)")
    assert "with security patches: 2" in lines[1]
    assert "reboot required: 1" in lines[1]
    header = next(line for line in lines if line.startswith("SYSTEM"))
    assert "SECURITY" in header and "REBOOT" in header
    web01 = next(line for line in lines if line.startswith("web01"))
    assert "2 (C1 I1)" in web01
    assert "yes" in web01
    assert "STALE" in next(line for line in lines if line.startswith("web02"))


def test_table_empty():
    r = Report("srv", "25", "2026-10-08T12:00:00+00:00", 7, False, [], [])
    assert "No systems matched." in render_table(r)


def test_table_strips_terminal_escapes():
    row = SystemRow(id=1, name="evil\x1b]0;pwned\x07host")
    r = Report("srv", "25", "now", 7, False, [], [row])
    assert "\x1b" not in render_table(r)
    assert clean("a\x1b[31mb") == "a?[31mb"


def test_json(fake):
    data = json.loads(render_json(make_report(fake)))
    assert data["server"] == "uyuni.example.com"
    assert data["summary"]["systems"] == 4
    web01 = data["systems"][0]
    assert web01["name"] == "web01.example.com"
    assert web01["total"] == 4
    assert web01["reboot_required"] is True
    assert web01["last_checkin"] == "2026-10-08T11:30:00+00:00"


def test_csv_with_formula_injection_protection(fake):
    rows = list(csv.reader(io.StringIO(render_csv(make_report(fake)))))
    assert rows[0] == CSV_FIELDS
    names = [r[1] for r in rows[1:]]
    assert "'=cmd|' /C calc'!A0" in names
    assert all(not n.startswith(("=", "+", "-", "@")) for n in names)
    web01 = rows[1]
    assert web01[CSV_FIELDS.index("security")] == "2"
    assert web01[CSV_FIELDS.index("reboot_required")] == "true"
    assert web01[CSV_FIELDS.index("critical")] == ""  # severity not requested
    assert web01[-1] == "SUSE-SU-2026:1001-1 SUSE-SU-2026:1002-1"


def test_csv_safe():
    assert csv_safe("=1+1") == "'=1+1"
    assert csv_safe("@SUM(A1)") == "'@SUM(A1)"
    assert csv_safe("-2") == "'-2"
    assert csv_safe("web01") == "web01"
    assert csv_safe(5) == 5
