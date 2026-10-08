from datetime import timezone

from conftest import NOW
from uyuni_patch_reporter.client import UyuniClient
from uyuni_patch_reporter.config import from_env
from uyuni_patch_reporter.report import build, classify, normalise_severity, to_utc

ENV = {
    "UYUNI_URL": "https://uyuni.example.com",
    "UYUNI_USER": "ro",
    "UYUNI_PASSWORD": "test-only-not-a-secret",
}
UTC_NOW = NOW.replace(tzinfo=timezone.utc)


def run(fake, **kw):
    with UyuniClient(from_env(ENV), lambda c: fake) as client:
        return build(client, server="uyuni.example.com", now=UTC_NOW, **kw)


def test_counts_by_category_and_flags(fake):
    report = run(fake)
    rows = {r.name: r for r in report.systems}
    web01 = rows["web01.example.com"]
    assert (web01.security, web01.bugfix, web01.enhancement, web01.other, web01.total) == (2, 1, 1, 0, 4)
    assert web01.outdated and web01.reboot_required and not web01.stale
    assert web01.security_advisories == ["SUSE-SU-2026:1001-1", "SUSE-SU-2026:1002-1"]
    assert rows["db01.example.com"].bugfix == 1  # duplicate advisory counted once
    assert rows["web02.example.com"].other == 1
    assert rows["web02.example.com"].stale  # last check-in 18 days ago
    assert web01.severity is None


def test_sorted_by_security_then_total(fake):
    names = [r.name for r in run(fake).systems]
    assert names[:2] == ["web01.example.com", "web02.example.com"]


def test_summary(fake):
    s = run(fake).summary
    assert s == {
        "systems": 4,
        "with_security_patches": 2,
        "with_any_patches": 3,
        "outdated": 2,
        "reboot_required": 1,
        "stale": 1,
        "security_advisories": 2,
        "pending_security": 3,
        "pending_bugfix": 2,
        "pending_enhancement": 1,
    }


def test_severity_lookup_is_cached(fake):
    report = run(fake, with_severity=True)
    web01 = next(r for r in report.systems if r.name == "web01.example.com")
    assert web01.severity == {"critical": 1, "important": 1, "moderate": 0, "low": 0, "unspecified": 0}
    assert fake.methods().count("errata.getDetails") == 2  # 3 security entries, 2 distinct advisories


def test_name_filter(fake):
    report = run(fake, patterns=["web*"])
    assert [r.name for r in report.systems] == ["web01.example.com", "web02.example.com"]
    assert report.filters == ["web*"]
    assert ("system.getRelevantErrata", ("session-key-123", 1000010002)) not in fake.calls


def test_stale_detection_can_be_disabled(fake):
    assert run(fake, inactive_days=0).summary["stale"] == 0


def test_only_read_only_calls_are_made(fake):
    run(fake, with_severity=True)
    assert set(fake.methods()) <= {
        "auth.login",
        "auth.logout",
        "api.getVersion",
        "system.listSystems",
        "system.getRelevantErrata",
        "system.listOutOfDateSystems",
        "system.listSuggestedReboot",
        "errata.getDetails",
    }


def test_helpers():
    assert classify("Security Advisory") == "security"
    assert classify("bug fix advisory") == "bugfix"
    assert classify(None) == "other"
    assert normalise_severity("Critical") == "critical"
    assert normalise_severity("bogus") == "unspecified"
    assert to_utc("20261008T10:00:00").isoformat() == "2026-10-08T10:00:00+00:00"
    assert to_utc("garbage") is None
    assert to_utc(None) is None
