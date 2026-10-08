"""Collect the report data from the API (read-only) into plain data classes."""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

CATEGORIES = ("security", "bugfix", "enhancement", "other")
SEVERITIES = ("critical", "important", "moderate", "low", "unspecified")
_TYPE_MAP = {
    "security advisory": "security",
    "bug fix advisory": "bugfix",
    "product enhancement advisory": "enhancement",
}


class Api(Protocol):
    def api_version(self) -> str: ...
    def list_systems(self) -> list[dict[str, Any]]: ...
    def relevant_errata(self, system_id: int) -> list[dict[str, Any]]: ...
    def outdated_systems(self) -> list[dict[str, Any]]: ...
    def reboot_suggested(self) -> list[dict[str, Any]]: ...
    def errata_details(self, advisory: str) -> dict[str, Any]: ...


def classify(advisory_type: object) -> str:
    return _TYPE_MAP.get(str(advisory_type or "").strip().lower(), "other")


def normalise_severity(value: object) -> str:
    sev = str(value or "").strip().lower()
    return sev if sev in SEVERITIES else "unspecified"


def to_utc(value: object) -> datetime | None:
    """XML-RPC dateTime values carry no zone; Uyuni servers normally run in UTC."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value:
        for fmt in ("%Y%m%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(value[:19], fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


@dataclass
class SystemRow:
    id: int
    name: str
    last_checkin: str = ""
    security: int = 0
    bugfix: int = 0
    enhancement: int = 0
    other: int = 0
    outdated: bool = False
    reboot_required: bool = False
    stale: bool = False
    severity: dict[str, int] | None = None
    security_advisories: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.security + self.bugfix + self.enhancement + self.other

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["total"] = self.total
        return d


@dataclass
class Report:
    server: str
    api_version: str
    generated_at: str
    inactive_days: int
    with_severity: bool
    filters: list[str]
    systems: list[SystemRow]

    @property
    def summary(self) -> dict[str, int]:
        advisories = {a for s in self.systems for a in s.security_advisories}
        return {
            "systems": len(self.systems),
            "with_security_patches": sum(1 for s in self.systems if s.security),
            "with_any_patches": sum(1 for s in self.systems if s.total),
            "outdated": sum(1 for s in self.systems if s.outdated),
            "reboot_required": sum(1 for s in self.systems if s.reboot_required),
            "stale": sum(1 for s in self.systems if s.stale),
            "security_advisories": len(advisories),
            "pending_security": sum(s.security for s in self.systems),
            "pending_bugfix": sum(s.bugfix for s in self.systems),
            "pending_enhancement": sum(s.enhancement for s in self.systems),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "api_version": self.api_version,
            "generated_at": self.generated_at,
            "inactive_days": self.inactive_days,
            "with_severity": self.with_severity,
            "filters": self.filters,
            "summary": self.summary,
            "systems": [s.to_dict() for s in self.systems],
        }


def _ids(rows: Iterable[dict[str, Any]]) -> set[int]:
    out: set[int] = set()
    for r in rows:
        try:
            out.add(int(r["id"]))
        except (KeyError, TypeError, ValueError):
            continue
    return out


def build(  # noqa: PLR0913 - keyword-only report options
    api: Api,
    *,
    server: str,
    patterns: Sequence[str] = (),
    with_severity: bool = False,
    inactive_days: int = 7,
    now: datetime | None = None,
) -> Report:
    now = now or datetime.now(timezone.utc)
    systems = api.list_systems()
    if patterns:
        systems = [s for s in systems if any(fnmatch.fnmatch(str(s.get("name", "")), p) for p in patterns)]
    outdated = _ids(api.outdated_systems())
    reboot = _ids(api.reboot_suggested())
    severity_cache: dict[str, str] = {}

    rows: list[SystemRow] = []
    for s in systems:
        try:
            sid = int(s["id"])
        except (KeyError, TypeError, ValueError):
            continue
        checkin = to_utc(s.get("last_checkin"))
        row = SystemRow(
            id=sid,
            name=str(s.get("name", "")),
            last_checkin=checkin.isoformat() if checkin else "",
            outdated=sid in outdated,
            reboot_required=sid in reboot,
            stale=bool(inactive_days and checkin and now - checkin > timedelta(days=inactive_days)),
            severity=dict.fromkeys(SEVERITIES, 0) if with_severity else None,
        )
        seen: set[str] = set()
        for erratum in api.relevant_errata(sid):
            name = str(erratum.get("advisory_name", ""))
            if name and name in seen:
                continue
            seen.add(name)
            category = classify(erratum.get("advisory_type"))
            setattr(row, category, getattr(row, category) + 1)
            if category != "security":
                continue
            row.security_advisories.append(name)
            if row.severity is not None:
                if name not in severity_cache:
                    severity_cache[name] = normalise_severity(api.errata_details(name).get("severity"))
                row.severity[severity_cache[name]] += 1
        row.security_advisories.sort()
        rows.append(row)

    rows.sort(key=lambda r: (-r.security, -r.total, not r.reboot_required, r.name.lower()))
    return Report(
        server=server,
        api_version=api.api_version(),
        generated_at=now.replace(microsecond=0).isoformat(),
        inactive_days=inactive_days,
        with_severity=with_severity,
        filters=list(patterns),
        systems=rows,
    )
