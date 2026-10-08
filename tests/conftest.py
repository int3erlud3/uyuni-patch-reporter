"""Shared fixtures: a fake Uyuni XML-RPC proxy with a small, realistic data set."""

from __future__ import annotations

import xmlrpc.client
from datetime import datetime
from types import SimpleNamespace
from typing import Any

import pytest

NOW = datetime(2026, 10, 8, 12, 0, 0)

SYSTEMS = [
    {"id": 1000010001, "name": "web01.example.com", "last_checkin": datetime(2026, 10, 8, 11, 30)},
    {"id": 1000010002, "name": "db01.example.com", "last_checkin": datetime(2026, 10, 8, 10, 0)},
    {"id": 1000010003, "name": "web02.example.com", "last_checkin": datetime(2026, 9, 20, 8, 0)},
    {"id": 1000010004, "name": "=cmd|' /C calc'!A0", "last_checkin": datetime(2026, 10, 8, 9, 0)},
]

SEC = "Security Advisory"
BUG = "Bug Fix Advisory"
ENH = "Product Enhancement Advisory"

ERRATA = {
    1000010001: [
        {
            "id": 1,
            "advisory_name": "SUSE-SU-2026:1001-1",
            "advisory_type": SEC,
            "advisory_synopsis": "openssl",
        },
        {
            "id": 2,
            "advisory_name": "SUSE-SU-2026:1002-1",
            "advisory_type": SEC,
            "advisory_synopsis": "kernel",
        },
        {
            "id": 3,
            "advisory_name": "SUSE-RU-2026:2001-1",
            "advisory_type": BUG,
            "advisory_synopsis": "systemd",
        },
        {
            "id": 4,
            "advisory_name": "SUSE-FU-2026:3001-1",
            "advisory_type": ENH,
            "advisory_synopsis": "zypper",
        },
    ],
    1000010002: [
        {
            "id": 3,
            "advisory_name": "SUSE-RU-2026:2001-1",
            "advisory_type": BUG,
            "advisory_synopsis": "systemd",
        },
        {"id": 3, "advisory_name": "SUSE-RU-2026:2001-1", "advisory_type": BUG, "advisory_synopsis": "dup"},
    ],
    1000010003: [
        {
            "id": 1,
            "advisory_name": "SUSE-SU-2026:1001-1",
            "advisory_type": SEC,
            "advisory_synopsis": "openssl",
        },
        {
            "id": 9,
            "advisory_name": "openSUSE-2026-77",
            "advisory_type": "Unknown Type",
            "advisory_synopsis": "x",
        },
    ],
    1000010004: [],
}

SEVERITY = {"SUSE-SU-2026:1001-1": "Important", "SUSE-SU-2026:1002-1": "Critical"}


class FakeUyuni:
    """Mimics ``xmlrpc.client.ServerProxy`` attribute access (``proxy.system.listSystems``)."""

    def __init__(self, password: str = "test-only-not-a-secret", fail: dict[str, Exception] | None = None):
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.password = password
        self.fail = fail or {}
        self.logged_out: list[str] = []
        self.auth = SimpleNamespace(
            login=self._wrap("auth.login", self._login), logout=self._wrap("auth.logout", self._logout)
        )
        self.api = SimpleNamespace(getVersion=self._wrap("api.getVersion", lambda: "25"))
        self.system = SimpleNamespace(
            listSystems=self._wrap("system.listSystems", self._keyed(lambda: SYSTEMS)),
            getRelevantErrata=self._wrap("system.getRelevantErrata", self._keyed(lambda sid: ERRATA[sid])),
            listOutOfDateSystems=self._wrap(
                "system.listOutOfDateSystems", self._keyed(lambda: [{"id": 1000010001}, {"id": 1000010003}])
            ),
            listSuggestedReboot=self._wrap(
                "system.listSuggestedReboot", self._keyed(lambda: [{"id": 1000010001}])
            ),
            scheduleReboot=self._wrap("system.scheduleReboot", self._keyed(lambda *a: 1)),
        )
        self.errata = SimpleNamespace(
            getDetails=self._wrap(
                "errata.getDetails", self._keyed(lambda name: {"severity": SEVERITY.get(name, "")})
            )
        )

    def _wrap(self, name, fn):
        def call(*args):
            self.calls.append((name, args))
            if name in self.fail:
                raise self.fail[name]
            return fn(*args)

        return call

    def _keyed(self, fn):
        def call(key, *args):
            if key != "session-key-123":
                raise xmlrpc.client.Fault(2950, "Either the password or username is incorrect.")
            return fn(*args)

        return call

    def _login(self, user, password):
        if password != self.password:
            raise xmlrpc.client.Fault(2950, "Either the password or username is incorrect.")
        return "session-key-123"

    def _logout(self, key):
        self.logged_out.append(key)
        return 1

    def methods(self) -> list[str]:
        return [c[0] for c in self.calls]


@pytest.fixture
def fake() -> FakeUyuni:
    return FakeUyuni()


@pytest.fixture
def fake_factory(fake):
    return lambda config: fake


@pytest.fixture
def uyuni_env(monkeypatch):
    for var in ("UYUNI_PASSWORD_FILE", "UYUNI_CA_FILE", "UYUNI_TIMEOUT", "NO_BANNER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("UYUNI_URL", "https://uyuni.example.com")
    monkeypatch.setenv("UYUNI_USER", "report-ro")
    monkeypatch.setenv("UYUNI_PASSWORD", "test-only-not-a-secret")
