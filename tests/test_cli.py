import json
import os
import xmlrpc.client

import pytest

from uyuni_patch_reporter import cli


@pytest.fixture(autouse=True)
def _env(uyuni_env):
    pass


def test_table_report(fake_factory, capsys):
    assert cli.main(["--inactive-days", "0"], proxy_factory=fake_factory) == 0
    out = capsys.readouterr().out
    assert "web01.example.com" in out


def test_json_report(fake_factory, capsys):
    assert cli.main(["--format", "json"], proxy_factory=fake_factory) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["systems"] == 4


def test_csv_to_file(fake_factory, tmp_path, capsys):
    target = tmp_path / "report.csv"
    assert cli.main(["-f", "csv", "-o", str(target)], proxy_factory=fake_factory) == 0
    assert target.read_text().startswith("system_id,name,")
    assert oct(target.stat().st_mode & 0o777) == "0o640"
    assert capsys.readouterr().out == ""


def test_output_refuses_symlink(fake_factory, tmp_path):
    (tmp_path / "real").write_text("x")
    os.symlink(tmp_path / "real", tmp_path / "link")
    assert cli.main(["-o", str(tmp_path / "link")], proxy_factory=fake_factory) == 2
    assert (tmp_path / "real").read_text() == "x"


@pytest.mark.parametrize(
    ("fail_on", "code"),
    [("never", 0), ("security", 1), ("reboot", 1), ("outdated", 1), ("any", 1)],
)
def test_fail_on(fake_factory, fail_on, code):
    assert cli.main(["--fail-on", fail_on, "-f", "json"], proxy_factory=fake_factory) == code


def test_fail_on_clean_selection(fake_factory):
    assert cli.main(["--fail-on", "any", "-s", "db01*", "-f", "json"], proxy_factory=fake_factory) == 0


def test_configuration_error_exit_2(monkeypatch, fake_factory, capsys):
    monkeypatch.setenv("UYUNI_URL", "http://uyuni.example.com")
    assert cli.main([], proxy_factory=fake_factory) == 2
    assert "https" in capsys.readouterr().err


def test_api_error_exit_3_without_leaking_password(fake, fake_factory, capsys):
    fake.fail["auth.login"] = xmlrpc.client.Fault(2950, "Either the password or username is incorrect.")
    assert cli.main([], proxy_factory=fake_factory) == 3
    err = capsys.readouterr().err
    assert "login failed" in err
    assert "test-only-not-a-secret" not in err


def test_negative_inactive_days(fake_factory):
    assert cli.main(["--inactive-days", "-1"], proxy_factory=fake_factory) == 2


def test_no_credential_or_tls_options():
    opts = {a for action in cli.build_parser()._actions for a in action.option_strings}
    assert not {o for o in opts if any(w in o for w in ("pass", "user", "insecure", "verify", "token"))}
