import os

import pytest

from uyuni_patch_reporter.config import ConfigError, from_env, normalise_url

BASE = {
    "UYUNI_URL": "https://uyuni.example.com",
    "UYUNI_USER": "ro",
    "UYUNI_PASSWORD": "test-only-not-a-secret",
}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://uyuni.example.com", "https://uyuni.example.com/rpc/api"),
        ("https://uyuni.example.com/", "https://uyuni.example.com/rpc/api"),
        ("https://uyuni.example.com/rpc/api", "https://uyuni.example.com/rpc/api"),
        ("uyuni.example.com:8443", "https://uyuni.example.com:8443/rpc/api"),
        ("https://[2001:db8::1]:443", "https://[2001:db8::1]:443/rpc/api"),
    ],
)
def test_url_normalisation(raw, expected):
    assert normalise_url(raw) == expected


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("", "not set"),
        ("http://uyuni.example.com", "https"),
        ("https://user:pw@uyuni.example.com", "credentials"),
        ("https://uyuni.example.com/other", "path"),
        ("https://uyuni.example.com/?x=1", "query"),
        ("https://uyuni.example.com:99999", "port"),
        ("https://", "host"),
    ],
)
def test_invalid_urls(raw, message):
    with pytest.raises(ConfigError, match=message):
        normalise_url(raw)


def test_from_env_and_password_masked():
    cfg = from_env(BASE)
    assert cfg.url == "https://uyuni.example.com/rpc/api"
    assert cfg.host == "uyuni.example.com"
    assert cfg.timeout == 30
    assert "test-only-not-a-secret" not in repr(cfg)
    assert "test-only-not-a-secret" not in str(cfg)


def test_password_file(tmp_path):
    f = tmp_path / "pw"
    f.write_text("from-file\nignored\n")
    os.chmod(f, 0o600)
    env = {**BASE, "UYUNI_PASSWORD": "", "UYUNI_PASSWORD_FILE": str(f)}
    assert from_env(env).password == "from-file"
    os.chmod(f, 0o640)
    with pytest.raises(ConfigError, match="chmod 600"):
        from_env(env)


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"UYUNI_USER": ""}, "UYUNI_USER"),
        ({"UYUNI_PASSWORD": ""}, "no password"),
        ({"UYUNI_PASSWORD_FILE": "/nonexistent"}, "not both"),
        ({"UYUNI_PASSWORD": "", "UYUNI_PASSWORD_FILE": "/nonexistent/pw"}, "not readable"),
        ({"UYUNI_PASSWORD": "", "UYUNI_PASSWORD_FILE": "/"}, "regular file"),
        ({"UYUNI_CA_FILE": "/nonexistent/ca.pem"}, "UYUNI_CA_FILE"),
        ({"UYUNI_TIMEOUT": "abc"}, "number"),
        ({"UYUNI_TIMEOUT": "0"}, "between"),
    ],
)
def test_invalid_env(override, message):
    with pytest.raises(ConfigError, match=message):
        from_env({**BASE, **override})
