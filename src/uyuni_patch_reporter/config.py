"""Configuration from environment variables only (no credentials on the command line)."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

API_PATH = "/rpc/api"


class ConfigError(Exception):
    """Invalid or missing configuration."""


@dataclass(frozen=True)
class Config:
    url: str
    user: str
    password: str = field(repr=False)
    ca_file: str | None = None
    timeout: float = 30.0

    def __repr__(self) -> str:  # never show the password, even in tracebacks
        return f"Config(url={self.url!r}, user={self.user!r}, password='***', ca_file={self.ca_file!r})"

    @property
    def host(self) -> str:
        return urlsplit(self.url).hostname or ""


def _read_secret_file(path: str) -> str:
    p = Path(path)
    try:
        st = p.stat()
    except OSError as exc:
        raise ConfigError(f"UYUNI_PASSWORD_FILE is not readable: {exc.strerror}") from None
    if not stat.S_ISREG(st.st_mode):
        raise ConfigError("UYUNI_PASSWORD_FILE must be a regular file")
    if st.st_mode & 0o077:
        raise ConfigError("UYUNI_PASSWORD_FILE must not be accessible by group/others (chmod 600)")
    try:
        lines = p.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"UYUNI_PASSWORD_FILE cannot be read: {exc}") from None
    return lines[0] if lines else ""


def normalise_url(raw: str) -> str:
    """Accept ``https://host[:port][/rpc/api]`` and return the full API endpoint."""
    raw = raw.strip()
    if not raw:
        raise ConfigError("UYUNI_URL is not set (e.g. https://uyuni.example.com)")
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme != "https":
        raise ConfigError("UYUNI_URL must use https:// (TLS verification is always enabled)")
    if not parts.hostname:
        raise ConfigError("UYUNI_URL has no host name")
    if parts.username or parts.password:
        raise ConfigError("UYUNI_URL must not contain credentials; use UYUNI_USER / UYUNI_PASSWORD_FILE")
    if parts.query or parts.fragment:
        raise ConfigError("UYUNI_URL must not contain a query string or fragment")
    path = parts.path.rstrip("/")
    if path not in ("", API_PATH):
        raise ConfigError(f"UYUNI_URL path must be empty or {API_PATH}")
    try:
        port = parts.port
    except ValueError:
        raise ConfigError("UYUNI_URL has an invalid port") from None
    host = parts.hostname
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    netloc = host if port is None else f"{host}:{port}"
    return f"https://{netloc}{API_PATH}"


def from_env(env: Mapping[str, str] | None = None) -> Config:
    env = os.environ if env is None else env
    url = normalise_url(env.get("UYUNI_URL", ""))
    user = env.get("UYUNI_USER", "").strip()
    if not user:
        raise ConfigError("UYUNI_USER is not set (use a read-only API user)")
    pw_file = env.get("UYUNI_PASSWORD_FILE", "").strip()
    password = env.get("UYUNI_PASSWORD", "")
    if pw_file and password:
        raise ConfigError("set either UYUNI_PASSWORD_FILE or UYUNI_PASSWORD, not both")
    if pw_file:
        password = _read_secret_file(pw_file)
    if not password:
        raise ConfigError("no password: set UYUNI_PASSWORD_FILE (preferred) or UYUNI_PASSWORD")
    ca_file = env.get("UYUNI_CA_FILE", "").strip() or None
    if ca_file and not os.access(ca_file, os.R_OK):
        raise ConfigError("UYUNI_CA_FILE is not readable")
    raw_timeout = env.get("UYUNI_TIMEOUT", "").strip() or "30"
    try:
        timeout = float(raw_timeout)
    except ValueError:
        raise ConfigError("UYUNI_TIMEOUT must be a number of seconds") from None
    if not 1 <= timeout <= 600:
        raise ConfigError("UYUNI_TIMEOUT must be between 1 and 600 seconds")
    return Config(url=url, user=user, password=password, ca_file=ca_file, timeout=timeout)
