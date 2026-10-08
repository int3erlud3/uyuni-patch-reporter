"""Minimal read-only Uyuni / SUSE Manager XML-RPC client.

* TLS certificate and host name verification are always on (there is deliberately no
  option to turn them off); a private CA can be supplied with ``UYUNI_CA_FILE``.
* Only an explicit allow-list of read-only API methods can be called.
* The session key is invalidated with ``auth.logout`` when the client is closed.
* XML parsing is hardened with defusedxml (no entity expansion, bounded gzip decoding).
"""

from __future__ import annotations

import contextlib
import http.client
import ssl

# xmlrpc.client is hardened with defusedxml.xmlrpc.monkey_patch() below.
import xmlrpc.client  # nosec B411
from collections.abc import Callable
from typing import Any

import defusedxml.xmlrpc

from .config import Config

# Reject DTDs/entity expansion and cap gzip-decoded response sizes in xmlrpc.client.
defusedxml.xmlrpc.monkey_patch()

READ_ONLY_METHODS = frozenset(
    {
        "api.getVersion",
        "api.systemVersion",
        "system.listSystems",
        "system.getRelevantErrata",
        "system.listOutOfDateSystems",
        "system.listSuggestedReboot",
        "errata.getDetails",
    }
)


class ApiError(Exception):
    """The API could not be reached or returned an error."""


class NotAllowedError(ApiError):
    """A method outside the read-only allow-list was requested."""


def make_ssl_context(ca_file: str | None = None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # create_default_context() already sets these; asserting them documents the policy.
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


class _Transport(xmlrpc.client.SafeTransport):
    """HTTPS transport with a verified SSL context and a socket timeout."""

    def __init__(self, context: ssl.SSLContext, timeout: float) -> None:
        super().__init__(context=context)
        self._timeout = timeout

    def make_connection(self, host: Any) -> http.client.HTTPConnection:
        conn = super().make_connection(host)
        conn.timeout = self._timeout
        return conn


ProxyFactory = Callable[[Config], Any]


def default_proxy(config: Config) -> xmlrpc.client.ServerProxy:
    transport = _Transport(make_ssl_context(config.ca_file), config.timeout)
    return xmlrpc.client.ServerProxy(config.url, transport=transport, allow_none=False, use_datetime=True)


class UyuniClient:
    """Context manager: logs in on enter and out on exit."""

    def __init__(self, config: Config, proxy_factory: ProxyFactory = default_proxy) -> None:
        self._config = config
        self._proxy = proxy_factory(config)
        self._key: str | None = None

    # -- session ----------------------------------------------------------------------
    def __enter__(self) -> UyuniClient:
        self.login()
        return self

    def __exit__(self, *exc: object) -> None:
        self.logout()

    def login(self) -> None:
        try:
            key = self._proxy.auth.login(self._config.user, self._config.password)
        except xmlrpc.client.Fault:
            raise ApiError(f"login failed for user {self._config.user!r} (check the credentials)") from None
        except (ssl.SSLError, ssl.CertificateError) as exc:
            raise ApiError(f"TLS verification failed for {self._config.host}: {exc}") from None
        except (OSError, xmlrpc.client.ProtocolError) as exc:
            raise ApiError(f"cannot reach {self._config.url}: {exc}") from None
        except ValueError as exc:  # defusedxml rejections and malformed responses
            raise ApiError(f"unsafe or malformed response from {self._config.host}: {exc}") from None
        if not isinstance(key, str) or not key:
            raise ApiError("login returned no session key")
        self._key = key

    def logout(self) -> None:
        if self._key is None:
            return
        key, self._key = self._key, None
        # best effort: the session expires on the server anyway
        with contextlib.suppress(xmlrpc.client.Error, OSError):
            self._proxy.auth.logout(key)

    # -- calls ------------------------------------------------------------------------
    def call(self, method: str, *args: Any, authenticated: bool = True) -> Any:
        if method not in READ_ONLY_METHODS:
            raise NotAllowedError(f"API method {method!r} is not on the read-only allow-list")
        target = self._proxy
        for part in method.split("."):
            target = getattr(target, part)
        if authenticated:
            if self._key is None:
                raise ApiError("not logged in")
            args = (self._key, *args)
        try:
            return target(*args)
        except xmlrpc.client.Fault as exc:
            raise ApiError(f"{method} failed: {exc.faultString}") from None
        except (OSError, xmlrpc.client.ProtocolError) as exc:
            raise ApiError(f"{method} failed: {exc}") from None
        except ValueError as exc:  # defusedxml rejections and malformed responses
            raise ApiError(f"{method}: unsafe or malformed response: {exc}") from None

    def api_version(self) -> str:
        return str(self.call("api.getVersion", authenticated=False))

    def list_systems(self) -> list[dict[str, Any]]:
        return list(self.call("system.listSystems"))

    def relevant_errata(self, system_id: int) -> list[dict[str, Any]]:
        return list(self.call("system.getRelevantErrata", system_id))

    def outdated_systems(self) -> list[dict[str, Any]]:
        return list(self.call("system.listOutOfDateSystems"))

    def reboot_suggested(self) -> list[dict[str, Any]]:
        return list(self.call("system.listSuggestedReboot"))

    def errata_details(self, advisory: str) -> dict[str, Any]:
        return dict(self.call("errata.getDetails", advisory))
