import shutil
import ssl
import subprocess  # nosec B404 - test helper runs openssl with fixed arguments
import threading
import xmlrpc.client
from xmlrpc.server import SimpleXMLRPCRequestHandler, SimpleXMLRPCServer

import pytest

from uyuni_patch_reporter.client import (
    READ_ONLY_METHODS,
    ApiError,
    NotAllowedError,
    UyuniClient,
    default_proxy,
    make_ssl_context,
)
from uyuni_patch_reporter.config import from_env

ENV = {
    "UYUNI_URL": "https://uyuni.example.com",
    "UYUNI_USER": "ro",
    "UYUNI_PASSWORD": "test-only-not-a-secret",
}


def test_login_logout_and_session_key(fake):
    with UyuniClient(from_env(ENV), lambda c: fake) as client:
        assert client.list_systems()
    assert fake.calls[0] == ("auth.login", ("ro", "test-only-not-a-secret"))
    assert fake.calls[1] == ("system.listSystems", ("session-key-123",))
    assert fake.logged_out == ["session-key-123"]


def test_logout_even_when_a_call_fails(fake):
    fake.fail["system.listSystems"] = xmlrpc.client.Fault(-1, "boom")
    with (
        pytest.raises(ApiError, match=r"system\.listSystems failed: boom"),
        UyuniClient(from_env(ENV), lambda c: fake) as c,
    ):
        c.list_systems()
    assert fake.logged_out == ["session-key-123"]


def test_only_read_only_methods_can_be_called(fake):
    with UyuniClient(from_env(ENV), lambda c: fake) as client:
        with pytest.raises(NotAllowedError):
            client.call("system.scheduleReboot", 1000010001)
        with pytest.raises(NotAllowedError):
            client.call("system.deleteSystem", 1)
    assert "system.scheduleReboot" not in fake.methods()
    assert all(m.split(".")[1].startswith(("list", "get", "system")) for m in READ_ONLY_METHODS)


def test_wrong_password_gives_clean_error(fake):
    env = {**ENV, "UYUNI_PASSWORD": "wrong-password"}
    with (
        pytest.raises(ApiError, match="login failed for user 'ro'") as exc,
        UyuniClient(from_env(env), lambda c: fake),
    ):
        pass
    assert "wrong-password" not in str(exc.value)


def test_network_errors_become_api_errors(fake):
    fake.fail["auth.login"] = ConnectionRefusedError(111, "Connection refused")
    with pytest.raises(ApiError, match="cannot reach"), UyuniClient(from_env(ENV), lambda c: fake):
        pass


def test_calls_require_login(fake):
    client = UyuniClient(from_env(ENV), lambda c: fake)
    with pytest.raises(ApiError, match="not logged in"):
        client.list_systems()
    client.logout()  # no-op without a session


def test_xml_parser_is_hardened():
    parser, _ = xmlrpc.client.getparser()
    bomb = (
        b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]>'
        b"<methodResponse><params><param><value><string>&b;</string></value></param></params></methodResponse>"
    )
    with pytest.raises(ValueError, match="Entit"):
        parser.feed(bomb)


def test_malformed_response_becomes_api_error(fake):
    fake.fail["system.listSystems"] = ValueError("EntitiesForbidden")
    with (
        pytest.raises(ApiError, match="unsafe or malformed"),
        UyuniClient(from_env(ENV), lambda c: fake) as c,
    ):
        c.list_systems()
    fake.fail["auth.login"] = ValueError("bad xml")
    with pytest.raises(ApiError, match="unsafe or malformed"), UyuniClient(from_env(ENV), lambda c: fake):
        pass


def test_ssl_context_policy():
    ctx = make_ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


# ---- real XML-RPC over HTTPS against a local test server --------------------------------
@pytest.fixture(scope="module")
def tls_material(tmp_path_factory):
    if not shutil.which("openssl"):
        pytest.skip("openssl not available")
    d = tmp_path_factory.mktemp("tls")
    subprocess.run(  # nosec B603
        [
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", str(d / "key.pem"), "-out", str(d / "cert.pem"), "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
        ],
        check=True,
        capture_output=True,
    )  # fmt: skip
    return d


class _Quiet(SimpleXMLRPCServer):
    def handle_error(self, request, client_address):
        pass  # failed TLS handshakes are expected in the negative tests


@pytest.fixture(scope="module")
def https_server(tls_material):
    class Handler(SimpleXMLRPCRequestHandler):
        rpc_paths = ("/rpc/api",)

        def log_message(self, *args):
            pass

    server = _Quiet(("127.0.0.1", 0), requestHandler=Handler, logRequests=False, allow_none=False)
    server.register_function(lambda u, p: "key-1" if p == "test-only-not-a-secret" else 0, "auth.login")
    server.register_function(lambda k: 1, "auth.logout")
    server.register_function(lambda: "25", "api.getVersion")
    server.register_function(lambda k: [{"id": 1, "name": "tls-host"}], "system.listSystems")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tls_material / "cert.pem", tls_material / "key.pem")
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()


def test_https_with_trusted_ca(https_server, tls_material):
    env = {
        **ENV,
        "UYUNI_URL": f"https://localhost:{https_server}",
        "UYUNI_CA_FILE": str(tls_material / "cert.pem"),
    }
    with UyuniClient(from_env(env), default_proxy) as client:
        assert client.list_systems() == [{"id": 1, "name": "tls-host"}]
        assert client.api_version() == "25"


def test_https_untrusted_certificate_is_rejected(https_server):
    env = {**ENV, "UYUNI_URL": f"https://localhost:{https_server}"}
    with pytest.raises(ApiError, match="TLS verification failed"), UyuniClient(from_env(env), default_proxy):
        pass


def test_https_host_name_mismatch_is_rejected(https_server, tls_material):
    env = {
        **ENV,
        "UYUNI_URL": f"https://127.0.0.1:{https_server}",
        "UYUNI_CA_FILE": str(tls_material / "cert.pem"),
    }
    with pytest.raises(ApiError, match="TLS verification failed"), UyuniClient(from_env(env), default_proxy):
        pass
