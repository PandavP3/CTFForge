import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from ctfforge.core.cli import main
from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.registration import build_core_registry
from ctfforge.core.tool import ToolContext
from ctfforge.web.cookies import analyze as cookies
from ctfforge.web.cors import analyze as cors
from ctfforge.web.directory_discovery import analyze as discover
from ctfforge.web.headers import analyze as headers
from ctfforge.web.jwt_analyzer import analyze as jwt
from ctfforge.web.url_analyzer import analyze as url


def ctx(tool, **args): return ToolContext("web", tool, args)


def enc(value): return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")


def test_jwt_structure_claim_times_and_no_signature_verification():
    token = enc({"alg": "none", "kid": "key-1"}) + "." + enc({"exp": 1, "nbf": 9999999999}) + ".signature"
    result = jwt(ctx("jwt", token=token, now=100))
    assert result["algorithm"] == "none" and result["key_id"] == "key-1"
    assert result["signature_verified"] is False
    assert result["claims"]["exp"]["interpretation"] == "expired"
    assert any("alg=none" in row["message"] for row in result["findings"])
    assert '"value": "signature"' not in json.dumps(result)


@pytest.mark.parametrize("token", ["abc", "e30.e30", "!.e30.x", "eA.e30.x"])
def test_jwt_bad_tokens(token):
    with pytest.raises(CTFForgeError): jwt(ctx("jwt", token=token))


def test_headers_present_missing_and_weak_configuration():
    result = headers(ctx("headers", header=["Strict-Transport-Security: max-age=0", "Server: nginx/1.2", "X-Content-Type-Options: wrong"]))
    assert result["headers"][0]["present"]
    assert not result["headers"][1]["present"]
    assert result["findings"]
    assert "do not prove" in result["recommendations"][0]


def test_headers_malformed():
    with pytest.raises(CTFForgeError): headers(ctx("headers", header=["oops"]))


def test_cookie_flags_scopes_lifetime_redaction_and_multiple():
    result = cookies(ctx("cookies", header=["Set-Cookie: sid=secret; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=example.test",
                                      "Set-Cookie: pref=private; Max-Age=60; Expires=Wed, 21 Oct 2030 07:28:00 GMT"]))
    assert len(result["cookies"]) == 2
    assert all(c["value"] == "[REDACTED]" for c in result["cookies"])
    assert "secret" not in json.dumps(result) and "private" not in json.dumps(result)
    assert "domain" in result["cookies"][0]["attributes"]
    assert "max-age" in result["cookies"][1]["attributes"]


def test_cors_combinations_specific_vary_and_missing():
    bad = cors(ctx("cors", header=["Access-Control-Allow-Origin: *", "Access-Control-Allow-Credentials: true"]))
    assert bad["findings"]
    specific = cors(ctx("cors", header=["Access-Control-Allow-Origin: https://app.test", "Vary: Origin"]))
    assert specific["findings"] == []
    assert cors(ctx("cors", header=[]))["headers"] == {}


def test_url_duplicate_idn_fragment_and_no_network():
    result = url(ctx("url", input="https://例え.テスト/p%20q?a=1&a=2#frag"))
    assert result["host_ascii"] == "xn--r8jz45g.xn--zckzah"
    assert result["duplicate_parameters"] == ["a"]
    assert result["fragment"] == "frag" and result["percent_encoding_present"]
    assert result["network_requests"] == 0
    with pytest.raises(CTFForgeError): url(ctx("url", input="http://[bad"))


class MockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.endswith("/slow"):
            import time; time.sleep(0.5)
        if self.path.endswith("/redirect"):
            self.send_response(302); self.send_header("Location", "https://other.test/"); self.end_headers(); return
        self.send_response(200 if self.path.endswith("/known") else 404)
        self.send_header("Content-Length", "1000000")
        self.end_headers(); self.wfile.write(b"x" * 1000000)
    def log_message(self, *args): pass


@pytest.fixture
def server():
    httpd = HTTPServer(("127.0.0.1", 0), MockHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True); thread.start()
    yield f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown(); thread.join()


def test_discover_local_server_filters_limits_and_redirects(tmp_path, server):
    words = tmp_path / "words.txt"; words.write_text("known\nmissing\nredirect\n")
    result = discover(ctx("discover", url=server, wordlist=words, status=[200, 302], rate=10))
    if result["paths"] and all("WinError 10013" in row.get("error", "") for row in result["paths"]):
        pytest.skip("Sandbox blocks loopback HTTP client connections (WinError 10013).")
    rows = [r for r in result["paths"] if "status" in r]
    assert [r["status"] for r in rows] == [200, 302], result["paths"]
    assert result["body_read_limit"] == 65536
    assert next(r for r in rows if r["status"] == 302)["redirect_location"].startswith("https://other.test")


def test_discover_validation_and_timeout(tmp_path, server):
    words = tmp_path / "words.txt"; words.write_text("slow\n")
    with pytest.raises(CTFForgeError): discover(ctx("discover", url="file:///tmp", wordlist=words))
    result = discover(ctx("discover", url=server, wordlist=words, timeout=0.2, rate=10))
    assert result["paths"] and result["paths"][0].get("error")


def test_discover_status_filter_redirect_and_read_cap_with_mock(tmp_path, monkeypatch):
    import ctfforge.web.directory_discovery as module
    words = tmp_path / "words.txt"; words.write_text("ok\nredirect\nmissing\n")
    class Response:
        def __init__(self, status):
            self.status = status
            self.headers = {"Content-Length": "1000000", "Location": "https://elsewhere.test/"}
        def read(self, size):
            assert size == module.MAX_BODY + 1
            return b"x" * size
        def close(self): pass
    class Opener:
        def open(self, request, timeout):
            return Response(302 if request.full_url.endswith("redirect") else 200 if request.full_url.endswith("/ok") else 404)
    monkeypatch.setattr(module, "build_opener", lambda handler: Opener())
    result = discover(ctx("discover", url="https://authorized.test", wordlist=words, status=[200, 302], rate=10))
    assert [row["status"] for row in result["paths"]] == [200, 302]
    assert result["body_read_limit"] == module.MAX_BODY


def test_registration_lazy_and_cli():
    registry = build_core_registry()
    assert [s.name for s in registry.list_tools("web")] == ["cookies", "cors", "discover", "headers", "jwt", "url"]
    assert registry.resolve_handler("web", "url")
    assert main(["web", "url", "--input", "https://example.test"]) == 0


def test_discover_cli_requires_wordlist(capsys):
    with pytest.raises(SystemExit) as exc: main(["web", "discover", "--url", "http://localhost"])
    assert exc.value.code == 2
