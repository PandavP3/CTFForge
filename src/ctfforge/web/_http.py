"""Small bounded HTTP helpers shared by the web analyzers."""
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPRedirectHandler

from ctfforge.core.exceptions import CTFForgeError

MAX_HEADER_BODY = 65536


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def valid_http_url(value: str) -> bool:
    from urllib.parse import urlsplit
    try:
        parsed = urlsplit(value)
        return parsed.scheme.lower() in ("http", "https") and bool(parsed.hostname)
    except ValueError:
        return False


def fetch_headers(url: str, method: str = "GET") -> tuple[list[tuple[str, str]], int | None]:
    if not valid_http_url(url):
        raise CTFForgeError("Target must be an absolute HTTP or HTTPS URL with a hostname.")
    request = Request(url, method=method, headers={"User-Agent": "CTFForge/0.1 (authorized analysis)"})
    opener = build_opener(_NoRedirect)
    try:
        response = opener.open(request, timeout=5)
    except HTTPError as exc:
        response = exc
    except (URLError, TimeoutError, OSError) as exc:
        raise CTFForgeError(f"HTTP request failed: {exc}") from exc
    try:
        response.read(MAX_HEADER_BODY)
        return list(response.headers.items()), response.status
    finally:
        response.close()


def parse_headers(values: object) -> list[tuple[str, str]]:
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, (list, tuple)):
        raise CTFForgeError("Headers must be supplied as repeated --header values.")
    result = []
    for value in values:
        text = str(value)
        if ":" not in text:
            raise CTFForgeError(f"Malformed header (expected Name: value): {text!r}")
        name, content = text.split(":", 1)
        if not name.strip() or any(c in name for c in "\r\n"):
            raise CTFForgeError("Malformed header name.")
        result.append((name.strip(), content.strip()))
    return result
