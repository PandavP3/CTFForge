"""Bounded, non-recursive path checks for explicitly authorized HTTP targets."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Event, Lock
from time import monotonic, sleep
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler

from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult
from ._http import valid_http_url

MAX_WORDS = 10000
MAX_BODY = 65536


class _StopRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None


def analyze(context: ToolContext) -> ToolResult:
    args = context.arguments
    target = str(args.get("url", ""))
    if not valid_http_url(target): raise CTFForgeError("Target must be an absolute HTTP or HTTPS URL.")
    timeout, rate, workers = float(args.get("timeout", 5)), float(args.get("rate", 2)), int(args.get("concurrency", 2))
    if not 0.2 <= timeout <= 30: raise CTFForgeError("Timeout must be between 0.2 and 30 seconds.")
    if not 0.1 <= rate <= 10: raise CTFForgeError("Rate must be between 0.1 and 10 requests per second.")
    if not 1 <= workers <= 5: raise CTFForgeError("Concurrency must be between 1 and 5.")
    wordfile = Path(args["wordlist"]).expanduser()
    try: words = [line.strip().lstrip("/") for line in wordfile.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")]
    except OSError as exc: raise CTFForgeError(f"Cannot read wordlist: {exc}") from exc
    if not words or len(words) > MAX_WORDS: raise CTFForgeError(f"Wordlist must contain 1 to {MAX_WORDS} entries.")
    base = urlsplit(target)
    prefix = urlunsplit((base.scheme, base.netloc, base.path.rstrip("/"), "", ""))
    allowed = set(args.get("status") or [])
    lock, next_slot = Lock(), [0.0]
    def check(word):
        path = "/".join(part for part in word.split("/") if part and part not in (".", ".."))
        url = prefix + "/" + path
        with lock:
            wait = next_slot[0] - monotonic()
            if wait > 0: sleep(wait)
            next_slot[0] = monotonic() + 1 / rate
        req = Request(url, headers={"User-Agent": "CTFForge/0.1 (authorized path discovery)"})
        try:
            resp = build_opener(_StopRedirect).open(req, timeout=timeout)
        except HTTPError as exc: resp = exc
        except (URLError, TimeoutError, OSError) as exc: return {"path": path, "error": str(exc)}
        try:
            body = resp.read(MAX_BODY + 1)
            row = {"path": path, "status": resp.status, "content_length": resp.headers.get("Content-Length") or len(body), "redirect_location": resp.headers.get("Location")}
            return row if not allowed or resp.status in allowed else None
        finally: resp.close()
    results = []
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(check, word) for word in words]
            for future in as_completed(futures):
                row = future.result()
                if row is not None: results.append(row)
    except KeyboardInterrupt:
        raise CTFForgeError("Discovery interrupted; outstanding requests are stopping.")
    return make_result("web", target, tool="discover", paths=sorted(results, key=lambda r: r["path"]),
                       requests=len(words), concurrency=workers, body_read_limit=MAX_BODY,
                       authorization_warning="Use only against targets you are explicitly authorized to assess.",
                       limitations="No recursion; redirects are not followed; no authentication bypass or exploitation.")
