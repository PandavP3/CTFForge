"""Set-Cookie analysis with value redaction."""
from http.cookies import SimpleCookie, CookieError
from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult
from ._http import fetch_headers, parse_headers


def analyze(context: ToolContext) -> ToolResult:
    args = context.arguments
    headers = parse_headers(args.get("header"))
    status = None
    if args.get("url"):
        headers, status = fetch_headers(str(args["url"]))
    raw = [v for k, v in headers if k.lower() == "set-cookie"]
    cookies, findings = [], []
    for item in raw:
        jar = SimpleCookie()
        try: jar.load(item)
        except CookieError as exc: raise CTFForgeError(f"Malformed Set-Cookie header: {exc}") from exc
        for name, morsel in jar.items():
            attrs = {key.lower(): morsel[key] for key in ("secure", "httponly", "samesite", "domain", "path", "expires", "max-age") if morsel[key]}
            missing = [key for key in ("secure", "httponly", "samesite") if not attrs.get(key)]
            if "secure" not in attrs: findings.append({"severity": "medium", "cookie": name, "message": "Secure attribute is absent."})
            if "httponly" not in attrs: findings.append({"severity": "low", "cookie": name, "message": "HttpOnly attribute is absent."})
            if "samesite" not in attrs: findings.append({"severity": "low", "cookie": name, "message": "SameSite attribute is absent."})
            if attrs.get("samesite", "").lower() == "none" and "secure" not in attrs: findings.append({"severity": "medium", "cookie": name, "message": "SameSite=None without Secure is an insecure combination."})
            cookies.append({"name": name, "value": "[REDACTED]", "attributes": attrs, "missing_security_attributes": missing,
                            "session_cookie_observation": "No Expires or Max-Age; may be a session cookie" if not attrs.get("expires") and not attrs.get("max-age") else "Persistent lifetime is configured"})
    return make_result("web", str(args.get("url") or "<supplied headers>"), tool="cookies", status=status, cookies=cookies, findings=findings,
                       cookie_count=len(cookies), values_redacted=True)
