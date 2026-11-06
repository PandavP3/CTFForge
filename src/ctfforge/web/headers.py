"""HTTP security header checks."""
from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult
from ._http import fetch_headers, parse_headers

CHECKS = ("Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
          "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
          "Cross-Origin-Resource-Policy", "Cache-Control")


def inspect(values):
    grouped = {}
    for name, value in values: grouped.setdefault(name.lower(), []).append(value)
    rows, findings = [], []
    for name in CHECKS:
        vals = grouped.get(name.lower(), [])
        rows.append({"header": name, "present": bool(vals), "values": vals})
        if not vals: findings.append({"severity": "info", "header": name, "message": "Header is missing; relevance depends on the application."})
    hsts = ";".join(grouped.get("strict-transport-security", [])).lower()
    if hsts and "max-age=" not in hsts: findings.append({"severity": "low", "header": "Strict-Transport-Security", "message": "HSTS lacks max-age."})
    csp = ";".join(grouped.get("content-security-policy", [])).lower()
    if "unsafe-inline" in csp or "unsafe-eval" in csp or "*" in csp: findings.append({"severity": "medium", "header": "Content-Security-Policy", "message": "Policy contains a permissive source or unsafe directive; review in context."})
    if "nosniff" not in ";".join(grouped.get("x-content-type-options", [])).lower() and grouped.get("x-content-type-options"):
        findings.append({"severity": "low", "header": "X-Content-Type-Options", "message": "Value is not nosniff."})
    server = grouped.get("server", [])
    if server and any(any(c.isdigit() for c in value) for value in server): findings.append({"severity": "info", "header": "Server", "message": "Server header may disclose product/version details."})
    return rows, findings, {k: v for k, v in grouped.items() if k in ("server", "x-powered-by")}


def analyze(context: ToolContext) -> ToolResult:
    args = context.arguments
    values = parse_headers(args.get("header"))
    status = None
    if args.get("url"):
        values, status = fetch_headers(str(args["url"]))
    rows, findings, disclosure = inspect(values)
    return make_result("web", str(args.get("url") or "<supplied headers>"), tool="headers", status=status, headers=rows, disclosure=disclosure,
                       findings=findings, recommendations=["Apply headers that match the application's threat model; missing headers alone do not prove a vulnerability."])
