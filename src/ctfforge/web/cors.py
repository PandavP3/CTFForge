"""Static CORS policy analysis."""
from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult
from ._http import fetch_headers, parse_headers


def analyze(context: ToolContext) -> ToolResult:
    args = context.arguments
    values = parse_headers(args.get("header"))
    status = None
    if args.get("url"):
        values, status = fetch_headers(str(args["url"]), "OPTIONS")
    grouped = {}
    for key, val in values: grouped.setdefault(key.lower(), []).append(val)
    names = ("access-control-allow-origin", "access-control-allow-credentials", "access-control-allow-methods",
             "access-control-allow-headers", "access-control-expose-headers", "access-control-max-age", "vary")
    headers = {key: grouped.get(key, []) for key in names if grouped.get(key)}
    origin = ",".join(grouped.get("access-control-allow-origin", [])).strip()
    cred = ",".join(grouped.get("access-control-allow-credentials", [])).strip().lower()
    vary = ",".join(grouped.get("vary", [])).lower()
    findings = []
    if origin == "*" and cred == "true": findings.append({"severity": "high", "message": "Wildcard origin and credentials=true are reported together; browsers reject this combination for credentialed access, but review the actual policy and clients."})
    elif origin == "*": findings.append({"severity": "medium", "message": "Any origin is allowed for non-credentialed CORS reads; assess whether the resources are intended to be public."})
    if origin and origin != "*" and "origin" not in vary: findings.append({"severity": "low", "message": "Specific origin response does not include Vary: Origin; shared caches may reuse responses unexpectedly."})
    return make_result("web", str(args.get("url") or "<supplied headers>"), tool="cors", status=status, headers=headers,
                       present={key: bool(grouped.get(key)) for key in names[:-1]}, findings=findings,
                       assessment="Header-based indicators only; this does not establish exploitability.")
