"""Offline URL parsing and heuristic inspection."""
import ipaddress
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult


def analyze(context: ToolContext) -> ToolResult:
    value = str(context.arguments.get("input", ""))
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise CTFForgeError(f"Malformed URL: {exc}") from exc
    if not parts.scheme or not parts.hostname:
        raise CTFForgeError("URL must include a scheme and hostname.")
    host = parts.hostname
    try:
        host_ascii = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise CTFForgeError("Invalid internationalized hostname.") from exc
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    counts = {}
    for key, _ in pairs: counts[key] = counts.get(key, 0) + 1
    findings = []
    if parts.scheme.lower() not in ("http", "https"):
        findings.append({"severity": "medium", "message": "Non-HTTP scheme; review before opening."})
    if "@" in parts.netloc:
        findings.append({"severity": "medium", "message": "User information in authority can obscure the actual host."})
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        findings.append({"severity": "info", "message": "URL uses a literal IP address."})
    if parts.scheme.lower() == "http":
        findings.append({"severity": "info", "message": "URL uses unencrypted HTTP."})
    dups = sorted(k for k, n in counts.items() if n > 1)
    if dups: findings.append({"severity": "info", "message": "Duplicate query parameters: " + ", ".join(dups)})
    return make_result("web", value, tool="url", scheme=parts.scheme, host=host, host_ascii=host_ascii,
                       port=port, path=parts.path or "/", query_parameters=[{"name": k, "value": v} for k, v in pairs],
                       duplicate_parameters=dups, percent_encoding_present="%" in value,
                       fragment=parts.fragment, normalized=urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", parts.query, parts.fragment)),
                       findings=findings, network_requests=0)
