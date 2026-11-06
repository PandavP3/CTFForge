"""Offline JWT decoder and static analyzer; it never verifies signatures."""
import base64
import json
import time

from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult


def _decode(part: str) -> bytes:
    if not part or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=" for c in part):
        raise ValueError("invalid base64url characters")
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def analyze(context: ToolContext) -> ToolResult:
    token = str(context.arguments.get("token", ""))
    pieces = token.split(".")
    if len(pieces) != 3 or any(not p for p in pieces):
        raise CTFForgeError("JWT must contain three non-empty dot-separated segments.")
    try:
        header = json.loads(_decode(pieces[0]))
        payload = json.loads(_decode(pieces[1]))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CTFForgeError(f"JWT header or payload is malformed: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise CTFForgeError("JWT header and payload must each be JSON objects.")
    now = int(context.arguments.get("now", time.time()))
    claims = {}
    for key in ("iss", "sub", "aud", "exp", "nbf", "iat", "jti"):
        if key in payload:
            value = payload[key]
            row = {"value": value}
            if key in ("exp", "nbf", "iat") and isinstance(value, (int, float)):
                row["unix_time"] = value
                row["interpretation"] = "expired" if key == "exp" and value <= now else "not-yet-valid" if key == "nbf" and value > now else "active-or-informational"
            claims[key] = row
    alg = header.get("alg")
    findings = []
    if alg == "none":
        findings.append({"severity": "high", "message": "alg=none is an unsigned-token configuration and requires careful rejection by consumers."})
    elif alg in ("HS256", "HS384", "HS512"):
        findings.append({"severity": "info", "message": "Symmetric HMAC algorithm declared; ensure the consumer uses the expected algorithm and key."})
    missing = [key for key in ("iss", "sub", "aud", "exp") if key not in payload]
    if missing:
        findings.append({"severity": "info", "message": "Common claims absent: " + ", ".join(missing) + ". Applicability depends on the application."})
    return make_result("web", "<JWT>", tool="jwt", structurally_valid=True, header=header, algorithm=alg,
                       key_id=header.get("kid"), claims=claims, signature_segment_present=True,
                       signature_verified=False, findings=findings,
                       notice="Decoded JWT data is untrusted input. Decoding does not authenticate the token; signature bytes were not displayed.")
