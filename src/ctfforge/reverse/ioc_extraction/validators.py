"""Offline syntax validation and conservative normalization for IOC candidates."""
import ipaddress
import re
from urllib.parse import SplitResult, urlsplit, urlunsplit

from .patterns import LIKELY_FILE_SUFFIXES

_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def normalize_domain(value: str) -> str | None:
    candidate = value.rstrip(".")
    if not candidate or len(candidate) > 253:
        return None
    try:
        ascii_name = candidate.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return None
    labels = ascii_name.split(".")
    if len(labels) < 2 or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        return None
    tld = labels[-1]
    if len(tld) < 2 or not (tld.isalpha() or tld.startswith("xn--")):
        return None
    if tld in LIKELY_FILE_SUFFIXES:
        return None
    # Dotted numeric values should be parsed as IPs, never as domain names.
    if all(label.isdecimal() for label in labels):
        return None
    return ascii_name


def normalize_ip(value: str, version: int | None = None) -> str | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if version is not None and address.version != version:
        return None
    return address.compressed


def validate_email(value: str) -> tuple[str, str] | None:
    if value.count("@") != 1:
        return None
    local, domain = value.rsplit("@", 1)
    if not local or len(local.encode("utf-8", errors="ignore")) > 64:
        return None
    if local.startswith(".") or local.endswith(".") or ".." in local:
        return None
    normalized_domain = normalize_domain(domain)
    if not normalized_domain:
        return None
    return f"{local}@{normalized_domain}", normalized_domain


def _normalize_url_parts(parts: SplitResult) -> tuple[str, str] | None:
    if parts.scheme.lower() not in ("http", "https") or not parts.netloc:
        return None
    if parts.username is not None or parts.password is not None:
        # Credentials in URL candidates are still valid syntax, but preserve them
        # exactly while normalizing only the host component.
        user_info = parts.netloc.rsplit("@", 1)[0] + "@"
    else:
        user_info = ""
    try:
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if not hostname:
        return None
    normalized_ip = normalize_ip(hostname)
    if normalized_ip:
        host = f"[{normalized_ip}]" if ":" in normalized_ip else normalized_ip
    else:
        host = normalize_domain(hostname)
        if not host:
            return None
    if port is not None and not 1 <= port <= 65535:
        return None
    authority = f"{user_info}{host}{':' + str(port) if port is not None else ''}"
    normalized = urlunsplit((parts.scheme.lower(), authority, parts.path, parts.query, parts.fragment))
    return normalized, hostname


def validate_url(value: str) -> tuple[str, str] | None:
    try:
        parts = urlsplit(value)
        return _normalize_url_parts(parts)
    except (ValueError, UnicodeError):
        return None

