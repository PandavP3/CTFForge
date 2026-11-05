"""Heuristic identifier for common password and digest hash formats."""

import re
from pathlib import Path

from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult

MAX_HASH_INPUT_BYTES = 4096
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_SHA_CRYPT = re.compile(r"^\$(5|6)\$(?:rounds=\d+\$)?[^$]{1,16}\$[./0-9A-Za-z]{20,}$")
_BCRYPT = re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$")


def identify_hash(value: str) -> list[dict[str, str]]:
    """Return all structurally plausible formats; matches are heuristic only."""
    candidate = value.strip()
    if not candidate:
        return []
    matches: list[dict[str, str]] = []

    def add(name: str, reason: str) -> None:
        matches.append({"format": name, "reason": reason, "identification": "heuristic"})

    if _HEX.fullmatch(candidate):
        hex_formats = {
            32: (("MD5", "32 hexadecimal characters match an MD5 digest width."),
                 ("NTLM", "NTLM is commonly represented by a 32-character hexadecimal digest.")),
            40: (("SHA-1", "40 hexadecimal characters match a SHA-1 digest width."),),
            64: (("SHA-256", "64 hexadecimal characters match a SHA-256 digest width."),),
            96: (("SHA-384", "96 hexadecimal characters match a SHA-384 digest width."),),
            128: (("SHA-512", "128 hexadecimal characters match a SHA-512 digest width."),),
        }
        for name, reason in hex_formats.get(len(candidate), ()):
            add(name, reason)
    if candidate.startswith(("$2a$", "$2b$", "$2y$")):
        if _BCRYPT.fullmatch(candidate):
            add("bcrypt", "Prefix, two-digit cost, and 53-character bcrypt payload match its structure.")
    if candidate.startswith(("$5$", "$6$")) and _SHA_CRYPT.fullmatch(candidate):
        label = "SHA-256 crypt" if candidate.startswith("$5$") else "SHA-512 crypt"
        add(label, "Modular crypt prefix, salt field, and crypt alphabet match the format structure.")
    return matches


def _read_value(context: ToolContext) -> tuple[str, str]:
    args = context.arguments
    has_file = args.get("file") is not None
    has_input = args.get("input") is not None
    if has_file == has_input:
        raise CTFForgeError("Provide exactly one of file or input for hash identification.")
    if has_input:
        value = str(args["input"])
        if len(value.encode("utf-8")) > MAX_HASH_INPUT_BYTES:
            raise CTFForgeError(f"Hash input exceeds the {MAX_HASH_INPUT_BYTES}-byte limit.")
        return value, "<direct input>"
    path = Path(str(args["file"])).expanduser()
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_HASH_INPUT_BYTES + 1)
    except OSError as exc:
        raise CTFForgeError(f"Cannot read hash input file {path}: {exc}") from exc
    if len(raw) > MAX_HASH_INPUT_BYTES:
        raise CTFForgeError(f"Hash input exceeds the {MAX_HASH_INPUT_BYTES}-byte limit.")
    try:
        return raw.decode("ascii").strip(), str(path)
    except UnicodeDecodeError as exc:
        raise CTFForgeError("Hash identifier input must contain ASCII text.") from exc


def identify(context: ToolContext) -> ToolResult:
    value, target = _read_value(context)
    candidates = identify_hash(value)
    findings = [f"Possible format: {candidate['format']}" for candidate in candidates]
    return make_result(
        "crypto", target, tool="hashid", input=value, candidates=candidates,
        findings=findings,
        confidence=100 if len(candidates) == 1 else (75 if candidates else 0),
        recommendations=["Identification is heuristic; validate with challenge context."
                         ] if candidates else ["No supported hash structure matched."],
    )
