"""Bounded printable-string extraction for evidence files."""

from pathlib import Path


def extract_strings(path: Path, *, minimum: int = 4, limit_bytes: int = 64 * 1024 * 1024) -> list[str]:
    if minimum < 1:
        raise ValueError("minimum must be positive")
    data = path.read_bytes()[:limit_bytes]
    found: list[str] = []
    current = bytearray()
    for byte in data:
        if 32 <= byte <= 126 or byte in (9,):
            current.append(byte)
        else:
            if len(current) >= minimum:
                found.append(current.decode("ascii", errors="replace"))
            current.clear()
    if len(current) >= minimum:
        found.append(current.decode("ascii", errors="replace"))
    return found
