"""Small, dependency-free file signature identification."""

from pathlib import Path

SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "PNG image"), (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"), (b"GIF89a", "GIF image"), (b"PK\x03\x04", "ZIP archive"),
    (b"%PDF-", "PDF document"), (b"MZ", "PE executable"), (b"\x7fELF", "ELF executable"),
    (b"RIFF", "RIFF container"),
)


def identify_file(path: Path) -> str:
    with path.open("rb") as stream:
        header = stream.read(16)
    for signature, description in SIGNATURES:
        if header.startswith(signature):
            if signature == b"RIFF" and header[8:12] == b"WAVE":
                return "WAV audio"
            return description
    return "Unknown or text data"
