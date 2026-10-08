"""Conservative offline text-encoding detection and decoding."""

import base64
import binascii
import codecs
import html
import re
import urllib.parse
import zlib
from dataclasses import dataclass


@dataclass(frozen=True)
class DecodeCandidate:
    name: str
    operation: str
    output: bytes
    confidence: int


def _is_text(data: bytes) -> bool:
    if not data:
        return False
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return sum(char.isprintable() or char in "\r\n\t" for char in text) / len(text) >= 0.85


def detect_decodings(value: str | bytes) -> list[DecodeCandidate]:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    text = raw.decode("utf-8", errors="strict") if _is_text(raw) else ""
    candidates: list[DecodeCandidate] = []
    compact = re.sub(r"\s+", "", text)
    if len(compact) >= 8 and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", compact) and len(compact) % 4 == 0:
        try:
            decoded = base64.b64decode(compact, validate=True)
            if decoded != raw:
                candidates.append(DecodeCandidate("base64", "From Base64", decoded, 98))
        except (binascii.Error, ValueError):
            pass
    if len(compact) >= 6 and len(compact) % 2 == 0 and re.fullmatch(r"[A-Fa-f0-9]+", compact):
        try:
            decoded = bytes.fromhex(compact)
            if decoded != raw:
                candidates.append(DecodeCandidate("hex", "From Hex", decoded, 98))
        except ValueError:
            pass
    if re.search(r"%[0-9A-Fa-f]{2}", text):
        decoded = urllib.parse.unquote_to_bytes(text)
        if decoded != raw and _is_text(decoded):
            candidates.append(DecodeCandidate("url", "URL Decode", decoded, 95))
    if re.search(r"&(?:amp|lt|gt|quot|#\d+|#x[\da-f]+);", text, re.IGNORECASE):
        decoded = html.unescape(text).encode("utf-8")
        if decoded != raw and _is_text(decoded):
            candidates.append(DecodeCandidate("html", "HTML Entity Decode", decoded, 94))
    if re.search(r"\\u[0-9a-fA-F]{4}", text):
        try:
            decoded = codecs.decode(text, "unicode_escape").encode("utf-8")
            if decoded != raw and _is_text(decoded):
                candidates.append(DecodeCandidate("unicode", "Unescape Unicode Characters", decoded, 90))
        except UnicodeDecodeError:
            pass
    for name, decoder in (("gzip", zlib.decompress), ("zlib", zlib.decompress)):
        try:
            decoded = decoder(raw, zlib.MAX_WBITS | (16 if name == "gzip" else 0))
            if decoded != raw:
                candidates.append(DecodeCandidate(name, "Gunzip" if name == "gzip" else "Zlib Inflate", decoded, 99))
        except zlib.error:
            pass
    if len(candidates) == 0 and text and text.isalpha() and text.isascii() and len(text) >= 8:
        decoded_text = codecs.decode(text, "rot_13")
        if decoded_text != text and any(token in decoded_text.lower() for token in ("flag", "ctf", "http", "the")):
            candidates.append(DecodeCandidate("rot13", "ROT13", decoded_text.encode(), 65))
    return sorted(candidates, key=lambda item: item.confidence, reverse=True)


def hash_kind(value: str) -> str | None:
    if re.fullmatch(r"[a-fA-F0-9]{32}", value):
        return "MD5"
    if re.fullmatch(r"[a-fA-F0-9]{40}", value):
        return "SHA1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return "SHA256"
    return None
