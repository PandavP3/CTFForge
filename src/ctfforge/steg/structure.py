"""Bounded, read-only file-signature and PNG/JPEG structure inspection."""

import struct
import zlib
from pathlib import Path
from typing import Any

from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.file_detection import identify_file
from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult

MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_CHUNKS = 100_000
MAX_EMBEDDED_SIGNATURES = 32
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_EMBEDDED_SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"%PDF-", "PDF document"),
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "PE executable"),
    (b"\x1f\x8b\x08", "gzip stream"),
    (b"Rar!\x1a\x07", "RAR archive"),
)
_EXTENSION_TYPES = {
    ".png": "PNG image", ".jpg": "JPEG image", ".jpeg": "JPEG image",
    ".tif": "TIFF image", ".tiff": "TIFF image", ".gif": "GIF image",
    ".webp": "WebP image", ".pdf": "PDF document", ".zip": "ZIP archive",
    ".exe": "PE executable", ".dll": "PE executable", ".wav": "WAV audio",
}
_PNG_KNOWN_CRITICAL = {b"IHDR", b"PLTE", b"IDAT", b"IEND"}
_JPEG_MARKERS = {
    0x01: "TEM", 0xC0: "SOF0", 0xC1: "SOF1", 0xC2: "SOF2", 0xC3: "SOF3",
    0xC4: "DHT", 0xC5: "SOF5", 0xC6: "SOF6", 0xC7: "SOF7", 0xC8: "JPG",
    0xC9: "SOF9", 0xCA: "SOF10", 0xCB: "SOF11", 0xCC: "DAC", 0xCD: "SOF13",
    0xCE: "SOF14", 0xCF: "SOF15", 0xD8: "SOI", 0xD9: "EOI", 0xDA: "SOS",
    0xDB: "DQT", 0xDC: "DNL", 0xDD: "DRI", 0xDE: "DHP", 0xDF: "EXP",
    0xFE: "COM",
}


def _read_file(path: Path) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise CTFForgeError(f"Cannot inspect file {path}: {exc}") from exc
    if not path.is_file():
        raise CTFForgeError(f"Target is not a regular file: {path}")
    if size > MAX_FILE_BYTES:
        raise CTFForgeError(f"File exceeds the {MAX_FILE_BYTES}-byte structure processing limit.")
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise CTFForgeError(f"Cannot read file {path}: {exc}") from exc
    if len(data) > MAX_FILE_BYTES:
        raise CTFForgeError(f"File exceeds the {MAX_FILE_BYTES}-byte structure processing limit.")
    return data


def _actual_type(data: bytes, path: Path) -> str:
    try:
        detected = identify_file(path)
    except OSError:
        detected = "Unknown or text data"
    if data.startswith((b"II*\x00", b"MM\x00*")):
        return "TIFF image"
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "WebP image"
    if data.startswith(b"RIFF") and data[8:12] == b"WAVE":
        return "WAV audio"
    return detected


def _embedded(data: bytes) -> list[dict[str, Any]]:
    hits = []
    for signature, label in _EMBEDDED_SIGNATURES:
        start = 1
        while len(hits) < MAX_EMBEDDED_SIGNATURES:
            offset = data.find(signature, start)
            if offset < 0:
                break
            hits.append({"format": label, "offset": offset})
            start = offset + len(signature)
        if len(hits) >= MAX_EMBEDDED_SIGNATURES:
            break
    return sorted(hits, key=lambda item: item["offset"])


def _png(data: bytes) -> tuple[list[dict[str, Any]], list[str], int | None]:
    chunks: list[dict[str, Any]] = []
    findings: list[str] = []
    position = len(PNG_SIGNATURE)
    seen_ihdr = False
    seen_iend = False
    seen_idat = False
    ended_idat = False
    end_offset = None

    while position < len(data) and len(chunks) < MAX_CHUNKS:
        if len(data) - position < 12:
            findings.append(f"Incomplete PNG chunk header or trailer at offset {position}.")
            break
        length = struct.unpack_from(">I", data, position)[0]
        chunk_type = data[position + 4:position + 8]
        if not all(65 <= byte <= 90 or 97 <= byte <= 122 for byte in chunk_type):
            findings.append(f"Invalid PNG chunk type at offset {position + 4}.")
            break
        chunk_end = position + 12 + length
        if chunk_end > len(data):
            findings.append(
                f"PNG {chunk_type.decode('ascii', 'replace')} chunk declares {length} data bytes, "
                "which extends beyond the file boundary."
            )
            chunks.append({"type": chunk_type.decode("ascii", "replace"),
                           "length": length, "crc_valid": None, "offset": position})
            break
        stored_crc = struct.unpack_from(">I", data, position + 8 + length)[0]
        calculated_crc = zlib.crc32(data[position + 4:position + 8 + length]) & 0xFFFFFFFF
        crc_valid = stored_crc == calculated_crc
        name = chunk_type.decode("ascii")
        chunks.append({"type": name, "length": length, "crc_valid": crc_valid, "offset": position})
        if not crc_valid:
            findings.append(f"PNG {name} chunk has an invalid CRC.")
        if not chunks[:-1] and chunk_type != b"IHDR":
            findings.append("PNG IHDR is not the first chunk.")
        if chunk_type == b"IHDR":
            if seen_ihdr:
                findings.append("PNG contains more than one IHDR chunk.")
            if length != 13:
                findings.append(f"PNG IHDR has an unexpected length of {length}; expected 13.")
            seen_ihdr = True
        elif not seen_ihdr:
            findings.append(f"PNG {name} appears before IHDR.")
        if chunk_type == b"IDAT":
            if ended_idat:
                findings.append("PNG IDAT chunks are not consecutive.")
            seen_idat = True
        elif seen_idat and chunk_type != b"IEND":
            ended_idat = True
        if chunk_type[0] & 0x20 == 0 and chunk_type not in _PNG_KNOWN_CRITICAL:
            findings.append(f"PNG contains unrecognized critical chunk {name}.")
        position = chunk_end
        if chunk_type == b"IEND":
            if length != 0:
                findings.append(f"PNG IEND has unexpected data length {length}.")
            seen_iend = True
            end_offset = position
            break

    if len(chunks) >= MAX_CHUNKS:
        findings.append(f"PNG chunk scan stopped at the {MAX_CHUNKS}-chunk safety limit.")
    if not seen_ihdr:
        findings.append("PNG is missing its required IHDR chunk.")
    if not seen_idat:
        findings.append("PNG contains no IDAT image-data chunk.")
    if not seen_iend:
        findings.append("PNG is missing its required IEND end marker.")
    return chunks, findings, end_offset


def _find_next_jpeg_marker(data: bytes, position: int) -> int | None:
    while position < len(data):
        marker_start = data.find(b"\xff", position)
        if marker_start < 0:
            return None
        cursor = marker_start + 1
        while cursor < len(data) and data[cursor] == 0xFF:
            cursor += 1
        if cursor >= len(data):
            return None
        code = data[cursor]
        if code == 0x00 or 0xD0 <= code <= 0xD7:
            position = cursor + 1
            continue
        return marker_start
    return None


def _jpeg(data: bytes) -> tuple[list[dict[str, Any]], list[str], int | None]:
    markers: list[dict[str, Any]] = [
        {"marker": "SOI", "code": "0xD8", "offset": 0, "segment_length": None}
    ]
    findings: list[str] = []
    position = 2
    end_offset = None
    in_scan = False
    saw_sof = False
    saw_sos = False

    while position < len(data):
        if in_scan:
            next_marker = _find_next_jpeg_marker(data, position)
            if next_marker is None:
                findings.append("JPEG entropy-coded scan ends without a following marker.")
                break
            position = next_marker
            in_scan = False
        if data[position] != 0xFF:
            findings.append(f"Unexpected byte in JPEG marker stream at offset {position}.")
            break
        marker_start = position
        while position < len(data) and data[position] == 0xFF:
            position += 1
        if position >= len(data):
            findings.append("JPEG ends with an incomplete marker prefix.")
            break
        code = data[position]
        position += 1
        label = _JPEG_MARKERS.get(code, f"MARKER_0x{code:02X}")
        if code == 0xD9:
            markers.append({"marker": label, "code": f"0x{code:02X}", "offset": marker_start,
                            "segment_length": None})
            end_offset = position
            break
        if code == 0xD8 or code == 0x01 or 0xD0 <= code <= 0xD7:
            markers.append({"marker": label, "code": f"0x{code:02X}", "offset": marker_start,
                            "segment_length": None})
            if code == 0xD8 and marker_start != 0:
                findings.append("JPEG contains an unexpected nested SOI marker.")
            continue
        if code == 0x00:
            findings.append("JPEG contains a stuffed 0xFF00 byte outside an entropy-coded scan.")
            break
        if position + 2 > len(data):
            findings.append(f"JPEG {label} marker is missing its segment length.")
            break
        segment_length = struct.unpack_from(">H", data, position)[0]
        if segment_length < 2:
            findings.append(f"JPEG {label} marker has invalid segment length {segment_length}.")
            break
        segment_end = position + segment_length
        if segment_end > len(data):
            findings.append(f"JPEG {label} segment extends beyond the file boundary.")
            markers.append({"marker": label, "code": f"0x{code:02X}", "offset": marker_start,
                            "segment_length": segment_length})
            break
        markers.append({"marker": label, "code": f"0x{code:02X}", "offset": marker_start,
                        "segment_length": segment_length})
        if 0xC0 <= code <= 0xCF and code not in (0xC4, 0xC8, 0xCC):
            saw_sof = True
        if code == 0xDA:
            saw_sos = True
            in_scan = True
        position = segment_end

    if end_offset is None:
        findings.append("JPEG is missing its EOI end marker.")
    if not saw_sof:
        findings.append("JPEG contains no recognized start-of-frame marker.")
    if not saw_sos:
        findings.append("JPEG contains no start-of-scan marker.")
    return markers, findings, end_offset


def _generic_end(data: bytes, file_type: str) -> int | None:
    if file_type == "GIF image":
        offset = data.rfind(b";")
        return offset + 1 if offset >= 0 else None
    if file_type == "PDF document":
        offset = data.rfind(b"%%EOF")
        return offset + len(b"%%EOF") if offset >= 0 else None
    if file_type == "ZIP archive":
        offset = data.rfind(b"PK\x05\x06")
        if offset < 0 or offset + 22 > len(data):
            return None
        comment_length = struct.unpack_from("<H", data, offset + 20)[0]
        return offset + 22 + comment_length
    return None


def _analyze_data(data: bytes, path: Path) -> ToolResult:
    actual_type = _actual_type(data, path) if data else "Empty file"
    expected_type = _EXTENSION_TYPES.get(path.suffix.lower())
    findings: list[str] = []
    if expected_type and actual_type not in (expected_type, "Unknown or text data"):
        findings.append(
            f"Extension suggests {expected_type}, but the file signature suggests {actual_type}."
        )
    elif expected_type and actual_type == "Unknown or text data":
        findings.append(
            f"Extension suggests {expected_type}, but no recognized matching signature was found."
        )

    chunks: list[dict[str, Any]] = []
    markers: list[dict[str, Any]] = []
    end_offset = None
    if data.startswith(PNG_SIGNATURE):
        chunks, parser_findings, end_offset = _png(data)
        findings.extend(parser_findings)
    elif data.startswith(b"\xff\xd8\xff"):
        markers, parser_findings, end_offset = _jpeg(data)
        findings.extend(parser_findings)
    else:
        end_offset = _generic_end(data, actual_type)
        if actual_type in {"GIF image", "PDF document", "ZIP archive"} and end_offset is None:
            findings.append(f"No complete recognized end marker was found for {actual_type}.")

    trailing_bytes = max(0, len(data) - end_offset) if end_offset is not None else 0
    if trailing_bytes:
        tail = data[end_offset:]
        if actual_type == "PDF document" and not tail.strip():
            pass
        else:
            findings.append(
                f"{trailing_bytes} byte(s) follow the recognized {actual_type} end marker; "
                "this can be benign padding or appended content."
            )

    embedded = _embedded(data)
    for entry in embedded:
        findings.append(
            f"Recognizable {entry['format']} signature at offset {entry['offset']}; "
            "this indicates embedded-looking bytes, not proof of hidden content."
        )
    if not findings:
        findings.append("No obvious extension mismatch or structural anomaly was detected.")
    return make_result(
        "steg", str(path), tool="structure", file_size=len(data),
        file_type=actual_type, expected_type=expected_type,
        extension_matches=expected_type is None or actual_type == expected_type,
        trailing_data_bytes=trailing_bytes, png_chunks=chunks, jpeg_markers=markers,
        embedded_signatures=embedded, findings=findings, confidence=0,
        recommendations=[
            "Suspicious structure is an analysis lead and does not prove steganography "
            "or malicious activity."
        ],
    )


def analyze(context: ToolContext) -> ToolResult:
    """Inspect a bounded artifact without extracting or executing embedded content."""
    value = context.arguments.get("file")
    if not isinstance(value, (str, Path)):
        raise CTFForgeError("Steg structure requires a file path argument named 'file'.")
    path = Path(value).expanduser()
    data = _read_file(path)
    return _analyze_data(data, path)
