import struct
import zlib

import pytest

from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.tool import ToolContext
from ctfforge.steg.structure import MAX_FILE_BYTES, analyze


def context(path):
    return ToolContext("steg", "structure", {"file": path})


def png_chunk(name, payload):
    chunk_type = name.encode("ascii")
    crc = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + chunk_type + payload + struct.pack(">I", crc)


def valid_png():
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + png_chunk("IHDR", ihdr)
            + png_chunk("IDAT", b"data") + png_chunk("IEND", b""))


def minimal_jpeg(trailing=b""):
    # Minimal marker sequence for structural parsing; image decoding is not attempted.
    sof = bytes([8]) + struct.pack(">HH", 1, 1) + bytes([1, 1, 0x11, 0])
    return (b"\xff\xd8" + b"\xff\xc0" + struct.pack(">H", len(sof) + 2) + sof
            + b"\xff\xda" + struct.pack(">H", 2) + b"\x12\x34\xff\xd9" + trailing)


def test_valid_png_chunks_and_crc(tmp_path):
    target = tmp_path / "sample.png"
    target.write_bytes(valid_png())

    result = analyze(context(target))

    assert result["file_type"] == "PNG image"
    assert [chunk["type"] for chunk in result["png_chunks"]] == ["IHDR", "IDAT", "IEND"]
    assert all(chunk["crc_valid"] for chunk in result["png_chunks"])
    assert result["trailing_data_bytes"] == 0


def test_png_bad_crc_and_trailing_bytes_are_reported(tmp_path):
    data = bytearray(valid_png())
    data[29] ^= 1  # Flip a byte within IHDR payload, leaving its original CRC.
    data.extend(b"tail")
    target = tmp_path / "suspicious.png"
    target.write_bytes(data)

    result = analyze(context(target))

    assert any("invalid CRC" in finding for finding in result["findings"])
    assert result["trailing_data_bytes"] == 4
    assert any("benign padding" in finding for finding in result["findings"])


def test_png_unusual_chunk_order_is_reported(tmp_path):
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    data = (b"\x89PNG\r\n\x1a\n" + png_chunk("tEXt", b"note\x00value")
            + png_chunk("IHDR", ihdr) + png_chunk("IDAT", b"data")
            + png_chunk("IEND", b""))
    target = tmp_path / "order.png"
    target.write_bytes(data)

    result = analyze(context(target))

    assert any("IHDR is not the first chunk" in finding for finding in result["findings"])


def test_extension_mismatch_and_embedded_signature(tmp_path):
    target = tmp_path / "picture.png"
    target.write_bytes(minimal_jpeg() + b"PK\x03\x04payload")

    result = analyze(context(target))

    assert result["file_type"] == "JPEG image"
    assert result["extension_matches"] is False
    assert any(entry["format"] == "ZIP archive" for entry in result["embedded_signatures"])
    assert any("Extension suggests" in finding for finding in result["findings"])


def test_valid_jpeg_markers_and_trailing_data(tmp_path):
    target = tmp_path / "sample.jpg"
    target.write_bytes(minimal_jpeg(b"extra"))

    result = analyze(context(target))

    assert [marker["marker"] for marker in result["jpeg_markers"]] == ["SOI", "SOF0", "SOS", "EOI"]
    assert result["trailing_data_bytes"] == 5


@pytest.mark.parametrize("data", [b"", b"\x89PNG\r\n\x1a\n\x00\x00", b"\xff\xd8\xff\xc0\x00\x01"])
def test_empty_and_malformed_structures_are_handled(tmp_path, data):
    target = tmp_path / "bad.bin"
    target.write_bytes(data)

    result = analyze(context(target))

    assert result["file_size"] == len(data)
    assert isinstance(result["findings"], list)


def test_size_limit_and_missing_file_are_friendly_errors(tmp_path):
    target = tmp_path / "too-large.bin"
    with target.open("wb") as stream:
        stream.truncate(MAX_FILE_BYTES + 1)
    with pytest.raises(CTFForgeError, match="processing limit"):
        analyze(context(target))
    with pytest.raises(CTFForgeError, match="Cannot inspect file"):
        analyze(context(tmp_path / "missing.bin"))
