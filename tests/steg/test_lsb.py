import json
import pytest

from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.tool import ToolContext

Image = pytest.importorskip("PIL.Image")
from ctfforge.steg import lsb


def context(path, **kwargs):
    return ToolContext("steg", "lsb", {"file": path, **kwargs})


def embed(values, message, channel=0, plane=0):
    bits = [((byte >> shift) & 1) for byte in message
            for shift in range(7, -1, -1)]
    pixels = list(values)
    for index, bit in enumerate(bits[:len(pixels)]):
        pixel = list(pixels[index])
        pixel[channel] = (pixel[channel] & ~(1 << plane)) | (bit << plane)
        pixels[index] = tuple(pixel)
    return pixels


def make_image(path, mode="RGB", size=(144, 1), message=b"CTF{known-message}"):
    channels = Image.getmodebands(mode)
    values = [(0, 0, 255) if mode == "RGB" else (0, 0, 255, 0)
              for _ in range(size[0] * size[1])] if mode in ("RGB", "RGBA") else [0] * (size[0] * size[1])
    pixels = embed(values, message) if mode != "L" else [0] * (size[0] * size[1])
    image = Image.new(mode, size)
    image.putdata(pixels)
    image.save(path, format="PNG")
    return path


def test_rgb_lsb_extracts_known_message_in_row_major_order(tmp_path):
    target = make_image(tmp_path / "rgb.png")
    result = lsb.analyze(context(target, channel="red"))
    candidate = result["candidates"][0]
    assert candidate["preview"].startswith("CTF{known-message}")
    assert candidate["channel"] == "red"
    assert result["traversal"] == "row-major"


def test_rgba_channel_extraction_and_alpha_handling(tmp_path):
    target = make_image(tmp_path / "rgba.png", "RGBA")
    result = lsb.analyze(context(target, channel="alpha"))
    assert result["candidates"][0]["channel"] == "alpha"
    assert result["candidates"][0]["extracted_byte_count"] == 18


def test_alpha_unavailable_for_rgb_and_grayscale_works(tmp_path):
    target = make_image(tmp_path / "gray.png", "L")
    assert lsb.analyze(context(target, channel="green"))["candidates"][0]["channel"] == "green"
    rgb = make_image(tmp_path / "rgb2.png")
    with pytest.raises(CTFForgeError, match="unavailable"):
        lsb.analyze(context(rgb, channel="alpha"))


@pytest.mark.parametrize("plane", range(8))
def test_bit_planes_extract(plane):
    pixels = [(0xA5,)] * 8
    assert lsb.extract_channel(pixels, 0, plane) == bytes([0xFF if 0xA5 & (1 << plane) else 0])


def test_bit_order_packing_and_partial_byte():
    pixels = [(1,), (0,), (1,), (1,), (0,), (0,), (1,), (0,), (1,)]
    assert lsb.extract_channel(pixels, 0, 0, "msb") == bytes([0xB2, 0x80])
    assert lsb.extract_channel(pixels, 0, 0, "lsb") == bytes([0x4D, 0x01])


def test_candidate_utf8_invalid_and_ranked_scoring():
    readable = lsb._candidate("red", 0, "msb", b"CTF{hello}")
    binary = lsb._candidate("green", 0, "msb", b"\x00\xff\x00\xfe")
    assert readable["utf8_valid"] and not binary["utf8_valid"]
    assert readable["candidate_score"] > binary["candidate_score"]


def test_malformed_empty_and_unsupported_inputs(tmp_path):
    empty = tmp_path / "empty.png"
    empty.write_bytes(b"")
    with pytest.raises(CTFForgeError, match="Cannot parse"):
        lsb.analyze(context(empty))
    jpeg = tmp_path / "lossy.jpg"
    Image.new("RGB", (2, 2)).save(jpeg, format="JPEG")
    with pytest.raises(CTFForgeError, match="JPEG"):
        lsb.analyze(context(jpeg))
    unknown = tmp_path / "bad.bmp"
    unknown.write_bytes(b"not image")
    with pytest.raises(CTFForgeError):
        lsb.analyze(context(unknown))


def test_input_pixel_and_output_limits(tmp_path, monkeypatch):
    target = make_image(tmp_path / "bounded.png", size=(2, 2))
    monkeypatch.setattr(lsb, "MAX_IMAGE_BYTES", 1)
    with pytest.raises(CTFForgeError, match="byte"):
        lsb.analyze(context(target))
    monkeypatch.setattr(lsb, "MAX_IMAGE_BYTES", 32 * 1024 * 1024)
    monkeypatch.setattr(lsb, "MAX_PIXELS", 3)
    with pytest.raises(CTFForgeError, match="pixel"):
        lsb.analyze(context(target))
    monkeypatch.setattr(lsb, "MAX_PIXELS", 4_000_000)
    monkeypatch.setattr(lsb, "MAX_OUTPUT_BYTES", 0)
    with pytest.raises(CTFForgeError, match="output limit"):
        lsb.analyze(context(target))


def test_output_refuses_overwrite_and_text_requires_valid_utf8(tmp_path):
    target = make_image(tmp_path / "message.png")
    destination = tmp_path / "out.bin"
    destination.write_bytes(b"keep")
    with pytest.raises(CTFForgeError, match="refusing to overwrite"):
        lsb.analyze(context(target, channel="red", output=destination))
    result = lsb.analyze(context(target, channel="red", text=True))
    assert result["extracted_text"].startswith("CTF{")


def test_output_writes_binary_and_text_invalid_is_rejected(tmp_path):
    target = make_image(tmp_path / "message.png")
    destination = tmp_path / "export.bin"
    result = lsb.analyze(context(target, channel="red", output=destination))
    assert destination.exists() and result["output"]["format"] == "binary"
    with pytest.raises(CTFForgeError, match="valid UTF-8"):
        lsb.analyze(context(target, channel="blue", text=True))


def test_all_channels_sorted_and_cli_validation(tmp_path, capsys):
    from ctfforge.core.cli import main
    target = make_image(tmp_path / "all.png")
    assert main(["steg", "lsb", "--file", str(target), "--channel", "all"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert {c["channel"] for c in payload["candidates"]} == {"red", "green", "blue"}
    with pytest.raises(SystemExit):
        main(["steg", "lsb", "--file", str(target), "--bit-plane", "8"])


def test_missing_pillow_message(monkeypatch, tmp_path):
    real_import = __import__

    def no_pillow(name, *args, **kwargs):
        if name == "PIL":
            raise ModuleNotFoundError("No module named 'PIL'", name="PIL")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", no_pillow)
    with pytest.raises(CTFForgeError, match="requirements/steg.txt"):
        lsb.analyze(context(tmp_path / "anything.png"))
