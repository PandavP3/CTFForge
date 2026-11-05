import hashlib

import pytest

from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.tool import ToolContext

pytest.importorskip("PIL")

from ctfforge.steg.metadata import MAX_IMAGE_BYTES, analyze


def context(path):
    return ToolContext("steg", "metadata", {"file": path})


def pillow():
    return pytest.importorskip("PIL.Image")


def test_jpeg_metadata_includes_format_dimensions_and_exif(tmp_path):
    Image = pillow()
    image = Image.new("RGB", (13, 7), color="red")
    exif = Image.Exif()
    exif[271] = "CTF Camera"
    exif[272] = "Model One"
    exif[36867] = "2024:01:02 03:04:05"
    target = tmp_path / "photo.jpg"
    image.save(target, format="JPEG", exif=exif)

    result = analyze(context(target))

    assert result["image"] == {"format": "JPEG", "dimensions": [13, 7], "mode": "RGB"}
    assert result["exif"]["Make"] == "CTF Camera"
    assert result["exif"]["Model"] == "Model One"
    assert result["timestamps"]["DateTimeOriginal"] == "2024:01:02 03:04:05"
    assert result["exif_status"] == "present"


def test_gps_metadata_is_reported_when_present(tmp_path):
    Image = pillow()
    image = Image.new("RGB", (4, 4), color="blue")
    exif = Image.Exif()
    exif[34853] = {1: "N", 2: (40, 0, 0), 3: "W", 4: (70, 0, 0)}
    target = tmp_path / "gps.jpg"
    image.save(target, format="JPEG", exif=exif)

    result = analyze(context(target))

    assert result["gps"]["GPSLatitudeRef"] == "N"
    assert result["gps"]["GPSLongitudeRef"] == "W"
    assert any("GPS metadata is present" in finding for finding in result["findings"])


def test_png_text_chunks_are_reported(tmp_path):
    Image = pillow()
    PngImagePlugin = pytest.importorskip("PIL.PngImagePlugin")
    target = tmp_path / "note.png"
    info = PngImagePlugin.PngInfo()
    info.add_text("Comment", "challenge note")
    Image.new("RGB", (3, 2)).save(target, pnginfo=info)

    result = analyze(context(target))

    assert result["image"]["format"] == "PNG"
    assert result["text_chunks"]["Comment"] == "challenge note"
    assert result["comments"]["Comment"] == "challenge note"


@pytest.mark.parametrize(("image_format", "suffix"), [("TIFF", ".tiff"), ("WEBP", ".webp")])
def test_tiff_and_webp_are_supported_when_pillow_codec_is_available(
    tmp_path, image_format, suffix
):
    Image = pillow()
    if image_format not in Image.SAVE:
        pytest.skip(f"Pillow was built without {image_format} write support")
    target = tmp_path / f"sample{suffix}"
    Image.new("RGB", (5, 3)).save(target, format=image_format)

    result = analyze(context(target))

    assert result["image"]["format"] == image_format
    assert result["image"]["dimensions"] == [5, 3]


def test_missing_metadata_is_distinct_from_unavailable_metadata(tmp_path):
    Image = pillow()
    target = tmp_path / "plain.png"
    Image.new("RGB", (2, 2)).save(target)

    result = analyze(context(target))

    assert result["metadata_status"] == "absent"
    assert result["exif_status"] == "absent"
    assert "No EXIF" in result["findings"][0]


@pytest.mark.parametrize("suffix, content", [
    (".txt", b"ordinary text"),
    (".png", b"not an image"),
])
def test_unsupported_and_malformed_images_return_friendly_errors(tmp_path, suffix, content):
    target = tmp_path / f"bad{suffix}"
    target.write_bytes(content)

    with pytest.raises(CTFForgeError, match="Cannot parse image|Unsupported image format"):
        analyze(context(target))


def test_image_size_limit_and_source_immutability(tmp_path):
    Image = pillow()
    target = tmp_path / "unchanged.png"
    Image.new("RGB", (4, 4)).save(target)
    original_hash = hashlib.sha256(target.read_bytes()).hexdigest()

    result = analyze(context(target))

    assert result["file_size"] == target.stat().st_size
    assert hashlib.sha256(target.read_bytes()).hexdigest() == original_hash

    oversized = tmp_path / "oversized.png"
    with oversized.open("wb") as stream:
        stream.truncate(MAX_IMAGE_BYTES + 1)
    with pytest.raises(CTFForgeError, match="processing limit"):
        analyze(context(oversized))


