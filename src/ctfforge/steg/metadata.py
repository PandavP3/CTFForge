"""Bounded, read-only image metadata inspection using optional Pillow support."""

import warnings
from io import BytesIO
from pathlib import Path
from typing import Any

from PIL import ExifTags, Image, UnidentifiedImageError

from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult

MAX_IMAGE_BYTES = 32 * 1024 * 1024
MAX_METADATA_FIELDS = 128
MAX_VALUE_CHARS = 512
SUPPORTED_FORMATS = {"JPEG", "PNG", "TIFF", "WEBP"}
_TIMESTAMP_TAGS = {306: "DateTime", 36867: "DateTimeOriginal", 36868: "DateTimeDigitized"}


def _safe_value(value: Any, depth: int = 0) -> Any:
    """Convert metadata values to bounded JSON-safe values."""
    if depth > 4:
        return "<nested value omitted>"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, bytes):
        return {"hex_prefix": value[:128].hex(), "truncated": len(value) > 128}
    if isinstance(value, (tuple, list)):
        return [_safe_value(item, depth + 1) for item in value[:16]]
    text = str(value)
    return text[:MAX_VALUE_CHARS] + ("…" if len(text) > MAX_VALUE_CHARS else "")


def _tag_name(tag: int) -> str:
    return ExifTags.TAGS.get(tag, str(tag))


def _read_exif(image: Image.Image) -> tuple[dict[str, Any], str | None, dict[str, Any]]:
    try:
        exif = image.getexif()
    except (OSError, ValueError, SyntaxError):
        return {}, "EXIF data is present but could not be parsed.", {}
    if not exif:
        return {}, None, {}
    fields: dict[str, Any] = {}
    for tag_id, value in list(exif.items())[:MAX_METADATA_FIELDS]:
        fields[_tag_name(tag_id)] = _safe_value(value)
    timestamps = {
        label: _safe_value(exif[tag_id])
        for tag_id, label in _TIMESTAMP_TAGS.items()
        if tag_id in exif
    }
    gps: dict[str, Any] = {}
    if 34853 in exif:
        try:
            gps_ifd = exif.get_ifd(34853)
            gps = {
                ExifTags.GPSTAGS.get(tag_id, str(tag_id)): _safe_value(value)
                for tag_id, value in list(gps_ifd.items())[:MAX_METADATA_FIELDS]
            }
        except (AttributeError, OSError, ValueError, TypeError):
            gps = {"status": "GPS IFD exists but could not be parsed."}
    return fields, None, {"timestamps": timestamps, "gps": gps}


def analyze(context: ToolContext) -> ToolResult:
    """Inspect common image metadata without decoding or modifying pixel data."""
    value = context.arguments.get("file")
    if not isinstance(value, (str, Path)):
        raise CTFForgeError("Steg metadata requires a file path argument named 'file'.")
    path = Path(value).expanduser()
    if not path.is_file():
        raise CTFForgeError(f"Target is not a regular file: {path}")
    try:
        with path.open("rb") as stream:
            image_bytes = stream.read(MAX_IMAGE_BYTES + 1)
    except OSError as exc:
        raise CTFForgeError(f"Cannot inspect image {path}: {exc}") from exc
    if len(image_bytes) > MAX_IMAGE_BYTES:
        raise CTFForgeError(f"Image exceeds the {MAX_IMAGE_BYTES}-byte metadata processing limit.")
    size = len(image_bytes)

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(image_bytes)) as image:
                image_format = (image.format or "").upper()
                if image_format not in SUPPORTED_FORMATS:
                    raise CTFForgeError(
                        f"Unsupported image format {image.format!r}; supported formats are "
                        "JPEG, PNG, TIFF, and WebP."
                    )
                exif_fields, exif_error, exif_details = _read_exif(image)
                info = image.info
                text_metadata = {}
                for key, item in list(info.items())[:MAX_METADATA_FIELDS]:
                    if key.lower() in {"exif", "icc_profile", "xmp", "photoshop"}:
                        continue
                    if isinstance(item, (str, int, float, bool, tuple, list)):
                        text_metadata[str(key)[:128]] = _safe_value(item)
                comments = {
                    key: value for key, value in text_metadata.items()
                    if "comment" in key.lower() or "description" in key.lower()
                }
                metadata_present = bool(exif_fields or text_metadata)
                findings = []
                findings.append(
                    "Image metadata was found." if metadata_present
                    else "No EXIF or readable image text metadata was found."
                )
                if exif_error:
                    findings.append(exif_error)
                if exif_details.get("gps"):
                    findings.append("GPS metadata is present; review it for location information.")
                result = make_result(
                    "steg", str(path), tool="metadata", file_size=size,
                    image={
                        "format": image_format,
                        "dimensions": list(image.size),
                        "mode": image.mode,
                    },
                    metadata_status="present" if metadata_present else "absent",
                    exif_status=(
                        "unavailable" if exif_error else "present" if exif_fields else "absent"
                    ),
                    exif=exif_fields, timestamps=exif_details.get("timestamps", {}),
                    gps=exif_details.get("gps", {}), text_chunks=text_metadata,
                    comments=comments, findings=findings,
                    confidence=100 if image_format else 0,
                    recommendations=[
                        "Metadata presence or absence does not by itself establish hidden content."
                    ],
                )
                return result
    except CTFForgeError:
        raise
    except (
        UnidentifiedImageError,
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
    ) as exc:
        raise CTFForgeError(
            f"Cannot parse image {path}: {exc or 'invalid or unsafe image'}"
        ) from exc
    except (OSError, SyntaxError, ValueError) as exc:
        raise CTFForgeError(
            f"Cannot parse image {path}: malformed or unsupported image data."
        ) from exc
