"""Bounded heuristic LSB analysis for lossless raster images."""

import warnings
from io import BytesIO
from pathlib import Path
from typing import Any

from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult

MAX_IMAGE_BYTES = 32 * 1024 * 1024
MAX_PIXELS = 4_000_000
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
SUPPORTED_FORMATS = {"PNG", "TIFF", "BMP", "GIF", "WEBP"}
_CHANNELS = {"red": 0, "green": 1, "blue": 2, "alpha": 3}
_BAND_NAMES = {"R": "red", "G": "green", "B": "blue", "A": "alpha"}
_READABLE_MARKERS = (b"CTF{", b"FLAG{", b"flag{", b"http://", b"https://", b"password", b"secret")


def _pack(values, channel: int, plane: int, bit_order: str) -> bytes:
    """Pack pixels in traversal order; msb sets first pixel as byte bit 7."""
    count = len(values)
    out = bytearray((count + 7) // 8)
    for index, pixel in enumerate(values):
        bit = (pixel[channel] >> plane) & 1
        shift = 7 - index % 8 if bit_order == "msb" else index % 8
        out[index // 8] |= bit << shift
    return bytes(out)


def extract_channel(pixels: list[tuple[int, ...]], channel: int, bit_plane: int,
                    bit_order: str = "msb") -> bytes:
    """Extract one channel in row-major order and pack bits into bytes."""
    return _pack(pixels, channel, bit_plane, bit_order)


def _candidate(channel: str, plane: int, order: str, data: bytes) -> dict[str, Any]:
    printable = sum(byte in (9, 10, 13) or 32 <= byte <= 126 for byte in data)
    ratio = printable / len(data) if data else 0.0
    try:
        text = data.decode("utf-8")
        utf8_valid = True
    except UnicodeDecodeError:
        text = None
        utf8_valid = False
    null_ratio = data.count(0) / len(data) if data else 0.0
    lower = data.lower()
    markers = [marker.decode("ascii") for marker in _READABLE_MARKERS if marker.lower() in lower]
    # Transparent score: printable bytes (0-70), valid UTF-8 (0-20), markers (0-10),
    # with a small penalty for null-heavy streams. This ranks candidates; it is not proof.
    score = min(70.0, ratio * 70) + (20 if utf8_valid and data else 0)
    score += min(10, len(markers) * 5) - min(20, null_ratio * 20)
    preview = None
    if ratio >= 0.55 and text is not None:
        preview = "".join(char if char.isprintable() else " " for char in text[:160])
    return {
        "channel": channel, "bit_plane": plane, "bit_order": order,
        "extracted_byte_count": len(data), "printable_ratio": round(ratio, 4),
        "null_byte_ratio": round(null_ratio, 4), "utf8_valid": utf8_valid,
        "candidate_score": round(max(0.0, min(100.0, score)), 2),
        "readable_patterns": markers, "preview": preview, "_data": data,
    }


def analyze(context: ToolContext) -> ToolResult:
    """Analyze independent bit streams from a lossless image; never proves steganography."""
    try:
        from PIL import Image, UnidentifiedImageError
    except ModuleNotFoundError as exc:
        if exc.name == "PIL" or (exc.name and exc.name.startswith("PIL.")):
            raise CTFForgeError("LSB analysis requires Pillow. Install it with: python -m pip install -r requirements/steg.txt") from exc
        raise

    args = context.arguments
    value = args.get("file")
    if not isinstance(value, (str, Path)):
        raise CTFForgeError("Steg LSB requires a file path argument named 'file'.")
    path = Path(value).expanduser()
    if not path.is_file():
        raise CTFForgeError(f"Target is not a regular file: {path}")
    try:
        size = path.stat().st_size
        if size > MAX_IMAGE_BYTES:
            raise CTFForgeError(f"Image exceeds the {MAX_IMAGE_BYTES}-byte LSB processing limit.")
        with path.open("rb") as stream:
            raw = stream.read(MAX_IMAGE_BYTES + 1)
    except OSError as exc:
        raise CTFForgeError(f"Cannot read image {path}: {exc}") from exc
    if len(raw) > MAX_IMAGE_BYTES:
        raise CTFForgeError(f"Image exceeds the {MAX_IMAGE_BYTES}-byte LSB processing limit.")

    channel_arg = args.get("channel", "all")
    plane = args.get("bit_plane", 0)
    order = args.get("bit_order", "msb")
    if channel_arg not in (*_CHANNELS, "all"):
        raise CTFForgeError("Channel must be red, green, blue, alpha, or all.")
    if isinstance(plane, bool) or not isinstance(plane, int) or not 0 <= plane <= 7:
        raise CTFForgeError("Bit plane must be an integer from 0 through 7.")
    if order not in ("msb", "lsb"):
        raise CTFForgeError("Bit order must be msb or lsb.")

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(raw)) as image:
                image_format = (image.format or "").upper()
                if image_format == "JPEG":
                    raise CTFForgeError("JPEG is lossy; basic LSB recovery is unreliable. Use a lossless image format.")
                if image_format not in SUPPORTED_FORMATS:
                    raise CTFForgeError("Unsupported image format; LSB analysis supports PNG, TIFF, BMP, GIF, and WebP lossless images.")
                if image_format == "WEBP" and b"VP8L" not in raw:
                    raise CTFForgeError("Only lossless WebP (VP8L) is supported for LSB recovery.")
                width, height = image.size
                if width <= 0 or height <= 0 or width * height > MAX_PIXELS:
                    raise CTFForgeError(f"Image dimensions exceed the {MAX_PIXELS}-pixel LSB processing limit.")
                if image.mode in ("RGB", "RGBA"):
                    converted = image
                elif image.mode in ("L", "LA", "1"):
                    converted = image.convert("RGBA" if image.mode == "LA" else "RGB")
                else:
                    converted = image.convert("RGBA" if "A" in image.getbands() else "RGB")
                bands = converted.getbands()
                pixels = converted.getdata()
                if len(pixels) != width * height:
                    raise CTFForgeError("Decoded image dimensions do not match its pixel data.")
    except CTFForgeError:
        raise
    except (UnidentifiedImageError, Image.DecompressionBombError, Image.DecompressionBombWarning,
            OSError, SyntaxError, ValueError) as exc:
        raise CTFForgeError(f"Cannot parse image {path}: malformed or unsafe image data.") from exc

    indexes = {_BAND_NAMES[name]: index for index, name in enumerate(bands)
               if name in _BAND_NAMES}
    available = [name for name in ("red", "green", "blue", "alpha") if name in indexes]
    selected = available if channel_arg == "all" else [channel_arg]
    if any(name not in indexes for name in selected):
        raise CTFForgeError(f"Channel {channel_arg!r} is unavailable in this image; available channels: {', '.join(available)}.")
    if (len(pixels) + 7) // 8 > MAX_OUTPUT_BYTES:
        raise CTFForgeError(f"Extracted stream would exceed the {MAX_OUTPUT_BYTES}-byte output limit.")

    candidates = [_candidate(name, plane, order,
                  extract_channel(pixels, indexes[name], plane, order))
                  for name in selected]
    candidates.sort(key=lambda item: (-item["candidate_score"], item["channel"]))
    output = args.get("output")
    text_requested = bool(args.get("text", False))
    if (output is not None or text_requested) and len(candidates) != 1:
        raise CTFForgeError("--output and --text require one selected channel; choose --channel red, green, blue, or alpha.")
    text_value = None
    if text_requested:
        if not candidates[0]["utf8_valid"]:
            raise CTFForgeError("Extracted stream is not valid UTF-8; omit --text and use --output for binary data.")
        text_value = candidates[0]["_data"].decode("utf-8")
        if len(text_value) > 4096:
            text_value = text_value[:4096] + "\n[truncated; use --output to save the full stream]"
    output_info = None
    if output is not None:
        destination = Path(output).expanduser()
        data = candidates[0]["_data"]
        if len(data) > MAX_OUTPUT_BYTES:
            raise CTFForgeError(f"Extracted data exceeds the {MAX_OUTPUT_BYTES}-byte output limit.")
        try:
            with destination.open("xb") as stream:
                stream.write(data)
        except FileExistsError as exc:
            raise CTFForgeError(f"Output file already exists; refusing to overwrite: {destination}") from exc
        except OSError as exc:
            raise CTFForgeError(f"Cannot write output file {destination}: {exc}") from exc
        output_info = {"path": str(destination), "bytes_written": len(data), "format": "binary"}
    public_candidates = [{key: value for key, value in item.items() if key != "_data"}
                         for item in candidates]
    result = make_result(
        "steg", str(path), tool="lsb", image={"format": image_format, "dimensions": [width, height],
        "mode": image.mode}, traversal="row-major", bit_order=order, bit_plane=plane,
        candidates=public_candidates, output=output_info, extracted_text=text_value,
        findings=["LSB candidate scores are heuristic. Readable data is not proof of hidden content."],
        recommendations=["Compare candidate streams with challenge context; lossless image transforms may still alter pixel data."],
    )
    return result
