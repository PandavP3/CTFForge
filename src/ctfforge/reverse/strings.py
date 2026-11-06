"""Bounded printable ASCII and UTF-16LE string extraction."""
from pathlib import Path

from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult
from .formats import read_binary

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_STRINGS = 100_000
MAX_STORED_CHARS = 4096
MAX_EXPORT_BYTES = 8 * 1024 * 1024


def _ascii_strings(data: bytes, minimum: int):
    start = None
    sample = bytearray()
    length = 0
    for offset, value in enumerate(data):
        if 32 <= value <= 126:
            if start is None:
                start = offset
            length += 1
            if len(sample) < MAX_STORED_CHARS:
                sample.append(value)
        else:
            if start is not None and length >= minimum:
                yield {"offset": start, "encoding": "ASCII", "string": sample.decode("ascii"),
                       "length": length, "truncated": length > MAX_STORED_CHARS}
            start, sample, length = None, bytearray(), 0
    if start is not None and length >= minimum:
        yield {"offset": start, "encoding": "ASCII", "string": sample.decode("ascii"),
               "length": length, "truncated": length > MAX_STORED_CHARS}


def _utf16le_strings(data: bytes, minimum: int):
    for alignment in (0, 1):
        start = None
        sample = []
        length = 0
        offset = alignment
        while offset + 1 < len(data):
            code = data[offset] | (data[offset + 1] << 8)
            if chr(code).isprintable() and code != 0:
                if start is None:
                    start = offset
                length += 1
                if len(sample) < MAX_STORED_CHARS:
                    sample.append(chr(code))
                offset += 2
            else:
                if start is not None and length >= minimum:
                    yield {"offset": start, "encoding": "UTF-16LE", "string": "".join(sample),
                           "length": length, "truncated": length > MAX_STORED_CHARS}
                start, sample, length = None, [], 0
                offset += 2
        if start is not None and length >= minimum:
            yield {"offset": start, "encoding": "UTF-16LE", "string": "".join(sample),
                   "length": length, "truncated": length > MAX_STORED_CHARS}


def extract(data: bytes, *, minimum: int = 4, encoding: str = "both", limit: int = 10000):
    if not 1 <= minimum <= 256:
        raise CTFForgeError("Minimum string length must be between 1 and 256.")
    if not 1 <= limit <= MAX_STRINGS:
        raise CTFForgeError(f"String limit must be between 1 and {MAX_STRINGS}.")
    if encoding not in ("ascii", "utf16le", "both"):
        raise CTFForgeError("Encoding must be ascii, utf16le, or both.")
    result = []
    if encoding in ("ascii", "both"):
        result.extend(item for _, item in zip(range(limit), _ascii_strings(data, minimum)))
    if encoding in ("utf16le", "both"):
        result.extend(item for _, item in zip(range(limit), _utf16le_strings(data, minimum)))
    result.sort(key=lambda row: (row["offset"], row["encoding"]))
    return result[:limit]


def _export(path: Path, source: Path, rows: list[dict]):
    try:
        if path.resolve() == source.resolve():
            raise CTFForgeError("String export path must not overwrite the analyzed input file.")
        text = "".join(f"{row['offset']:#010x}\t{row['encoding']}\t{row['string']}\n" for row in rows)
        encoded = text.encode("utf-8")
        if len(encoded) > MAX_EXPORT_BYTES:
            raise CTFForgeError(f"String export exceeds the {MAX_EXPORT_BYTES}-byte output limit.")
        with path.expanduser().open("xb") as stream:
            stream.write(encoded)
    except FileExistsError as exc:
        raise CTFForgeError(f"Refusing to overwrite existing output file: {path}") from exc
    except OSError as exc:
        raise CTFForgeError(f"Cannot write string export {path}: {exc}") from exc
    return str(path.expanduser())


def analyze(context: ToolContext) -> ToolResult:
    args = context.arguments
    path, data = read_binary(args.get("file"), maximum=MAX_FILE_BYTES)
    try:
        minimum, limit = int(args.get("min_length", 4)), int(args.get("limit", 10000))
    except (TypeError, ValueError) as exc:
        raise CTFForgeError("Minimum length and limit must be integers.") from exc
    rows = extract(data, minimum=minimum, encoding=str(args.get("encoding", "both")), limit=limit)
    output = args.get("output")
    exported = _export(Path(output), path, rows) if output else None
    return make_result("reverse", str(path), tool="strings", file_size=len(data),
                       min_length=minimum, encoding=args.get("encoding", "both"),
                       strings=rows, string_count=len(rows), output_file=exported,
                       output_limit=limit, note="Extracted strings are untrusted text and are never executed.")
