"""Bounded XOR analysis for CTF text and binary artifacts."""

from pathlib import Path

from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult

MAX_INPUT_BYTES = 16 * 1024 * 1024


def _read_data(context: ToolContext) -> tuple[bytes, str]:
    args = context.arguments
    sources = [key for key in ("file", "input", "hex") if args.get(key) is not None]
    if len(sources) != 1:
        raise CTFForgeError("Provide exactly one of file, input, or hex.")
    source = sources[0]
    if source == "file":
        path = Path(str(args["file"])).expanduser()
        try:
            with path.open("rb") as stream:
                data = stream.read(MAX_INPUT_BYTES + 1)
        except OSError as exc:
            raise CTFForgeError(f"Cannot read input file {path}: {exc}") from exc
        if len(data) > MAX_INPUT_BYTES:
            raise CTFForgeError(f"Input exceeds the {MAX_INPUT_BYTES}-byte processing limit.")
        return data, str(path)
    value = str(args[source])
    if source == "hex":
        if len(value) > MAX_INPUT_BYTES * 2:
            raise CTFForgeError(f"Hex input exceeds the {MAX_INPUT_BYTES}-byte processing limit.")
        try:
            data = bytes.fromhex(value)
        except ValueError as exc:
            raise CTFForgeError("Hex input must contain an even number of valid hex digits.") from exc
        if len(data) > MAX_INPUT_BYTES:
            raise CTFForgeError(f"Input exceeds the {MAX_INPUT_BYTES}-byte processing limit.")
        return data, "<hex input>"
    data = value.encode("utf-8")
    if len(data) > MAX_INPUT_BYTES:
        raise CTFForgeError(f"Input exceeds the {MAX_INPUT_BYTES}-byte processing limit.")
    return data, "<text input>"


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR bytes with a non-empty repeating key."""
    if not key:
        raise CTFForgeError("XOR key cannot be empty.")
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))


def _candidate_score(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(byte in (9, 10, 13) or 32 <= byte <= 126 for byte in data) / len(data)
    text = data.decode("ascii", errors="ignore").lower()
    letters = sum(char.isalpha() for char in text) / len(data)
    spaces = text.count(" ") / len(data)
    common = sum(text.count(word) for word in (" the ", " and ", " to ", " of ", " is "))
    common_score = min(common / max(len(data) / 30, 1), 1.0)
    return round(0.62 * printable + 0.20 * min(letters * 2.5, 1.0)
                 + 0.10 * min(spaces * 6, 1.0) + 0.08 * common_score, 6)


def rank_single_byte_keys(data: bytes, limit: int = 10) -> list[dict[str, object]]:
    """Return the highest-scoring single-byte XOR candidates."""
    if not 1 <= limit <= 256:
        raise CTFForgeError("Candidate limit must be between 1 and 256.")
    candidates = []
    for key in range(256):
        plaintext = xor_bytes(data, bytes((key,)))
        candidates.append({
            "key": key,
            "key_hex": f"{key:02x}",
            "score": _candidate_score(plaintext),
            "plaintext": plaintext.decode("utf-8", errors="replace"),
        })
    candidates.sort(key=lambda item: (-float(item["score"]), int(item["key"])))
    return candidates[:limit]


def analyze(context: ToolContext) -> ToolResult:
    """Run brute-force, known single-byte, or repeating-key XOR analysis."""
    data, target = _read_data(context)
    args = context.arguments
    key = args.get("key")
    repeat_key = args.get("repeat_key")
    if key is not None and repeat_key is not None:
        raise CTFForgeError("Choose either a single-byte key or a repeating key.")
    if key is not None:
        key_bytes = str(key).encode("utf-8")
        if len(key_bytes) != 1:
            raise CTFForgeError("--key must encode exactly one UTF-8 byte; use --repeat-key for longer keys.")
        plaintext = xor_bytes(data, key_bytes)
        findings = [{"mode": "known single-byte XOR", "key": str(key),
                     "key_hex": key_bytes.hex(), "plaintext": plaintext.decode("utf-8", "replace")}]
        mode = "known-single-byte"
    elif repeat_key is not None:
        key_bytes = str(repeat_key).encode("utf-8")
        if not key_bytes:
            raise CTFForgeError("Repeating XOR key cannot be empty.")
        plaintext = xor_bytes(data, key_bytes)
        findings = [{"mode": "repeating-key XOR", "key": str(repeat_key),
                     "plaintext": plaintext.decode("utf-8", "replace")}]
        mode = "repeating-key"
    else:
        try:
            limit = int(args.get("limit", 10))
        except (TypeError, ValueError) as exc:
            raise CTFForgeError("Candidate limit must be an integer between 1 and 256.") from exc
        findings = rank_single_byte_keys(data, limit)
        mode = "single-byte brute force"
    return make_result(
        "crypto", target, tool="xor", mode=mode, input_bytes=len(data), findings=findings,
        confidence=max((float(row.get("score", 0)) for row in findings), default=0),
        recommendations=["Review candidate plaintexts and validate any result against challenge clues."],
    )
