"""Bounded signature scanning and opt-in recovery for selected file types."""
import hashlib
import os
from pathlib import Path

from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult
from ctfforge.integrations.binwalk import scan_signatures

MAX_SOURCE = 128 * 1024 * 1024
MAX_CANDIDATES = 500
MAX_RECOVERED = 20
MAX_RECOVERED_SIZE = 25 * 1024 * 1024
SIGNATURES = ((b"\xff\xd8\xff", "jpeg", ".jpg"), (b"\x89PNG\r\n\x1a\n", "png", ".png"),
              (b"%PDF-", "pdf", ".pdf"), (b"PK\x03\x04", "zip", ".zip"))


def scan(data: bytes):
    found = []
    for signature, name, suffix in SIGNATURES:
        offset = 0
        while len(found) < MAX_CANDIDATES:
            offset = data.find(signature, offset)
            if offset < 0: break
            found.append({"offset": offset, "type": name, "suffix": suffix, "signature_length": len(signature)})
            offset += len(signature)
    return sorted(found, key=lambda row: row["offset"])[:MAX_CANDIDATES]


def _boundary(data: bytes, start: int, kind: str):
    if kind == "jpeg":
        end = data.find(b"\xff\xd9", start + 3)
        return end + 2 if end >= 0 else None
    if kind == "png":
        pos = start + 8
        while pos + 12 <= len(data):
            length = int.from_bytes(data[pos:pos + 4], "big")
            end = pos + 12 + length
            if end > len(data): return None
            chunk_type = data[pos + 4:pos + 8]
            if chunk_type == b"IEND": return end
            pos = end
        return None
    if kind == "pdf":
        end = data.find(b"%%EOF", start + 5)
        return end + 5 if end >= 0 else None
    if kind == "zip":
        end = data.find(b"PK\x05\x06", start + 4)
        if end < 0 or end + 22 > len(data): return None
        comment_length = int.from_bytes(data[end + 20:end + 22], "little")
        return end + 22 + comment_length if end + 22 + comment_length <= len(data) else None
    return None


def _unique_write(directory: Path, name: str, contents: bytes) -> Path:
    stem, suffix = Path(name).stem, Path(name).suffix
    for index in range(1000):
        target = directory / (f"{stem}{suffix}" if index == 0 else f"{stem}_{index}{suffix}")
        try:
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue
        with os.fdopen(descriptor, "wb") as stream: stream.write(contents)
        return target
    raise CTFForgeError("Cannot allocate a unique output filename.")


def analyze(context: ToolContext) -> ToolResult:
    args = context.arguments; path = Path(args["file"]).expanduser()
    try:
        with path.open("rb") as stream: data = stream.read(MAX_SOURCE + 1)
    except OSError as exc: raise CTFForgeError(f"Cannot read source file: {exc}") from exc
    if len(data) > MAX_SOURCE: raise CTFForgeError(f"Source exceeds {MAX_SOURCE} byte scan limit.")
    candidates = scan(data)
    for row in candidates:
        end = _boundary(data, row["offset"], row["type"])
        row["end_offset"] = end
        row["size"] = end - row["offset"] if end else None
        row["complete"] = end is not None
        row["ambiguous"] = end is None
    extracted = []
    offsets = args.get("extract_offset") or []
    if offsets:
        chosen = []
        for offset in offsets:
            candidate = next((row for row in candidates if row["offset"] == offset), None)
            if candidate is None: raise CTFForgeError(f"No supported signature candidate at offset {offset}.")
            if candidate in chosen: continue
            chosen.append(candidate)
        if len(chosen) > MAX_RECOVERED: raise CTFForgeError(f"At most {MAX_RECOVERED} files can be recovered per run.")
        outdir = Path(args["output_dir"]).expanduser()
        outdir.mkdir(parents=True, exist_ok=True)
        for candidate in chosen:
            end = candidate["end_offset"]
            if end is None: raise CTFForgeError(f"Candidate at {candidate['offset']} is incomplete; refusing ambiguous recovery.")
            size = end - candidate["offset"]
            if size > MAX_RECOVERED_SIZE: raise CTFForgeError(f"Candidate at {candidate['offset']} exceeds recovered file size limit.")
            name = f"recovered_{candidate['offset']:08x}{candidate['suffix']}"
            saved = _unique_write(outdir, name, data[candidate["offset"]:end])
            extracted.append({"offset": candidate["offset"], "path": str(saved), "size": size,
                              "sha256": hashlib.sha256(data[candidate["offset"]:end]).hexdigest()})
    backend = args.get("backend", "auto"); binwalk = None
    if backend in ("auto", "binwalk"):
        result = scan_signatures(path)
        binwalk = {"available": result.available, "returncode": result.returncode, "timed_out": result.timed_out,
                   "output_truncated": result.output_truncated, "error": result.error,
                   "output": result.stdout[:10000] if result.available else None}
        if backend == "binwalk" and not result.available: raise CTFForgeError(result.error or "Binwalk unavailable.")
    return make_result("forensics", str(path), tool="carve", input_bytes=len(data), candidates=candidates,
                       extracted=extracted, binwalk=binwalk,
                       limits={"source_bytes": MAX_SOURCE, "candidates": MAX_CANDIDATES,
                               "recovered_files": MAX_RECOVERED, "recovered_file_bytes": MAX_RECOVERED_SIZE},
                       note="Signature matches are candidates, not proof of valid files. Incomplete and ambiguous candidates are reported; recovered data is never executed.")
