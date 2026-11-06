"""Overall and bounded block-based Shannon entropy analysis."""
import math

from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.hashing import shannon_entropy
from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult
from .formats import read_binary

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_BLOCK_SIZE = 1024 * 1024
MAX_BLOCKS = 32768
HIGH_ENTROPY_THRESHOLD = 7.2


def analyze(context: ToolContext) -> ToolResult:
    args = context.arguments
    path, data = read_binary(args.get("file"), maximum=MAX_FILE_BYTES)
    try:
        block_size = int(args.get("block_size", 4096))
    except (TypeError, ValueError) as exc:
        raise CTFForgeError("Block size must be an integer.") from exc
    if not 256 <= block_size <= MAX_BLOCK_SIZE:
        raise CTFForgeError(f"Block size must be between 256 and {MAX_BLOCK_SIZE} bytes.")
    count = math.ceil(len(data) / block_size) if data else 0
    if count > MAX_BLOCKS:
        raise CTFForgeError(f"Block count exceeds {MAX_BLOCKS}; choose a larger block size.")
    blocks = []
    for offset in range(0, len(data), block_size):
        entropy = shannon_entropy(data[offset:offset + block_size])
        blocks.append({"offset": offset, "size": min(block_size, len(data) - offset),
                       "entropy": round(entropy, 6),
                       "high_entropy_indicator": entropy >= HIGH_ENTROPY_THRESHOLD})
    overall = shannon_entropy(data)
    high = [row for row in blocks if row["high_entropy_indicator"]]
    findings = ([{"severity": "info", "message": "High-entropy blocks may contain compressed, encrypted, or otherwise high-variation data.",
                  "block_count": len(high), "threshold": HIGH_ENTROPY_THRESHOLD}] if high else [])
    return make_result("reverse", str(path), tool="entropy", file_size=len(data),
                       overall_entropy=round(overall, 6), block_size=block_size,
                       blocks=blocks, high_entropy_blocks=len(high), findings=findings,
                       warning="Entropy is a statistical heuristic. High entropy alone does not prove encryption, packing, or malicious behavior.")
