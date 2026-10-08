"""Streaming file hashes and entropy calculation."""

import hashlib
import math
from pathlib import Path


def hash_file(path: Path, algorithms: tuple[str, ...] = ("md5", "sha1", "sha256")) -> dict[str, str]:
    digests = {name: hashlib.new(name) for name in algorithms}
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    size = len(data)
    return -sum((n / size) * math.log2(n / size) for n in counts if n)
