"""Bounded-output subprocess execution for allowlisted optional utilities."""
import shutil
import subprocess
import threading
from dataclasses import dataclass


@dataclass
class ProcessResult:
    available: bool
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    timed_out: bool = False
    output_truncated: bool = False
    error: str | None = None


def run_bounded(executable: str, arguments: list[str], *, timeout: float = 30,
                output_limit: int = 2_000_000) -> ProcessResult:
    if executable not in {"tshark", "binwalk"}:
        raise ValueError("External forensic executable is not allowlisted.")
    path = shutil.which(executable)
    if path is None:
        return ProcessResult(False, error=f"Optional executable {executable!r} is unavailable.")
    # Utility wrappers supply fixed flags; the only variable argument is an input path.
    if not arguments or any("\x00" in arg for arg in arguments):
        raise ValueError("Invalid external command arguments.")
    try:
        process = subprocess.Popen([path, *arguments], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=False)
    except OSError as exc:
        return ProcessResult(False, error=f"Could not start {executable}: {exc}")
    streams = [bytearray(), bytearray()]
    truncated = [[False], [False]]

    def drain(stream, buffer, flag):
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            room = max(0, output_limit - len(buffer))
            buffer.extend(chunk[:room])
            if len(chunk) > room:
                flag[0] = True

    readers = [threading.Thread(target=drain, args=(pipe, data, trunc), daemon=True)
               for pipe, data, trunc in zip((process.stdout, process.stderr), streams, truncated)]
    for reader in readers:
        reader.start()
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        process.wait()
    for reader in readers:
        reader.join(timeout=2)
    return ProcessResult(True, streams[0].decode("utf-8", "replace"),
                         streams[1].decode("utf-8", "replace"), process.returncode,
                         timed_out, any(flag[0] for flag in truncated),
                         f"{executable} timed out after {timeout:g} seconds" if timed_out else None)
