"""Bounded-output subprocess execution for allowlisted optional utilities."""
import shutil
import subprocess
import threading
import math
from numbers import Real
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
    if isinstance(timeout, bool) or not isinstance(timeout, Real):
        raise ValueError("timeout must be a finite positive number; booleans are not accepted.")
    try:
        valid_timeout = math.isfinite(timeout) and timeout > 0
    except OverflowError:
        valid_timeout = False
    if not valid_timeout:
        raise ValueError("timeout must be a finite positive number; booleans are not accepted.")
    if isinstance(output_limit, bool) or not isinstance(output_limit, int) or output_limit <= 0:
        raise ValueError("output_limit must be a positive integer; booleans are not accepted.")
    if executable not in {"tshark", "binwalk", "file", "readelf", "objdump"}:
        raise ValueError("External executable is not allowlisted.")
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
    locks = [threading.Lock(), threading.Lock()]

    def drain(stream, buffer, flag, lock):
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                with lock:
                    room = max(0, output_limit - len(buffer))
                    buffer.extend(chunk[:room])
                    if len(chunk) > room:
                        flag[0] = True
        except (OSError, ValueError):
            # Stream closure during bounded cleanup is expected on some platforms.
            return

    readers = [threading.Thread(target=drain, args=(pipe, data, trunc, lock), daemon=True)
               for pipe, data, trunc, lock in zip((process.stdout, process.stderr), streams, truncated, locks)]
    for reader in readers:
        reader.start()
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            process.kill()
        except OSError:
            # The child may have exited after wait raised its timeout.
            if process.poll() is None:
                raise
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            # kill() should terminate the direct child; this guards broken wrappers.
            try:
                process.kill()
            except OSError:
                pass
            process.wait()
    finally:
        # A descendant can inherit stdout/stderr and keep a pipe open after the
        # direct utility exits. Close our ends and bound reader cleanup in that case.
        for reader, pipe in zip(readers, (process.stdout, process.stderr)):
            reader.join(timeout=1)
            if reader.is_alive():
                try:
                    # Closing the raw descriptor avoids waiting on the buffered
                    # reader's lock while that reader is blocked in a pipe read.
                    getattr(pipe, "raw", pipe).close()
                except (OSError, ValueError):
                    pass
                reader.join(timeout=1)
            if not reader.is_alive():
                try:
                    pipe.close()
                except (OSError, ValueError):
                    pass
    # Snapshot under the same locks used by drain threads. Even if a platform
    # cannot interrupt a blocked pipe read, the returned strings are immutable
    # snapshots and are no longer backed by buffers a daemon reader can mutate.
    with locks[0]:
        stdout = bytes(streams[0]).decode("utf-8", "replace")
        stdout_truncated = truncated[0][0]
    with locks[1]:
        stderr = bytes(streams[1]).decode("utf-8", "replace")
        stderr_truncated = truncated[1][0]
    return ProcessResult(True, stdout, stderr, process.returncode,
                         timed_out, stdout_truncated or stderr_truncated,
                         f"{executable} timed out after {timeout:g} seconds" if timed_out else None)
