import subprocess
import threading
from io import BytesIO
import math

import pytest

from ctfforge.integrations import _process, binwalk, tshark


def test_external_missing_executable(monkeypatch, tmp_path):
    monkeypatch.setattr(_process.shutil, "which", lambda name: None)
    result = tshark.analyze_capture(tmp_path / "trace.pcap")
    assert not result.available and "unavailable" in result.error


def test_fixed_arguments_no_shell_and_output_limit(monkeypatch, tmp_path):
    observed = {}
    class FakeProcess:
        stdout = BytesIO(b"abcdefghij")
        stderr = BytesIO(b"errortext")
        returncode = 0
        def __init__(self, command, **kwargs):
            observed["command"] = command; observed["kwargs"] = kwargs
        def wait(self, timeout=None): return 0
    monkeypatch.setattr(_process.shutil, "which", lambda name: "C:/tools/" + name)
    monkeypatch.setattr(_process.subprocess, "Popen", FakeProcess)
    result = binwalk.scan_signatures(tmp_path / "evidence.bin", output_limit=4)
    assert observed["kwargs"]["shell"] is False
    assert "--signature" in observed["command"] and "--quiet" in observed["command"]
    assert "--extract" not in " ".join(observed["command"])
    assert result.stdout == "abcd" and result.output_truncated


def test_process_timeout_and_allowlist(monkeypatch, tmp_path):
    class SlowProcess:
        stdout = BytesIO(b"")
        stderr = BytesIO(b"")
        returncode = -9
        calls = 0
        def __init__(self, *args, **kwargs): pass
        def wait(self, timeout=None):
            self.calls += 1
            if self.calls == 1: raise subprocess.TimeoutExpired("binwalk", timeout)
        def kill(self): pass
    monkeypatch.setattr(_process.shutil, "which", lambda name: "binwalk.exe")
    monkeypatch.setattr(_process.subprocess, "Popen", SlowProcess)
    result = binwalk.scan_signatures(tmp_path / "sample", timeout=0.01)
    assert result.timed_out
    try:
        _process.run_bounded("custom", ["--arg"])
    except ValueError:
        pass
    else:
        raise AssertionError("non-allowlisted executable accepted")


@pytest.mark.parametrize("timeout", [0, -1, True, math.nan, math.inf, -math.inf])
def test_bounded_process_rejects_invalid_timeouts(timeout):
    with pytest.raises(ValueError, match="finite positive number"):
        _process.run_bounded("file", ["--version"], timeout=timeout)


@pytest.mark.parametrize("output_limit", [0, -1, True, 1.5, "100"])
def test_bounded_process_rejects_invalid_output_limits(output_limit):
    with pytest.raises(ValueError, match="positive integer"):
        _process.run_bounded("file", ["--version"], output_limit=output_limit)


def test_timed_out_child_is_killed_and_reader_threads_finish(monkeypatch):
    instances = []
    readers = []
    thread_type = threading.Thread
    def tracked_thread(*args, **kwargs):
        thread = thread_type(*args, **kwargs)
        readers.append(thread)
        return thread
    monkeypatch.setattr(_process.threading, "Thread", tracked_thread)
    class SlowProcess:
        def __init__(self, *args, **kwargs):
            self.stdout, self.stderr = BytesIO(), BytesIO()
            self.returncode = -9
            self.wait_calls = 0
            self.kill_calls = 0
            instances.append(self)
        def wait(self, timeout=None):
            self.wait_calls += 1
            if self.wait_calls == 1:
                raise subprocess.TimeoutExpired("file", timeout)
            return self.returncode
        def kill(self):
            self.kill_calls += 1
    monkeypatch.setattr(_process.shutil, "which", lambda _: "/mock/file")
    monkeypatch.setattr(_process.subprocess, "Popen", SlowProcess)
    result = _process.run_bounded("file", ["--version"], timeout=0.1)
    assert result.timed_out and instances[0].kill_calls == 1
    assert len(readers) == 2 and all(not thread.is_alive() for thread in readers)


def test_kill_race_when_child_exits_is_handled(monkeypatch):
    class ExitedProcess:
        def __init__(self, *args, **kwargs):
            self.stdout, self.stderr = BytesIO(), BytesIO()
            self.returncode = 0
            self.wait_calls = 0
        def wait(self, timeout=None):
            self.wait_calls += 1
            if self.wait_calls == 1:
                raise subprocess.TimeoutExpired("file", timeout)
            return 0
        def kill(self):
            raise ProcessLookupError("already exited")
        def poll(self):
            return 0
    monkeypatch.setattr(_process.shutil, "which", lambda _: "/mock/file")
    monkeypatch.setattr(_process.subprocess, "Popen", ExitedProcess)
    assert _process.run_bounded("file", ["--version"], timeout=0.1).timed_out


def test_tshark_and_binwalk_remain_compatible(monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(_process.shutil, "which", lambda name: "/mock/" + name)
    class Completed:
        returncode = 0
        def __init__(self, *args, **kwargs):
            self.stdout, self.stderr = BytesIO(), BytesIO()
        def wait(self, timeout=None):
            return 0
    def capture(command, **kwargs):
        seen.append(command)
        return Completed(command, **kwargs)
    monkeypatch.setattr(_process.subprocess, "Popen", capture)
    assert tshark.analyze_capture(tmp_path / "trace.pcap").available
    assert binwalk.scan_signatures(tmp_path / "evidence.bin").available
    assert seen[0][0] == "/mock/tshark" and seen[1][0] == "/mock/binwalk"


def test_tshark_uses_fixed_field_mode(monkeypatch, tmp_path):
    seen = {}
    def fake(name, args, **kwargs):
        seen["name"] = name; seen["args"] = args
        return _process.ProcessResult(True, returncode=0)
    monkeypatch.setattr(tshark, "run_bounded", fake)
    tshark.analyze_capture(tmp_path / "capture.pcap")
    assert seen["name"] == "tshark"
    assert seen["args"][:4] == ["-n", "-r", str((tmp_path / "capture.pcap").resolve()), "-T"]
    assert "-e" in seen["args"] and "-x" not in seen["args"]
