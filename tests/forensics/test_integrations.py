import subprocess
from io import BytesIO

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
