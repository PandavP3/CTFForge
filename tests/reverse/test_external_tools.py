import json
import subprocess
from io import BytesIO

import pytest

from ctfforge.core.cli import main
from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.interactive import run_interactive
from ctfforge.core.registration import build_core_registry
from ctfforge.core.tool import ToolContext
from ctfforge.integrations import _process, reverse_tools
from ctfforge.reverse.external_tools import elf_analysis, file_identification, objdump_analysis


def ctx(name, **args):
    return ToolContext("reverse", name, args)


def test_availability_reports_resolved_paths_and_missing_tools(monkeypatch):
    found = {"file": "/tools/file.exe", "readelf": None, "objdump": "/usr/bin/objdump"}
    monkeypatch.setattr(reverse_tools.shutil, "which", lambda name: found[name])
    rows = reverse_tools.availability()
    assert rows == [
        {"tool": "file", "available": True, "executable": "/tools/file.exe", "status": "available"},
        {"tool": "readelf", "available": False, "executable": None, "status": "not_found"},
        {"tool": "objdump", "available": True, "executable": "/usr/bin/objdump", "status": "available"},
    ]
    monkeypatch.setattr(reverse_tools.shutil, "which", lambda _: (_ for _ in ()).throw(OSError("lookup failed")))
    assert all(row["status"] == "lookup_error" for row in reverse_tools.availability())


def test_fixed_argument_mappings_for_all_readelf_and_objdump_modes(tmp_path, monkeypatch):
    observed = []
    def fake(executable, arguments, **kwargs):
        observed.append((executable, arguments, kwargs))
        return _process.ProcessResult(True, "report", returncode=0)
    monkeypatch.setattr(reverse_tools, "run_bounded", fake)
    path = tmp_path / "sample.elf"
    expected_readelf = {
        "header": ["-W", "-h"], "program-headers": ["-W", "-l"],
        "sections": ["-W", "-S"], "symbols": ["-W", "-s"],
        "dynamic": ["-W", "-d"], "relocations": ["-W", "-r"],
    }
    for mode, flags in expected_readelf.items():
        reverse_tools.run_readelf(path, mode)
        assert observed[-1][0] == "readelf"
        assert observed[-1][1] == [*flags, str(path.resolve())]
    expected_objdump = {
        "file-headers": ["-f"], "section-headers": ["-h"], "disassembly": ["-d"],
        "symbol-table": ["-t"], "private-headers": ["-p"],
    }
    for mode, flags in expected_objdump.items():
        reverse_tools.run_objdump(path, mode)
        assert observed[-1][0] == "objdump"
        assert observed[-1][1] == [*flags, str(path.resolve())]
    with pytest.raises(ValueError, match="Unsupported readelf mode"):
        reverse_tools.run_readelf(path, "--arbitrary")
    with pytest.raises(ValueError, match="Unsupported objdump mode"):
        reverse_tools.run_objdump(path, "--arbitrary")


def test_file_integration_success_validation_and_cli(tmp_path, monkeypatch, capsys):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data")
    calls = []
    def identify(path, **kwargs):
        calls.append((path, kwargs))
        return _process.ProcessResult(True, "ELF 64-bit LSB executable\n", returncode=0)
    monkeypatch.setattr(reverse_tools, "identify_file", identify)
    result = file_identification(ctx("external-file", file=sample, max_output=1234))
    assert result["execution_status"] == "success"
    assert result["input_filename"] == "sample.bin"
    assert result["identification"] == "ELF 64-bit LSB executable"
    assert calls[0][1]["output_limit"] == 1234
    assert main(["reverse", "external-file", "--file", str(sample)]) == 0
    assert json.loads(capsys.readouterr().out)["tool"] == "external-file"
    with pytest.raises(CTFForgeError, match="regular file"):
        file_identification(ctx("external-file", file=tmp_path / "missing"))
    with pytest.raises(CTFForgeError, match="Output limit"):
        file_identification(ctx("external-file", file=sample, max_output=0))
    monkeypatch.setattr(reverse_tools, "identify_file",
                        lambda *args, **kwargs: _process.ProcessResult(False, error="file unavailable"))
    missing = file_identification(ctx("external-file", file=sample))
    assert missing["execution_status"] == "unavailable"


@pytest.mark.parametrize(("handler", "tool", "mode", "executable"), [
    (elf_analysis, "external-elf", "dynamic", "readelf"),
    (objdump_analysis, "external-objdump", "disassembly", "objdump"),
])
def test_external_handler_status_modes_and_output_caps(tmp_path, monkeypatch, handler, tool, mode, executable):
    sample = tmp_path / "binary"
    sample.write_bytes(b"not executed")
    seen = {}
    def fake(name, arguments, **kwargs):
        seen.update(executable=name, arguments=arguments, kwargs=kwargs)
        return _process.ProcessResult(True, "bounded", "diagnostic", returncode=0,
                                      output_truncated=True)
    monkeypatch.setattr(reverse_tools, "run_bounded", fake)
    result = handler(ctx(tool, file=sample, mode=mode, max_output=77))
    assert seen["executable"] == executable
    assert seen["kwargs"]["output_limit"] == 77
    assert result["mode"] == mode and result["execution_status"] == "success"
    assert result["output_truncated"] is True


def test_missing_timeout_and_nonzero_process_results_are_structured(tmp_path, monkeypatch):
    sample = tmp_path / "object.o"
    sample.write_bytes(b"bytes")
    monkeypatch.setattr(reverse_tools, "run_readelf",
                        lambda *args, **kwargs: _process.ProcessResult(False, error="readelf unavailable"))
    missing = elf_analysis(ctx("external-elf", file=sample, mode="header"))
    assert missing["execution_status"] == "unavailable" and "unavailable" in missing["error"]
    monkeypatch.setattr(reverse_tools, "run_objdump",
                        lambda *args, **kwargs: _process.ProcessResult(True, "partial", "bad input", 1))
    failure = objdump_analysis(ctx("external-objdump", file=sample, mode="private-headers"))
    assert failure["execution_status"] == "failed" and failure["return_code"] == 1
    monkeypatch.setattr(reverse_tools, "run_objdump",
                        lambda *args, **kwargs: _process.ProcessResult(True, timed_out=True, error="timed out"))
    timeout = objdump_analysis(ctx("external-objdump", file=sample, mode="disassembly"))
    assert timeout["execution_status"] == "timed_out" and timeout["timed_out"]


def test_direct_cli_readelf_and_objdump_modes(tmp_path, monkeypatch, capsys):
    sample = tmp_path / "candidate.bin"
    sample.write_bytes(b"opaque")
    calls = []
    monkeypatch.setattr(reverse_tools, "run_readelf", lambda path, mode, **kw:
                        calls.append(("readelf", mode)) or _process.ProcessResult(True, "elf report", returncode=0))
    monkeypatch.setattr(reverse_tools, "run_objdump", lambda path, mode, **kw:
                        calls.append(("objdump", mode)) or _process.ProcessResult(True, "disassembly", returncode=0))
    assert main(["reverse", "external-elf", "--file", str(sample), "--mode", "symbols"]) == 0
    assert json.loads(capsys.readouterr().out)["mode"] == "symbols"
    assert main(["reverse", "external-objdump", "--file", str(sample), "--mode", "disassembly"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["mode"] == "disassembly" and calls == [("readelf", "symbols"), ("objdump", "disassembly")]


def test_shared_process_runner_bounds_output_and_times_out(monkeypatch, tmp_path):
    observed = {}
    class FakeProcess:
        stdout = BytesIO(b"x" * 50)
        stderr = BytesIO(b"y" * 50)
        returncode = 0
        def __init__(self, command, **kwargs):
            observed["command"], observed["kwargs"] = command, kwargs
        def wait(self, timeout=None):
            return 0
    monkeypatch.setattr(_process.shutil, "which", lambda name: "resolved/" + name)
    monkeypatch.setattr(_process.subprocess, "Popen", FakeProcess)
    result = _process.run_bounded("objdump", ["-d", str(tmp_path / "sample")], output_limit=8)
    assert result.stdout == "x" * 8 and result.stderr == "y" * 8 and result.output_truncated
    assert observed["command"][0] == "resolved/objdump" and observed["kwargs"]["shell"] is False
    class SlowProcess:
        stdout = BytesIO()
        stderr = BytesIO()
        returncode = -9
        calls = 0
        def __init__(self, *args, **kwargs): pass
        def wait(self, timeout=None):
            self.calls += 1
            if self.calls == 1:
                raise subprocess.TimeoutExpired("file", timeout)
        def kill(self): pass
    monkeypatch.setattr(_process.subprocess, "Popen", SlowProcess)
    assert _process.run_bounded("file", ["-b", "sample"], timeout=0.01).timed_out


def test_registry_cli_availability_and_interactive_execution(monkeypatch, capsys):
    registry = build_core_registry()
    names = {spec.name for spec in registry.list_tools("reverse")}
    assert {"external-status", "external-file", "external-elf", "external-objdump"} <= names
    assert registry.get_tool("reverse", "external-status").interactive_inputs == ()
    output_limit = next(item for item in registry.get_tool("reverse", "external-objdump").interactive_inputs
                        if item.name == "max_output")
    assert output_limit.default == 1_000_000 and output_limit.maximum == 2_000_000
    monkeypatch.setattr(reverse_tools.shutil, "which", lambda name: f"/mock/{name}" if name == "file" else None)
    assert main(["reverse", "external-status"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["available_count"] == 1 and status["tools"][0]["executable"] == "/mock/file"
    output = []
    # Registry-sorted list places external-status at position seven.
    choices = iter(("5", "7", "0", "0"))
    run_interactive(registry=registry, input_fn=lambda _: next(choices),
                    output=output.append)
    rendered = "\n".join(output)
    assert "external-status —" in rendered and "/mock/file" in rendered


def test_native_reverse_tools_still_registered():
    registry = build_core_registry()
    assert {"info", "strings", "entropy", "elf", "pe", "symbols", "disasm", "instructions",
            "functions", "packer"} <= {spec.name for spec in registry.list_tools("reverse")}
