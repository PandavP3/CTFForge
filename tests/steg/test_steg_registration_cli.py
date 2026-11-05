import json

import pytest

import ctfforge.core.registry as registry_module
from ctfforge.core.cli import main
from ctfforge.core.registration import build_core_registry
from ctfforge.core.registry import DuplicateToolError, MissingOptionalDependencyError, ToolRegistry
from ctfforge.steg.registration import register_steg_tools


def test_steg_tools_register_and_discover():
    registry = ToolRegistry()
    register_steg_tools(registry)

    assert [spec.name for spec in registry.list_tools("steg")] == ["metadata", "structure"]
    assert registry.get_tool("steg", "metadata").optional_dependencies == ("PIL",)
    assert registry.get_tool("steg", "structure").optional_dependencies == ()


def test_steg_handlers_resolve_lazily(monkeypatch):
    registry = build_core_registry()
    actual_import = registry_module.import_module
    imported = []

    def track_import(module_name):
        imported.append(module_name)
        return actual_import(module_name)

    monkeypatch.setattr(registry_module, "import_module", track_import)
    assert [spec.name for spec in registry.list_tools("steg")] == ["metadata", "structure"]
    assert imported == []
    registry.resolve_handler("steg", "structure")
    assert imported == ["ctfforge.steg.structure"]


def test_duplicate_steg_registration_is_rejected():
    registry = ToolRegistry()
    register_steg_tools(registry)

    with pytest.raises(DuplicateToolError):
        register_steg_tools(registry)


def test_registry_reports_missing_pillow_without_breaking_other_tools(monkeypatch):
    registry = build_core_registry()
    real_import = registry_module.import_module

    def without_pillow(module_name):
        if module_name == "ctfforge.steg.metadata":
            raise ModuleNotFoundError("No module named 'PIL'", name="PIL")
        return real_import(module_name)

    monkeypatch.setattr(registry_module, "import_module", without_pillow)
    with pytest.raises(MissingOptionalDependencyError, match="requirements/steg.txt"):
        registry.resolve_handler("steg", "metadata")
    assert registry.resolve_handler("steg", "structure")
    assert registry.resolve_handler("crypto", "xor")


def test_steg_cli_structure_parses_and_returns_json(tmp_path, capsys):
    target = tmp_path / "data.bin"
    target.write_bytes(b"ordinary bytes")

    assert main(["steg", "structure", "--file", str(target)]) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["category"] == "steg"
    assert result["tool"] == "structure"
    assert result["file_size"] == len(b"ordinary bytes")


def test_steg_cli_metadata_parses_and_returns_json(tmp_path, capsys):
    Image = pytest.importorskip("PIL.Image")
    target = tmp_path / "sample.png"
    Image.new("RGB", (2, 2)).save(target)

    assert main(["steg", "metadata", "--file", str(target)]) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["image"]["format"] == "PNG"


def test_steg_cli_reports_missing_file_with_error_exit(capsys):
    assert main(["steg", "structure", "--file", "missing.ctf"] ) == 2
    assert "Cannot inspect file" in capsys.readouterr().err
