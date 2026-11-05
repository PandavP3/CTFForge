import hashlib
import json

import pytest

import ctfforge.core.registry as registry_module
from ctfforge.core.cli import main
from ctfforge.core.file_detection import identify_file
from ctfforge.core.hashing import hash_file
from ctfforge.core.registration import build_core_registry, register_core_tools
from ctfforge.core.registry import DuplicateToolError, MissingOptionalDependencyError
from ctfforge.core.strings import extract_strings
from ctfforge.core.tool import ToolContext, ToolSpec


def test_core_tools_register_and_are_discoverable():
    registry = build_core_registry()

    assert registry.list_categories() == ("common",)
    assert [spec.name for spec in registry.list_tools("common")] == ["hash", "identify", "strings"]
    assert registry.get_tool("common", "hash").usage == "ctfforge hash FILE"


def test_adapters_resolve_lazily(monkeypatch):
    registry = build_core_registry()
    actual_import = registry_module.import_module
    imported = []

    def track_import(module_name):
        imported.append(module_name)
        return actual_import(module_name)

    monkeypatch.setattr(registry_module, "import_module", track_import)
    registry.list_categories()
    registry.list_tools("common")
    registry.get_tool("common", "hash")

    assert imported == []
    registry.resolve_handler("common", "hash")
    assert imported == ["ctfforge.core.tool_adapters"]


def test_hash_adapter_reuses_existing_implementation(tmp_path):
    target = tmp_path / "evidence.bin"
    target.write_bytes(b"reusable hash implementation")
    registry = build_core_registry()
    handler = registry.resolve_handler("common", "hash")

    result = handler(ToolContext("common", "hash", {"file": target}))

    assert result["hashes"] == hash_file(target)
    assert result["hashes"]["sha256"] == hashlib.sha256(target.read_bytes()).hexdigest()
    assert result["target"] == str(target)


def test_strings_adapter_reuses_existing_implementation(tmp_path):
    target = tmp_path / "strings.dat"
    target.write_bytes(b"\x00visible text\x00not")
    registry = build_core_registry()
    handler = registry.resolve_handler("common", "strings")

    result = handler(ToolContext("common", "strings", {"file": target}))

    assert result["strings"] == extract_strings(target)
    assert result["strings"] == ["visible text"]


def test_identify_adapter_reuses_existing_implementation(tmp_path):
    target = tmp_path / "image.png"
    target.write_bytes(b"\x89PNG\r\n\x1a\nchallenge")
    registry = build_core_registry()
    handler = registry.resolve_handler("common", "identify")

    result = handler(ToolContext("common", "identify", {"file": target}))

    assert result["file_type"] == identify_file(target) == "PNG image"


def test_missing_optional_tool_dependency_does_not_break_common_tools(monkeypatch, tmp_path):
    registry = build_core_registry()
    registry.register_tool(
        ToolSpec(
            category="crypto",
            name="optional",
            description="Test-only missing optional dependency.",
            handler_ref="ctfforge.crypto.optional:run",
            optional_dependencies=("optional_crypto_package",),
        )
    )
    real_import = registry_module.import_module

    def import_with_missing_optional(module_name):
        if module_name == "ctfforge.crypto.optional":
            raise ModuleNotFoundError(
                "No module named 'optional_crypto_package'", name="optional_crypto_package"
            )
        return real_import(module_name)

    monkeypatch.setattr(registry_module, "import_module", import_with_missing_optional)
    target = tmp_path / "small.bin"
    target.write_bytes(b"abc")

    with pytest.raises(MissingOptionalDependencyError, match="requirements/crypto.txt"):
        registry.resolve_handler("crypto", "optional")
    assert registry.resolve_handler("common", "hash")(
        ToolContext("common", "hash", {"file": target})
    )["hashes"] == hash_file(target)


def test_duplicate_core_registration_is_rejected():
    registry = build_core_registry()

    with pytest.raises(DuplicateToolError, match="already registered"):
        register_core_tools(registry)


def test_existing_cli_hash_output_is_preserved(tmp_path, capsys):
    target = tmp_path / "hash.txt"
    target.write_bytes(b"abc")

    assert main(["hash", str(target)]) == 0

    assert json.loads(capsys.readouterr().out) == {
        "target": str(target),
        "hashes": hash_file(target),
    }


def test_existing_cli_strings_output_is_preserved(tmp_path, capsys):
    target = tmp_path / "strings.txt"
    target.write_bytes(b"\x00visible text\x00")

    assert main(["strings", str(target)]) == 0

    assert capsys.readouterr().out == "\n".join(extract_strings(target)) + "\n"
