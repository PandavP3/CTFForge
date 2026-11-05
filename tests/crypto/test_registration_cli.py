import json

import pytest

import ctfforge.core.registry as registry_module
from ctfforge.core.cli import main
from ctfforge.core.registration import build_core_registry
from ctfforge.core.registry import DuplicateToolError, ToolRegistry
from ctfforge.crypto.registration import register_crypto_tools


def test_crypto_tools_register_and_discover():
    registry = ToolRegistry()
    register_crypto_tools(registry)

    assert [spec.name for spec in registry.list_tools("crypto")] == ["hashid", "xor"]
    assert registry.get_tool("crypto", "xor").usage.startswith("ctfforge crypto xor")


def test_crypto_handlers_resolve_lazily(monkeypatch):
    registry = build_core_registry()
    actual_import = registry_module.import_module
    imported = []

    def track_import(module_name):
        imported.append(module_name)
        return actual_import(module_name)

    monkeypatch.setattr(registry_module, "import_module", track_import)
    specs = registry.list_tools("crypto")
    assert imported == []
    registry.resolve_handler("crypto", specs[0].name)
    assert imported == ["ctfforge.crypto.hashid"]


def test_duplicate_crypto_registration_is_rejected():
    registry = ToolRegistry()
    register_crypto_tools(registry)

    with pytest.raises(DuplicateToolError):
        register_crypto_tools(registry)


def test_xor_cli_parses_and_executes(capsys):
    assert main(["crypto", "xor", "--input", "the answer is hidden", "--limit", "1"]) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["category"] == "crypto"
    assert result["tool"] == "xor"
    assert len(result["findings"]) == 1


def test_hashid_cli_parses_and_executes(capsys):
    assert main(["crypto", "hashid", "--input", "a" * 64]) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["candidates"][0]["format"] == "SHA-256"


def test_crypto_cli_rejects_missing_or_conflicting_arguments(capsys):
    with pytest.raises(SystemExit) as missing:
        main(["crypto", "xor"])
    assert missing.value.code == 2
    capsys.readouterr()

    assert main(["crypto", "xor", "--input", "data", "--key", "abc"]) == 2
    assert "exactly one UTF-8 byte" in capsys.readouterr().err


def test_existing_commands_still_parse_and_work(tmp_path, capsys):
    target = tmp_path / "evidence.bin"
    target.write_bytes(b"abc")

    assert main(["hash", str(target)]) == 0
    assert "sha256" in json.loads(capsys.readouterr().out)["hashes"]
    assert main(["strings", str(target)]) == 0
    capsys.readouterr()
    assert main(["doctor"]) == 0
    assert "Status:" in capsys.readouterr().out


def test_missing_crypto_optional_dependency_does_not_block_common_tools(monkeypatch):
    registry = build_core_registry()
    actual_import = registry_module.import_module

    def missing_crypto(module_name):
        if module_name == "ctfforge.crypto.hashid":
            raise ModuleNotFoundError("missing", name="unused_extra")
        return actual_import(module_name)

    monkeypatch.setattr(registry_module, "import_module", missing_crypto)
    assert registry.resolve_handler("common", "hash")
