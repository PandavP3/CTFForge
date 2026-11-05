from types import SimpleNamespace

import pytest

import ctfforge.core.registry as registry_module
from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.registry import (
    DuplicateToolError,
    HandlerResolutionError,
    MissingOptionalDependencyError,
    ToolRegistry,
    UnknownCategoryError,
    UnknownToolError,
)
from ctfforge.core.tool import ToolSpec


def make_spec(category="crypto", name="xor", **overrides):
    values = {
        "category": category,
        "name": name,
        "description": f"{name} test tool",
        "handler_ref": f"ctfforge.{category}.{name}:run",
    }
    values.update(overrides)
    return ToolSpec(**values)


def test_register_and_find_tool():
    registry = ToolRegistry()
    spec = make_spec(usage="ctfforge crypto xor --file INPUT")

    registry.register_tool(spec)

    assert registry.get_tool("crypto", "xor") is spec
    assert registry.list_tools("crypto") == (spec,)


def test_duplicate_registration_is_rejected():
    registry = ToolRegistry()
    spec = make_spec()
    registry.register_tool(spec)

    with pytest.raises(DuplicateToolError, match="already registered"):
        registry.register_tool(spec)


def test_category_batch_registration_is_atomic_on_duplicates():
    registry = ToolRegistry()
    with pytest.raises(DuplicateToolError, match="Duplicate tool name"):
        registry.register_category("crypto", [make_spec(), make_spec(name="xor")])

    assert registry.list_categories() == ()


def test_register_category_and_list_categories_and_tools():
    registry = ToolRegistry()
    registry.register_category("crypto", [make_spec(name="xor"), make_spec(name="hashid")])
    registry.register_category("steg", [make_spec(category="steg", name="metadata")])

    assert registry.list_categories() == ("crypto", "steg")
    assert [spec.name for spec in registry.list_tools("crypto")] == ["hashid", "xor"]
    assert [spec.name for spec in registry.list_tools("steg")] == ["metadata"]


def test_unknown_category_has_useful_message():
    registry = ToolRegistry()
    registry.register_tool(make_spec())

    with pytest.raises(UnknownCategoryError, match="Available categories: crypto"):
        registry.list_tools("web")


def test_unknown_tool_has_useful_message():
    registry = ToolRegistry()
    registry.register_tool(make_spec(name="xor"))

    with pytest.raises(UnknownToolError, match="Available tools: xor"):
        registry.get_tool("crypto", "rsa")


def test_handler_is_imported_only_when_resolved(monkeypatch):
    registry = ToolRegistry()
    spec = make_spec()
    calls = []
    def expected_handler(context):
        return {"category": context.category}


    def fake_import(module_name):
        calls.append(module_name)
        return SimpleNamespace(run=expected_handler)

    monkeypatch.setattr(registry_module, "import_module", fake_import)
    registry.register_tool(spec)
    registry.list_categories()
    registry.list_tools("crypto")

    assert calls == []
    handler = registry.resolve_handler("crypto", "xor")
    assert handler is expected_handler
    assert calls == ["ctfforge.crypto.xor"]
    assert registry.resolve_handler("crypto", "xor") is expected_handler
    assert calls == ["ctfforge.crypto.xor"]


def test_missing_handler_module_has_useful_error(monkeypatch):
    registry = ToolRegistry()
    registry.register_tool(make_spec(handler_ref="missing_tools.crypto:run"))

    def missing_module(module_name):
        raise ModuleNotFoundError("No module named 'missing_tools'", name="missing_tools")

    monkeypatch.setattr(registry_module, "import_module", missing_module)
    with pytest.raises(
        HandlerResolutionError,
        match="Handler module 'missing_tools.crypto'.*not found",
    ):
        registry.resolve_handler("crypto", "xor")


def test_missing_declared_dependency_has_category_install_hint(monkeypatch):
    registry = ToolRegistry()
    registry.register_tool(
        make_spec(optional_dependencies=("Crypto",), handler_ref="ctfforge.crypto.xor:run")
    )

    def missing_dependency(module_name):
        raise ModuleNotFoundError("No module named 'Crypto'", name="Crypto")

    monkeypatch.setattr(registry_module, "import_module", missing_dependency)
    with pytest.raises(MissingOptionalDependencyError, match="requirements/crypto.txt"):
        registry.resolve_handler("crypto", "xor")


def test_missing_optional_dependency_does_not_affect_unrelated_category(monkeypatch):
    registry = ToolRegistry()
    registry.register_tool(make_spec(optional_dependencies=("Crypto",)))
    registry.register_tool(make_spec(category="misc", name="qr"))

    def missing_crypto(module_name):
        if module_name == "ctfforge.crypto.xor":
            raise ModuleNotFoundError("No module named 'Crypto'", name="Crypto")
        return SimpleNamespace(run=lambda context: {"category": context.category})

    monkeypatch.setattr(registry_module, "import_module", missing_crypto)

    assert [spec.name for spec in registry.list_tools("misc")] == ["qr"]
    with pytest.raises(MissingOptionalDependencyError):
        registry.resolve_handler("crypto", "xor")
    assert registry.resolve_handler("misc", "qr") is not None


def test_invalid_handler_reference_is_rejected():
    with pytest.raises(CTFForgeError, match="Invalid handler reference"):
        make_spec(handler_ref="not-a-handler-reference")
