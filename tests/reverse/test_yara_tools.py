import json
import types
from pathlib import Path

import pytest

from ctfforge.core.cli import main
from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.interactive import run_interactive
from ctfforge.core.registration import build_core_registry
from ctfforge.core.tool import ToolContext
from ctfforge.reverse import yara_tools


def ctx(name, **arguments):
    return ToolContext("reverse", name, arguments)


class FakeRules:
    def __init__(self, matches=(), error=None):
        self.matches, self.error, self.calls = matches, error, []
    def match(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return self.matches


class FakeYara:
    __version__ = "4.5-test"
    class TimeoutError(Exception):
        pass
    def __init__(self, matches=(), compile_error=None, scan_error=None):
        self.rules = FakeRules(matches, scan_error)
        self.compile_error = compile_error
        self.compiles = []
    def compile(self, *, source, includes):
        self.compiles.append((source, includes))
        if self.compile_error:
            raise self.compile_error
        return self.rules


def legacy_match(rule="sample_rule", namespace="test", tags=(), meta=None, strings=()):
    return types.SimpleNamespace(rule=rule, namespace=namespace, tags=list(tags), meta=meta or {},
                                 strings=list(strings))


def setup_fake(monkeypatch, fake):
    monkeypatch.setattr(yara_tools, "_load_yara", lambda: fake)


def test_yara_availability_version_missing_and_import_error(monkeypatch):
    fake = FakeYara()
    monkeypatch.setattr(yara_tools.importlib, "import_module", lambda name: fake)
    result = yara_tools.availability(ctx("yara-status"))
    assert result["installed"] and result["version"] == "4.5-test"
    monkeypatch.setattr(yara_tools.importlib, "import_module",
                        lambda name: (_ for _ in ()).throw(ModuleNotFoundError("missing", name="yara")))
    result = yara_tools.availability(ctx("yara-status"))
    assert not result["installed"] and "requirements/reverse.txt" in result["installation"]
    monkeypatch.setattr(yara_tools.importlib, "import_module",
                        lambda name: (_ for _ in ()).throw(ImportError("broken extension")))
    assert "broken extension" in yara_tools.availability(ctx("yara-status"))["error"]


def test_rule_validation_success_invalid_syntax_and_no_scan(tmp_path, monkeypatch):
    rules_file = tmp_path / "demo.yar"
    rules_file.write_text('rule sample { condition: true }', encoding="utf-8")
    fake = FakeYara()
    setup_fake(monkeypatch, fake)
    result = yara_tools.validate(ctx("yara-validate", rules=rules_file))
    assert result["valid"] and result["rule_file_size"] == rules_file.stat().st_size
    assert fake.compiles == [('rule sample { condition: true }', False)]
    assert "scanned" in result["note"] and fake.rules.calls == []
    fake.compile_error = ValueError("unexpected token")
    result = yara_tools.validate(ctx("yara-validate", rules=rules_file))
    assert not result["valid"] and result["status"] == "invalid"
    assert "unexpected token" in result["error"]


def test_rule_file_validation_missing_directory_size_and_unreadable(tmp_path, monkeypatch):
    directory = tmp_path / "rules-dir"
    directory.mkdir()
    with pytest.raises(CTFForgeError, match="regular file"):
        yara_tools.validate(ctx("yara-validate", rules=directory))
    with pytest.raises(CTFForgeError, match="regular file"):
        yara_tools.validate(ctx("yara-validate", rules=tmp_path / "missing.yar"))
    large = tmp_path / "large.yar"
    with large.open("wb") as stream:
        stream.truncate(yara_tools.MAX_RULE_FILE_BYTES + 1)
    with pytest.raises(CTFForgeError, match="rules exceed"):
        yara_tools.validate(ctx("yara-validate", rules=large))
    rules_file = tmp_path / "unreadable.yar"
    rules_file.write_text("rule r { condition: true }")
    original_open = Path.open
    def denied(path, *args, **kwargs):
        if path == rules_file:
            raise PermissionError("permission denied")
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", denied)
    with pytest.raises(CTFForgeError, match="Cannot read YARA rules"):
        yara_tools.validate(ctx("yara-validate", rules=rules_file))


def test_scan_extracts_old_and_new_string_apis_without_binary_data(tmp_path, monkeypatch):
    target, rules_path = tmp_path / "sample.bin", tmp_path / "rules.yar"
    target.write_bytes(b"SYNTHETIC_TARGET_CONTENT")
    rules_path.write_text("rule r { condition: true }")
    modern_string = types.SimpleNamespace(identifier="$modern", instances=[
        types.SimpleNamespace(offset=4, matched_data=b"SECRET"),
        types.SimpleNamespace(offset=10, matched_data=b"SECRET"),
    ])
    matches = [legacy_match("legacy", "ns", ["tag"], {"family": "demo", "rank": 2},
                            [(1, "$old", b"HIDDEN")]),
               legacy_match("modern", strings=[modern_string])]
    fake = FakeYara(matches)
    setup_fake(monkeypatch, fake)
    result = yara_tools.scan(ctx("yara", file=target, rules=rules_path, timeout=7))
    assert result["status"] == "complete" and result["match_count"] == 2
    assert result["matches"][0]["namespace"] == "ns"
    assert result["matches"][0]["tags"] == ["tag"]
    assert result["matches"][0]["metadata"] == {"family": "demo", "rank": 2}
    assert result["matches"][0]["strings"] == [{"identifier": "$old", "offsets": [1]}]
    assert result["matches"][1]["strings"] == [{"identifier": "$modern", "offsets": [4, 10]}]
    assert result["string_instance_count"] == 3
    assert fake.rules.calls == [{"filepath": str(target), "timeout": 7}]
    assert "HIDDEN" not in json.dumps(result) and "SECRET" not in json.dumps(result)
    assert target.read_bytes() == b"SYNTHETIC_TARGET_CONTENT"


def test_scan_no_matches_timeout_and_limits(tmp_path, monkeypatch):
    target, rules_path = tmp_path / "target", tmp_path / "rules.yar"
    target.write_bytes(b"target")
    rules_path.write_text("rule r { condition: true }")
    fake = FakeYara()
    setup_fake(monkeypatch, fake)
    result = yara_tools.scan(ctx("yara", file=target, rules=rules_path))
    assert result["status"] == "complete" and result["match_count"] == 0 and result["matches"] == []
    assert result["results_complete"] is True
    fake.rules.error = fake.TimeoutError("timed out")
    result = yara_tools.scan(ctx("yara", file=target, rules=rules_path, timeout=2))
    assert result["status"] == "timed_out" and result["timeout_seconds"] == 2
    fake.rules.error = None
    many_matches = [legacy_match(f"r{index}") for index in range(yara_tools.MAX_MATCHES + 1)]
    rows, _, _ = yara_tools._match_records(many_matches)
    assert len(rows) == yara_tools.MAX_MATCHES
    instances = [(index, "$a", b"data") for index in range(yara_tools.MAX_STRING_INSTANCES + 1)]
    rows, count, truncated = yara_tools._match_records([legacy_match(strings=instances)])
    assert count == yara_tools.MAX_STRING_INSTANCES and truncated
    assert len(rows[0]["strings"][0]["offsets"]) == yara_tools.MAX_STRING_INSTANCES
    fake.rules.matches = many_matches
    fake.rules.error = None
    result = yara_tools.scan(ctx("yara", file=target, rules=rules_path))
    assert result["match_count"] == yara_tools.MAX_MATCHES + 1
    assert result["reported_match_count"] == yara_tools.MAX_MATCHES and result["matches_truncated"]
    assert result["results_complete"] is False
    fake.rules.matches = [legacy_match(strings=instances)]
    result = yara_tools.scan(ctx("yara", file=target, rules=rules_path))
    assert result["string_instances_truncated"] is True
    assert result["results_complete"] is False


@pytest.mark.parametrize("timeout", [0, -1, 61, True, 1.5])
def test_invalid_timeout_rejected(tmp_path, monkeypatch, timeout):
    target, rules_path = tmp_path / "target", tmp_path / "rules.yar"
    target.write_bytes(b"target")
    rules_path.write_text("rule r { condition: true }")
    setup_fake(monkeypatch, FakeYara())
    with pytest.raises(CTFForgeError, match="timeout must be an integer"):
        yara_tools.scan(ctx("yara", file=target, rules=rules_path, timeout=timeout))


def test_scan_missing_inputs_and_target_size_limit(tmp_path, monkeypatch):
    rules_path = tmp_path / "rules.yar"
    rules_path.write_text("rule r { condition: true }")
    setup_fake(monkeypatch, FakeYara())
    with pytest.raises(CTFForgeError, match="regular file"):
        yara_tools.scan(ctx("yara", file=tmp_path / "missing", rules=rules_path))
    target = tmp_path / "large.bin"
    with target.open("wb") as stream:
        stream.truncate(yara_tools.MAX_TARGET_FILE_BYTES + 1)
    with pytest.raises(CTFForgeError, match="scan limit"):
        yara_tools.scan(ctx("yara", file=target, rules=rules_path))


def test_missing_yara_dependency_and_export_safety(tmp_path, monkeypatch):
    target, rules_path = tmp_path / "target.bin", tmp_path / "rules.yar"
    target.write_bytes(b"target")
    rules_path.write_text("rule r { condition: true }")
    monkeypatch.setattr(yara_tools, "_load_yara",
                        lambda: (_ for _ in ()).throw(CTFForgeError("Install yara-python")))
    with pytest.raises(CTFForgeError, match="yara-python"):
        yara_tools.scan(ctx("yara", file=target, rules=rules_path))
    fake = FakeYara([legacy_match("match", strings=[(0, "$x", b"data")])])
    setup_fake(monkeypatch, fake)
    output = tmp_path / "result.json"
    result = yara_tools.scan(ctx("yara", file=target, rules=rules_path, output=output))
    assert json.loads(output.read_text())["matches"][0]["rule"] == "match"
    assert result["output_file"] == str(output)
    with pytest.raises(CTFForgeError, match="overwrite"):
        yara_tools.scan(ctx("yara", file=target, rules=rules_path, output=output))
    with pytest.raises(CTFForgeError, match="must not overwrite"):
        yara_tools.scan(ctx("yara", file=target, rules=rules_path, output=target))
    with pytest.raises(CTFForgeError, match="directory does not exist"):
        yara_tools.scan(ctx("yara", file=target, rules=rules_path, output=tmp_path / "missing" / "x.json"))


def test_registry_cli_and_interactive_integration(tmp_path, monkeypatch, capsys):
    registry = build_core_registry()
    expected = {"yara-status", "yara-validate", "yara"}
    specs = {spec.name: spec for spec in registry.list_tools("reverse")}
    assert expected <= specs.keys()
    assert specs["yara"].optional_dependencies == ("yara",)
    assert [item.name for item in specs["yara"].interactive_inputs] == ["file", "rules", "timeout", "output"]
    rules_path, target = tmp_path / "rule.yar", tmp_path / "target.bin"
    rules_path.write_text("rule r { condition: true }")
    target.write_bytes(b"target")
    fake = FakeYara([legacy_match("r")])
    setup_fake(monkeypatch, fake)
    assert main(["reverse", "yara-validate", "--rules", str(rules_path)]) == 0
    assert json.loads(capsys.readouterr().out)["valid"]
    assert main(["reverse", "yara", "--file", str(target), "--rules", str(rules_path), "--timeout", "3"]) == 0
    assert json.loads(capsys.readouterr().out)["timeout_seconds"] == 3
    assert main(["reverse", "yara", "--file", str(target), "--rules", str(rules_path), "--timeout", "0"]) == 2
    capsys.readouterr()
    available_fake = FakeYara()
    monkeypatch.setattr(yara_tools.importlib, "import_module", lambda name: available_fake)
    status = main(["reverse", "yara-status"])
    assert status == 0 and json.loads(capsys.readouterr().out)["version"] == "4.5-test"
    tool_names = [spec.name for spec in registry.list_tools("reverse")]
    menu_idx = tool_names.index("yara-status") + 1
    answers = iter(("5", str(menu_idx), "0"))
    output = []
    run_interactive(registry=registry, input_fn=lambda _: next(answers), output=output.append)
    assert "yara-status —" in "\n".join(output) and "4.5-test" in "\n".join(output)
    validate_index = tool_names.index("yara-validate") + 1
    answers = iter(("5", str(validate_index), str(rules_path), "0"))
    output = []
    run_interactive(registry=registry, input_fn=lambda _: next(answers), output=output.append)
    assert '"valid": true' in "\n".join(output)


def test_real_yara_integration_when_optional_package_is_installed(tmp_path):
    yara = pytest.importorskip("yara")
    target, rules_file = tmp_path / "sample.bin", tmp_path / "sample.yar"
    target.write_bytes(b"CTFFORGE_SYNTHETIC")
    rules_file.write_text('rule synthetic { strings: $a = "CTFFORGE" condition: $a }')
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(yara_tools, "_load_yara", lambda: yara)
    try:
        assert yara_tools.validate(ctx("yara-validate", rules=rules_file))["valid"]
        result = yara_tools.scan(ctx("yara", file=target, rules=rules_file))
        assert result["match_count"] == 1 and result["matches"][0]["rule"] == "synthetic"
    finally:
        monkeypatch.undo()
