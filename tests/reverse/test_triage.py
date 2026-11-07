import hashlib
import json
import struct

import pytest

from ctfforge.core.cli import build_parser, main
from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.registration import build_core_registry
from ctfforge.reverse import triage
from ctfforge.reverse.packer_detection import analyze as analyze_packer
from test_reverse import make_elf, make_pe


def sample(tmp_path, name="sample.bin", data=b"plain sample payload\x00"):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_quick_profile_metadata_hash_and_component_statuses(tmp_path):
    path = sample(tmp_path, data=b"powershell -NoProfile\x00" + b"A" * 256)
    from ctfforge.core.tool import ToolContext
    result = triage.analyze(ToolContext("reverse", "triage", {"file": path, "profile": "quick"}))
    assert result["target"]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert result["target"]["format"] == "Unknown"
    assert result["components"]["identity"]["status"] == "success"
    assert result["components"]["structure"] == {"status": "skipped", "reason": "quick_profile"}
    assert result["components"]["yara"]["reason"] == "no_rules_supplied"
    assert any(row["category"] == "strings" for row in result["evidence"])
    assert result["assessment"]["level"] in {"low", "medium"}


def test_standard_profile_reuses_elf_structure_and_symbols(tmp_path):
    from ctfforge.core.tool import ToolContext
    path = sample(tmp_path, "program.elf", make_elf(64))
    result = triage.analyze(ToolContext("reverse", "triage", {"file": path, "profile": "standard"}))
    assert result["target"]["format"] == "ELF"
    assert result["target"]["bitness"] == 64
    assert result["components"]["structure"]["status"] == "success"
    assert result["components"]["symbols"]["status"] == "success"
    assert result["components"]["functions"]["source"] == "symbols"


def test_target_validation(tmp_path):
    from ctfforge.core.tool import ToolContext
    with pytest.raises(CTFForgeError, match="required"):
        triage.analyze(ToolContext("reverse", "triage", {"file": None}))
    with pytest.raises(CTFForgeError, match="regular file"):
        triage.analyze(ToolContext("reverse", "triage", {"file": tmp_path}))


def test_unreadable_file_is_reported(tmp_path, monkeypatch):
    from pathlib import Path
    from ctfforge.core.tool import ToolContext
    path = sample(tmp_path)
    original_open = Path.open
    def denied(candidate, *args, **kwargs):
        if candidate == path:
            raise PermissionError("denied for test")
        return original_open(candidate, *args, **kwargs)
    monkeypatch.setattr(Path, "open", denied)
    with pytest.raises(CTFForgeError, match="Cannot read target"):
        triage.analyze(ToolContext("reverse", "triage", {"file": path}))


def test_size_limit_and_target_change_detection(tmp_path, monkeypatch):
    from ctfforge.core.tool import ToolContext
    path = sample(tmp_path)
    monkeypatch.setattr(triage, "MAX_TRIAGE_FILE_BYTES", 2)
    with pytest.raises(CTFForgeError, match="triage limit"):
        triage.analyze(ToolContext("reverse", "triage", {"file": path}))
    monkeypatch.setattr(triage, "MAX_TRIAGE_FILE_BYTES", 64 * 1024 * 1024)
    original = triage._snapshot
    calls = 0
    def changed(target):
        nonlocal calls
        calls += 1
        state = original(target)
        if calls == 2:
            target.write_bytes(target.read_bytes() + b"changed")
        return state if calls == 1 else original(target)
    monkeypatch.setattr(triage, "_snapshot", changed)
    with pytest.raises(CTFForgeError, match="changed during triage"):
        triage.analyze(ToolContext("reverse", "triage", {"file": path, "profile": "quick"}))


def _ev(identifier, category, *, kind="heuristic", section=None, details=None, offset=None):
    row = {"id": identifier, "category": category, "source": "test", "observation": identifier,
           "significance": "low", "confidence": "low", "kind": kind,
           "supporting_details": details or {}}
    if section:
        row["section"] = section
    if offset is not None:
        row["file_offset"] = offset
    return row


def test_explicit_correlations_and_deduplicated_evidence_references():
    evidence = [
        _ev("E1", "file_identity", details={"format": "PE"}),
        _ev("E2", "file_identity", details={"expected_format": "ELF"}),
        _ev("E3", "packer", section="UPX0", details={"indicator_kind": "known_signature"}),
        _ev("E4", "packer", section="UPX0", details={"indicator_kind": "section_name"}),
        _ev("E5", "entropy", section=".text"),
        _ev("E6", "packer", section=".text", details={"indicator_kind": "writable_executable_section"}),
        _ev("E7", "yara", details={"rule": "r"}),
        _ev("E8", "strings", details={"indicator": "powershell"}),
        _ev("E9", "imports", details={"name": "VirtualAlloc"}),
    ]
    correlations = triage.correlate(evidence + [evidence[-1]])
    rules = {item["rule"]: item for item in correlations}
    assert set(rules) == {"entropy_and_wx_section", "packer_signature_and_section",
                          "yara_with_string_indicator", "import_with_string_indicator",
                          "extension_mismatch_executable"}
    assert all(len(item["evidence_ids"]) == len(set(item["evidence_ids"])) for item in correlations)
    assert all(set(item["evidence_ids"]) <= {row["id"] for row in evidence} for item in correlations)


def test_writable_executable_packer_evidence_uses_validated_section_and_offset(tmp_path):
    from ctfforge.core.tool import ToolContext
    raw = bytearray(make_pe(64))
    section_header = 0x80 + 24 + 240
    struct.pack_into("<I", raw, section_header + 36, 0xE0000020)
    raw[0x240:0x440] = bytes(range(256)) * 2
    target = tmp_path / "sample.exe"
    target.write_bytes(raw)
    packer_result = analyze_packer(ToolContext("reverse", "packer", {"file": target}))
    assert any(row["kind"] == "writable_executable_section"
               and row["evidence"] == "Section '.text' is writable and executable."
               for row in packer_result["indicators"])
    components = {"packer": {"status": "success"}}
    evidence, _ = triage._collect_evidence(components, {"packer": packer_result})
    wx = next(row for row in evidence if row["supporting_details"].get("indicator_kind")
              == "writable_executable_section")
    assert wx["section"] == ".text"
    assert wx["file_offset"] == 0x240
    correlations = triage.correlate(evidence)
    assert any(row["rule"] == "entropy_and_wx_section"
               and set(row["evidence_ids"]) == {wx["id"], next(
                   item["id"] for item in evidence if item["category"] == "entropy" and item.get("section") == ".text")}
               for row in correlations)


def test_risk_assessment_weak_entropy_signature_and_missing_analysis():
    entropy_only = [_ev("E1", "entropy")]
    assert triage.assess(entropy_only, [], {}, set())["level"] == "low"
    yara = [_ev("E1", "yara", kind="factual")]
    assert triage.assess(yara, [], {}, set())["level"] == "low"
    many = [_ev(f"E{i}", "yara", kind="factual") for i in range(1, 5)]
    assert triage.assess(many, [], {}, set())["score"] == 2
    assert triage.assess([], [], {"identity": {"status": "failed"}}, {"identity"})["level"] == "inconclusive"


def test_overlapping_correlation_scores_do_not_reuse_evidence():
    yara = _ev("E1", "yara", kind="factual")
    string = _ev("E2", "strings")
    imported = _ev("E3", "imports")
    correlations = [
        {"rule": "import_with_string_indicator", "title": "Import + string",
         "evidence_ids": ["E3", "E2"]},
        {"rule": "yara_with_string_indicator", "title": "YARA + string",
         "evidence_ids": ["E1", "E2"]},
    ]
    result = triage.assess([yara, string, imported], correlations, {}, set())
    assert result["score"] == 3  # YARA/string correlation (2), then unconsumed import (1).
    assert [item["factor"] for item in result["drivers"]] == ["YARA + string", "Sensitive import reference"]
    used_ids = [identifier for driver in result["drivers"] for identifier in driver["evidence_ids"]]
    assert len(used_ids) == len(set(used_ids))
    assert set(used_ids) == {"E1", "E2", "E3"}


def test_correlation_scoring_is_deterministic_for_evidence_and_rule_order():
    rows = [_ev("E1", "yara", kind="factual"), _ev("E2", "strings"), _ev("E3", "imports")]
    correlations = [
        {"rule": "import_with_string_indicator", "title": "Import + string", "evidence_ids": ["E3", "E2"]},
        {"rule": "yara_with_string_indicator", "title": "YARA + string", "evidence_ids": ["E1", "E2"]},
    ]
    first = triage.assess(rows, correlations, {}, set())
    reordered = triage.assess(list(reversed(rows)), list(reversed(correlations)), {}, set())
    assert first["score"] == reordered["score"] == 3
    assert first["drivers"] == reordered["drivers"]


def test_multiple_imports_and_strings_have_one_weight_per_factor():
    rows = [
        _ev("E4", "strings"), _ev("E3", "imports"), _ev("E2", "strings"),
        _ev("E1", "imports"),
    ]
    first = triage.assess(rows, [], {}, set())
    reordered = triage.assess(list(reversed(rows)), [], {}, set())
    assert first["score"] == reordered["score"] == 2
    assert first["drivers"] == reordered["drivers"]
    assert first["drivers"] == [
        {"factor": "Sensitive import reference", "points": 1, "evidence_ids": ["E1", "E3"]},
        {"factor": "Suspicious string indicator", "points": 1, "evidence_ids": ["E2", "E4"]},
    ]


def test_duplicate_evidence_ids_are_scored_once_deterministically():
    rows = [
        _ev("E1", "strings"), _ev("E3", "imports"), _ev("E1", "imports"),
        _ev("E2", "strings"), _ev("E3", "imports"),
    ]
    first = triage.assess(rows, [], {}, set())
    reordered = triage.assess(list(reversed(rows)), [], {}, set())
    assert first["score"] == reordered["score"] == 2
    assert first["drivers"] == reordered["drivers"]
    used_ids = [item for driver in first["drivers"] for item in driver["evidence_ids"]]
    assert len(used_ids) == len(set(used_ids)) == 3


@pytest.mark.parametrize(("result_status", "expected"), [
    ("success", "success"), ("timed_out", "timed_out"), ("failed", "failed"),
    ("unavailable", "unavailable"), ("skipped", "skipped"),
    ("unexpected", "failed"), ([], "failed"),
])
def test_component_status_is_preserved_or_failed_closed(monkeypatch, result_status, expected):
    monkeypatch.setattr(triage, "_run", lambda *args: {"status": result_status})
    components = {}
    triage._component(None, components, "test", "tool", {})
    assert components["test"]["status"] == expected
    if expected in {"failed", "unavailable", "timed_out"}:
        assessment = triage.assess([], [], components, {"test"})
        assert assessment["incomplete"] is True


def test_report_export_exclusive_and_target_collision(tmp_path):
    from ctfforge.core.tool import ToolContext
    target = sample(tmp_path, data=b"unknown test bytes")
    output = tmp_path / "report.json"
    result = triage.analyze(ToolContext("reverse", "triage", {"file": target, "profile": "quick", "output": output}))
    assert result["export"]["status"] == "success"
    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved["report_schema_version"] == "1.0"
    assert saved["target"]["sha256"] == result["target"]["sha256"]
    again = triage.analyze(ToolContext("reverse", "triage", {"file": target, "profile": "quick", "output": output}))
    assert again["export"]["status"] == "failed"
    assert "Refusing to overwrite" in again["export"]["error"]
    collision = triage.analyze(ToolContext("reverse", "triage", {"file": target, "profile": "quick", "output": target}))
    assert collision["report_status"] == "export_failed"


def test_yara_status_and_truncation_propagated_via_registered_handler(tmp_path, monkeypatch):
    from ctfforge.core.tool import ToolContext
    path = sample(tmp_path)
    rules = tmp_path / "rules.yar"
    rules.write_text("rule sample { condition: true }", encoding="utf-8")
    original = triage._run
    def fake_run(registry, name, arguments):
        if name == "yara":
            return {"status": "success", "matches": [{"rule": "sample", "namespace": "default",
                    "tags": [], "metadata": {}, "strings": [], "string_instance_count": 0}],
                    "match_count": 1, "reported_match_count": 1, "matches_truncated": True,
                    "string_instances_truncated": False, "results_complete": False}
        return original(registry, name, arguments)
    monkeypatch.setattr(triage, "_run", fake_run)
    result = triage.analyze(ToolContext("reverse", "triage", {"file": path, "profile": "quick", "rules": rules}))
    assert result["components"]["yara"]["status"] == "success"
    assert result["components"]["yara"]["matches_truncated"] is True
    assert result["truncation"]["yara_matches"] is True
    assert result["components"]["yara"]["results_complete"] is False
    monkeypatch.setattr(triage, "_run", lambda registry, name, arguments:
                        (_ for _ in ()).throw(CTFForgeError("Optional dependency yara is unavailable"))
                        if name == "yara" else original(registry, name, arguments))
    unavailable = triage.analyze(ToolContext("reverse", "triage", {"file": path, "profile": "quick", "rules": rules}))
    assert unavailable["components"]["yara"]["status"] == "unavailable"
    skipped = triage.analyze(ToolContext("reverse", "triage", {"file": path, "profile": "quick", "rules": rules, "skip_yara": True}))
    assert skipped["components"]["yara"]["reason"] == "explicitly_skipped"


def test_analyzer_failure_is_preserved_and_no_match_yara_is_success(tmp_path, monkeypatch):
    from ctfforge.core.tool import ToolContext
    path = sample(tmp_path)
    rules = tmp_path / "empty.yar"
    rules.write_text("rule no_match { condition: false }", encoding="utf-8")
    original = triage._run
    def fake_run(registry, name, arguments):
        if name == "entropy":
            raise OSError("synthetic entropy failure")
        if name == "yara":
            return {"status": "success", "matches": [], "match_count": 0,
                    "reported_match_count": 0, "matches_truncated": False,
                    "string_instances_truncated": False, "results_complete": True}
        return original(registry, name, arguments)
    monkeypatch.setattr(triage, "_run", fake_run)
    result = triage.analyze(ToolContext("reverse", "triage", {"file": path, "profile": "quick", "rules": rules}))
    assert result["components"]["entropy"]["status"] == "failed"
    assert result["components"]["entropy"]["error"] == "synthetic entropy failure"
    assert result["components"]["yara"]["status"] == "success"
    assert result["components"]["yara"]["match_count"] == 0
    assert result["assessment"]["incomplete"] is True


def test_registry_cli_and_interactive_metadata(tmp_path, monkeypatch, capsys):
    registry = build_core_registry()
    spec = registry.get_tool("reverse", "triage")
    assert spec.handler_ref == "ctfforge.reverse.triage:analyze"
    assert [item.name for item in spec.interactive_inputs] == ["file", "profile", "rules", "skip_yara", "timeout", "output"]
    parsed = build_parser().parse_args(["reverse", "triage", "--file", str(sample(tmp_path)), "--profile", "quick"])
    assert parsed.reverse_tool == "triage" and parsed.profile == "quick"
    target = sample(tmp_path, "cli.bin", b"short opaque content")
    assert main(["reverse", "triage", "--file", str(target), "--profile", "quick"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["profile"] == "quick"
