import base64
import json

import pytest

from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.flag_format import compile_flag_pattern, find_flags
from ctfforge.core.recommendations import cyberchef_operation, recommend
from ctfforge.core.solver import continue_session, solve
from ctfforge.core.solver_input import from_text
from ctfforge.core.cli import main


def test_flag_format_requires_actual_match():
    pattern = compile_flag_pattern(r"CTF\{[^}]+\}", None)
    assert find_flags("probably a flag", pattern) == []
    assert find_flags("CTF{validated}", pattern) == ["CTF{validated}"]


def test_flag_prefix_and_conflict_validation():
    pattern = compile_flag_pattern(None, "THM{")
    assert find_flags("THM{sample}", pattern) == ["THM{sample}"]
    with pytest.raises(CTFForgeError):
        compile_flag_pattern(r"CTF\{.*\}", "HTB{")


def test_solve_decodes_base64_and_persists_session(tmp_path):
    encoded = base64.b64encode(b"CTF{offline_success}").decode()
    state, result = solve(from_text(encoded), "crypto", r"CTF\{[^}]+\}", sessions_root=tmp_path)
    assert state["status"] == "SOLVED"
    assert result["possible_flags"] == ["CTF{offline_success}"]
    assert state["operations"][0]["operation"] == "From Base64"
    session = json.loads((tmp_path / state["session_id"] / "session.json").read_text())
    assert session["flag_format"] == r"CTF\{[^}]+\}"
    assert (tmp_path / state["session_id"] / "reports" / "report.json").exists()


def test_invalid_lookalike_is_not_reported_as_flag(tmp_path):
    state, result = solve(from_text("This is probably the flag"), "misc", r"CTF\{.*\}", sessions_root=tmp_path)
    assert state["status"] == "UNSOLVED"
    assert result["possible_flags"] == []


def test_continue_session_can_validate_returned_result(tmp_path):
    state, _ = solve(from_text("encrypted clue"), "crypto", r"flag\{[^}]+\}", sessions_root=tmp_path)
    resumed, result = continue_session(state["session_id"], "external result: flag{resumed}", sessions_root=tmp_path)
    assert resumed["status"] == "SOLVED"
    assert result["possible_flags"] == ["flag{resumed}"]
    assert resumed["user_results"][0]["length"] > 0


def test_recommendations_are_problem_specific():
    assert cyberchef_operation("base64") == "From Base64"
    assert recommend("encoding")["tool"] == "CyberChef"
    assert recommend("unknown") is None


def test_solve_cli_text_input_creates_session(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    status = main(["solve", "--category", "misc", "--flag-format", r"CTF\{[^}]+\}",
                   "--input", "CTF{cli_ok}"])
    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["status"] == "SOLVED"
    assert output["possible_flags"] == ["CTF{cli_ok}"]
    assert (tmp_path / "sessions" / output["session_id"] / "session.json").exists()


def test_solver_cli_rejects_mismatched_flag_options(capsys):
    status = main(["solve", "--category", "crypto", "--flag-format", r"CTF\{.*\}",
                   "--flag-prefix", "HTB{", "--input", "value"])
    assert status == 2
    assert "do not describe a compatible flag" in capsys.readouterr().err
