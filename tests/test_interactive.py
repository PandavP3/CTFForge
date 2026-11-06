import json
import pytest

from ctfforge.core.cli import build_parser, main
from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.interactive import ASCII_BANNER, BANNER, run_interactive
from ctfforge.core.registry import ToolRegistry
from ctfforge.core.tool import InteractiveInput as I, ToolContext, ToolSpec
from ctfforge.core.registration import build_core_registry


def run_with(values, registry=None):
    prompts = iter(values)
    output = []
    result = run_interactive(registry=registry, input_fn=lambda prompt: next(prompts), output=output.append)
    return result, "\n".join(output)


def test_interactive_command_is_registered_and_banner_menu_shows_availability():
    parsed = build_parser().parse_args(["interactive"])
    assert parsed.command == "interactive"
    status, output = run_with(["0"])
    assert status == 0 and BANNER in output
    assert "[1] Cryptography" in output
    assert "[2] Web Exploitation" in output
    assert "[4] Digital Forensics" in output
    assert "[5] Reverse Engineering" in output
    assert "[5] Reverse Engineering  (Coming Soon)" not in output
    assert "[15] Miscellaneous" in output
    assert "[15] Miscellaneous  (Coming Soon)" not in output


def test_interactive_cli_dispatches_to_launcher(monkeypatch):
    import ctfforge.core.interactive as interactive
    monkeypatch.setattr(interactive, "run_interactive", lambda: 7)
    assert main(["interactive"]) == 7


def test_unicode_banner_falls_back_to_ascii(monkeypatch):
    class ASCIIStream:
        encoding = "ascii"
        def isatty(self): return False
    monkeypatch.setattr("ctfforge.core.interactive.sys.stdout", ASCIIStream())
    status, output = run_with(["0"])
    assert status == 0 and ASCII_BANNER in output and BANNER not in output


def test_invalid_empty_and_coming_soon_category_inputs():
    _, output = run_with(["", "bad", "16", "6", "0"])
    assert "Enter a menu number." in output
    assert "Invalid category selection." in output
    assert "That category is coming soon." in output


def test_empty_and_invalid_tool_selection():
    _, output = run_with(["1", "", "bad", "0"], build_core_registry())
    assert "Invalid tool selection." in output


def test_dynamic_tool_listing_uses_registry_specs():
    registry = build_core_registry()
    registry.register_tool(ToolSpec("future_tool", "crypto", "A dynamically added demonstration tool.", "demo:run"))
    _, output = run_with(["1", "b", "0"], registry)
    assert "future_tool — A dynamically added demonstration tool." in output


def test_common_tools_are_available_under_miscellaneous():
    _, output = run_with(["15", "b", "0"], build_core_registry())
    assert "Miscellaneous Tools" in output
    assert "hash — Calculate MD5, SHA1, and SHA256 hashes for a file." in output


def make_registry(handler, input_definitions=(I("value", "Value"),), optional_dependencies=()):
    registry = ToolRegistry()
    registry.register_tool(ToolSpec("demo", "crypto", "Test tool description", "demo:run",
                                    optional_dependencies=optional_dependencies,
                                    usage="ctfforge crypto demo --value VALUE",
                                    help="Test input help.", interactive_inputs=input_definitions))
    registry.resolve_handler = lambda category, tool: handler
    return registry


def test_category_tool_selection_and_handler_invocation():
    received = []
    def handler(context):
        received.append(context)
        return {"answer": context.arguments["value"]}
    registry = make_registry(handler)
    _, output = run_with(["1", "1", "sample value", "2", "0"], registry)
    assert received[0] == ToolContext("crypto", "demo", {"value": "sample value"})
    assert '"answer": "sample value"' in output
    assert "Usage: ctfforge crypto demo --value VALUE" in output
    assert "[2] Tools in this category" in output


def test_invalid_value_reprompt_and_input_group_validation():
    spec_inputs = (I("file", "File path", "path", required=False, group="source", group_rule="exactly_one"),
                   I("value", "Text input", required=False, group="source", group_rule="exactly_one"))
    registry = make_registry(lambda context: {"keys": list(context.arguments)}, spec_inputs)
    _, output = run_with(["1", "1", "", "", "", "sample", "2", "0"], registry)
    assert "Choose exactly one input for: source" in output
    assert '"value"' in output


def test_numeric_bounds_reprompt_before_handler():
    inputs = (I("concurrency", "Workers", "int", minimum=1, maximum=5),)
    called = []
    registry = make_registry(lambda context: called.append(context) or {}, inputs)
    _, output = run_with(["1", "1", "8", "3", "2", "0"], registry)
    assert len(called) == 1 and called[0].arguments["concurrency"] == 3
    assert "Value must be at most 5." in output


def test_home_back_and_navigation_from_input():
    called = []
    registry = make_registry(lambda context: called.append(context) or {})
    _, output = run_with(["1", "1", ":home", "1", "b", "0"], registry)
    assert not called
    assert output.count("CTFForge Categories") == 3
    assert "Test tool description" in output


def test_run_again_then_exit():
    count = []
    registry = make_registry(lambda context: count.append(1) or {"run": len(count)})
    _, output = run_with(["1", "1", "a", "1", "b", "0"], registry)
    assert len(count) == 2
    assert '"run": 2' in output


def test_tool_error_is_displayed_and_back_works():
    def handler(context):
        raise CTFForgeError("bad input for test")
    registry = make_registry(handler)
    _, output = run_with(["1", "1", "value", "2", "0"], registry)
    assert "Tool error: bad input for test" in output


def test_missing_optional_dependency_has_install_guidance():
    registry = make_registry(lambda context: {}, optional_dependencies=("missing_package",))
    registry.resolve_handler = lambda category, tool: (_ for _ in ()).throw(
        __import__("ctfforge.core.registry", fromlist=["MissingOptionalDependencyError"]).MissingOptionalDependencyError(
            "Install the dependencies listed in requirements/crypto.txt."))
    _, output = run_with(["1", "1", "value", "2", "0"], registry)
    assert "requirements/crypto.txt" in output


@pytest.mark.parametrize("interrupt", [KeyboardInterrupt, EOFError])
def test_ctrl_c_and_eof_exit_cleanly(interrupt):
    def input_fn(prompt):
        raise interrupt
    output = []
    assert run_interactive(registry=ToolRegistry(), input_fn=input_fn, output=output.append) == 0
    assert "Input closed. Goodbye." in "\n".join(output)


def test_actual_registered_handler_is_used_for_web_url():
    status, output = run_with(["2", "6", "https://example.test/a?x=1", "0"], build_core_registry())
    assert status == 0
    assert '"network_requests": 0' in output


def test_actual_registered_common_handler_runs_from_interactive(tmp_path):
    file = tmp_path / "small.bin"
    file.write_bytes(b"abc")
    _, output = run_with(["15", "1", str(file), "2", "0"], build_core_registry())
    assert '"sha256"' in output


def test_direct_cli_commands_remain_registered(capsys, tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")
    assert main(["hash", str(sample)]) == 0
    assert "sha256" in json.loads(capsys.readouterr().out)["hashes"]
