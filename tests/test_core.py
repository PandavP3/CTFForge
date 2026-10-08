import hashlib
import json

import pytest

from ctfforge.core.cli import main
from ctfforge.core.config import load_config
from ctfforge.core.exceptions import ConfigurationError
from ctfforge.core.file_detection import identify_file
from ctfforge.core.hashing import hash_file, shannon_entropy
from ctfforge.core.output import make_result, render_report
from ctfforge.core.strings import extract_strings


def test_hash_file_and_entropy(tmp_path):
    target = tmp_path / "evidence.bin"
    target.write_bytes(b"abc")
    assert hash_file(target)["sha256"] == hashlib.sha256(b"abc").hexdigest()
    assert shannon_entropy(b"") == 0
    assert shannon_entropy(b"aaaa") == 0


def test_signature_identification(tmp_path):
    target = tmp_path / "image.png"
    target.write_bytes(b"\x89PNG\r\n\x1a\nrest")
    assert identify_file(target) == "PNG image"


def test_strings(tmp_path):
    target = tmp_path / "strings.dat"
    target.write_bytes(b"\x00hello world\x00abc")
    assert extract_strings(target, minimum=4) == ["hello world"]


def test_detect_common_and_custom_flag(tmp_path, capsys):
    target = tmp_path / "challenge.txt"
    target.write_text("CTF{demo_flag}", encoding="utf-8")
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"flag_patterns": [r"CUSTOM\{[^}]+\}"]}), encoding="utf-8")
    assert main(["detect", str(target), "--config", str(config)]) == 0
    assert "No potential flags" in capsys.readouterr().out
    target.write_text("CUSTOM{demo_flag}", encoding="utf-8")
    assert main(["detect", str(target), "--config", str(config)]) == 0
    assert "CUSTOM{demo_flag}" in capsys.readouterr().out


def test_detect_directory(tmp_path, capsys):
    (tmp_path / "a.txt").write_text("flag{one}", encoding="utf-8")
    (tmp_path / "b.txt").write_text("HTB{two}", encoding="utf-8")
    assert main(["detect", str(tmp_path)]) == 0
    output = capsys.readouterr().out
    assert "flag{one}" in output and "HTB{two}" in output


def test_reports_include_common_fields():
    result = make_result("foundation", "sample", findings=["demo"])
    assert json.loads(render_report(result, "json"))["target"] == "sample"
    assert "demo" in render_report(result, "markdown")
    assert "<pre>" in render_report(result, "html")
    assert "category,target" in render_report(result, "csv")


def test_invalid_config_root(tmp_path):
    config = tmp_path / "bad.json"
    config.write_text("[]", encoding="utf-8")
    with pytest.raises(ConfigurationError):
        load_config(config)
