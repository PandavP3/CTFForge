import pytest

from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.tool import ToolContext
from ctfforge.crypto.hashid import identify, identify_hash


@pytest.mark.parametrize(("value", "expected"), [
    ("5f4dcc3b5aa765d61d8327deb882cf99", {"MD5", "NTLM"}),
    ("a" * 40, {"SHA-1"}),
    ("b" * 64, {"SHA-256"}),
    ("c" * 96, {"SHA-384"}),
    ("d" * 128, {"SHA-512"}),
    ("$2b$12$" + "A" * 53, {"bcrypt"}),
    ("$5$saltstring$" + "A" * 43, {"SHA-256 crypt"}),
    ("$6$saltstring$" + "A" * 86, {"SHA-512 crypt"}),
])
def test_supported_hash_structures(value, expected):
    assert {row["format"] for row in identify_hash(value)} == expected
    assert all(row["identification"] == "heuristic" for row in identify_hash(value))


def test_hash_identifier_returns_multiple_candidates_for_ambiguous_format():
    assert [row["format"] for row in identify_hash("0" * 32)] == ["MD5", "NTLM"]


@pytest.mark.parametrize("value", ["", "  ", "not-a-hash", "g" * 32, "$2b$bad$payload", "$7$salt$" + "x" * 30])
def test_malformed_and_empty_hashes_have_no_matches(value):
    assert identify_hash(value) == []


def test_hashid_handler_accepts_direct_input():
    result = identify(ToolContext("crypto", "hashid", {"input": "a" * 64}))

    assert result["target"] == "<direct input>"
    assert result["candidates"][0]["format"] == "SHA-256"
    assert "heuristic" in result["candidates"][0]["identification"]


def test_hashid_handler_accepts_file(tmp_path):
    target = tmp_path / "hash.txt"
    target.write_text("a" * 40, encoding="ascii")

    result = identify(ToolContext("crypto", "hashid", {"file": target}))

    assert result["target"] == str(target)
    assert result["candidates"][0]["format"] == "SHA-1"


@pytest.mark.parametrize("arguments", [{}, {"input": "abc", "file": "hash.txt"}])
def test_hashid_handler_rejects_invalid_source(arguments):
    with pytest.raises(CTFForgeError):
        identify(ToolContext("crypto", "hashid", arguments))


def test_hashid_handler_handles_empty_input_without_a_match():
    result = identify(ToolContext("crypto", "hashid", {"input": ""}))

    assert result["candidates"] == []
    assert result["confidence"] == 0
