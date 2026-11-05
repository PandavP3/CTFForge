import pytest

from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.tool import ToolContext
from ctfforge.crypto.xor import analyze, rank_single_byte_keys, xor_bytes


def context(**arguments):
    return ToolContext("crypto", "xor", arguments)


def test_single_byte_xor_recovers_plaintext_and_key():
    plaintext = b"the quick brown fox jumps over the lazy dog"
    ciphertext = xor_bytes(plaintext, b"\x42")

    result = analyze(context(hex=ciphertext.hex(), limit=5))

    assert result["findings"][0]["key"] == 0x42
    assert result["findings"][0]["plaintext"] == plaintext.decode()


def test_candidate_ranking_prefers_english_text():
    plaintext = b"the answer is hidden in the old library"
    candidates = rank_single_byte_keys(xor_bytes(plaintext, b"\x17"), limit=4)

    assert candidates[0]["key"] == 0x17
    assert candidates[0]["plaintext"] == plaintext.decode()
    assert all(candidates[index]["score"] >= candidates[index + 1]["score"]
               for index in range(len(candidates) - 1))


def test_known_single_byte_key_decrypts_text_input():
    plaintext = "CTF{known_key}"
    ciphertext = xor_bytes(plaintext.encode(), b"K")

    result = analyze(context(hex=ciphertext.hex(), key="K"))

    assert result["mode"] == "known-single-byte"
    assert result["findings"][0]["plaintext"] == plaintext


def test_repeating_key_decrypts_text_and_hex_input():
    plaintext = b"repeating key challenge"
    ciphertext = xor_bytes(plaintext, b"ICE")

    result = analyze(context(input="hello", repeat_key="\x00"))
    hex_result = analyze(context(hex=ciphertext.hex(), repeat_key="ICE"))

    assert result["findings"][0]["plaintext"] == "hello"
    assert hex_result["findings"][0]["plaintext"] == plaintext.decode()


def test_file_input_and_limit(tmp_path):
    plaintext = b"file input XOR"
    target = tmp_path / "challenge.bin"
    target.write_bytes(xor_bytes(plaintext, b"\x22"))

    result = analyze(context(file=target, key='"'))

    assert result["target"] == str(target)
    assert result["findings"][0]["plaintext"] == plaintext.decode()


@pytest.mark.parametrize("arguments", [
    {"input": "data", "repeat_key": ""},
    {"input": "data", "key": "long"},
    {"hex": "abc"},
    {"hex": "zz"},
    {"input": "data", "limit": 0},
    {"input": "data", "key": "a", "repeat_key": "b"},
])
def test_invalid_or_empty_input_is_rejected(arguments):
    with pytest.raises(CTFForgeError):
        analyze(context(**arguments))


def test_empty_ciphertext_can_be_ranked():
    assert rank_single_byte_keys(b"", limit=1)[0]["plaintext"] == ""
    assert analyze(context(input="", repeat_key="key"))["findings"][0]["plaintext"] == ""
