import pytest

from ctfforge.core.exceptions import CTFForgeError
from ctfforge.reverse.ioc_extraction import extract_file
from ctfforge.reverse.ioc_extraction import extractor
from ctfforge.reverse.ioc_extraction.models import IOC, Occurrence
from ctfforge.reverse.ioc_extraction.validators import (
    normalize_domain, normalize_ip, validate_email, validate_url,
)


def _write(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _find(result, ioc_type, value=None):
    return next(item for item in result["iocs"]
                if item["type"] == ioc_type and (value is None or item["value"] == value))


def test_ascii_url_normalization_offset_and_url_hostname_deduplication(tmp_path):
    data = b"prefix https://Example.COM/path?q=1, suffix\x00"
    result = extract_file(_write(tmp_path, "ascii.bin", data))
    url = _find(result, "url", "https://example.com/path?q=1")
    assert url["original_value"] == "https://Example.COM/path?q=1"
    assert url["occurrences"][0]["source"] == "ascii_string"
    assert url["occurrences"][0]["encoding"] == "ascii"
    assert url["occurrences"][0]["offset"] == data.index(b"https://")
    assert not any(item["type"] == "domain" and item["value"] == "example.com"
                   for item in result["iocs"])


def test_utf16le_url_has_correct_byte_offset(tmp_path):
    text = "prefix https://example.org/a"
    data = ("xx " + text).encode("utf-16le") + b"\x00\x00"
    result = extract_file(_write(tmp_path, "wide.bin", data))
    url = _find(result, "url", "https://example.org/a")
    occurrence = url["occurrences"][0]
    assert occurrence["encoding"] == "utf-16le"
    assert occurrence["source"] == "utf16le_string"
    assert occurrence["offset"] == data.index("https://".encode("utf-16le"))


@pytest.mark.parametrize(("candidate", "expected"), [
    ("192.0.2.1", "192.0.2.1"), ("999.2.3.4", None), ("01.2.3.4", None),
])
def test_ipv4_uses_ipaddress_validation(candidate, expected):
    assert normalize_ip(candidate, 4) == expected


@pytest.mark.parametrize(("candidate", "expected"), [
    ("2001:0db8::1", "2001:db8::1"), ("2001:db8::zz", None),
])
def test_ipv6_uses_ipaddress_validation(candidate, expected):
    assert normalize_ip(candidate, 6) == expected


def test_domain_validation_rejects_versions_and_common_filenames():
    assert normalize_domain("Sub.Example.COM.") == "sub.example.com"
    assert normalize_domain("example.exe") is None
    assert normalize_domain("1.2.3.4") is None
    assert normalize_domain("v1.2.3") is None
    assert normalize_domain("bad..example.com") is None


def test_email_extraction_preserves_original_and_suppresses_embedded_domain(tmp_path):
    data = b"contact=Analyst+tag@Example.org; file=report.pdf\x00"
    result = extract_file(_write(tmp_path, "email.bin", data))
    email = _find(result, "email", "Analyst+tag@example.org")
    assert email["original_value"] == "Analyst+tag@Example.org"
    assert not any(item["type"] == "domain" and item["value"] == "example.org"
                   for item in result["iocs"])
    assert not any(item["type"] == "domain" and item["value"] == "report.pdf"
                   for item in result["iocs"])


def test_validators_reject_malformed_candidates():
    assert validate_url("javascript://example.com") is None
    assert validate_url("https://example.com:99999/path") is None
    assert validate_url("https://-bad.example/path") is None
    assert validate_email("bad..local@example.com") is None
    assert validate_email("user@localhost") is None


def test_repeated_iocs_keep_each_occurrence_and_offsets(tmp_path):
    first = b"https://example.com/a"
    second = b"HTTPS://EXAMPLE.COM/a"
    data = first + b"\x00" + second + b"\x00"
    result = extract_file(_write(tmp_path, "repeat.bin", data))
    url = _find(result, "url", "https://example.com/a")
    assert len(url["occurrences"]) == 2
    assert [row["offset"] for row in url["occurrences"]] == [0, len(first) + 1]
    assert {row["original_value"] for row in url["occurrences"]} == {
        "https://example.com/a", "HTTPS://EXAMPLE.COM/a",
    }


def test_separate_domain_occurrence_is_retained_alongside_url_host(tmp_path):
    data = b"https://example.com/one\x00example.com\x00"
    result = extract_file(_write(tmp_path, "separate.bin", data))
    assert len([row for row in result["iocs"] if row["type"] == "url"]) == 1
    domain = _find(result, "domain", "example.com")
    assert [row["offset"] for row in domain["occurrences"]] == [len(b"https://example.com/one\x00")]


def test_ipv4_ipv6_and_domain_candidates_from_binary_strings(tmp_path):
    data = b"ip=192.0.2.9; host=api.example.net; v6=2001:db8::5\x00"
    result = extract_file(_write(tmp_path, "addresses.bin", data))
    assert _find(result, "ipv4", "192.0.2.9")["validation"] == "valid_syntax"
    assert _find(result, "ipv6", "2001:db8::5")["validation"] == "valid_syntax"
    assert _find(result, "domain", "api.example.net")["confidence"] == "high"


def test_empty_file_and_file_size_limit(tmp_path, monkeypatch):
    empty = extract_file(_write(tmp_path, "empty.bin", b""))
    assert empty["status"] == "success" and empty["iocs"] == []
    monkeypatch.setattr(extractor, "MAX_FILE_BYTES", 2)
    with pytest.raises(CTFForgeError, match="processing limit"):
        extract_file(_write(tmp_path, "large.bin", b"123"))


def test_candidate_ioc_occurrence_and_long_value_limits_are_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(extractor, "MAX_CANDIDATES", 1)
    candidates = extract_file(_write(tmp_path, "candidates.bin", b"https://one.example https://two.example\x00"))
    assert candidates["truncation"]["candidates"] is True
    assert candidates["candidate_count"] == 1

    monkeypatch.setattr(extractor, "MAX_CANDIDATES", 50_000)
    monkeypatch.setattr(extractor, "MAX_IOCS", 1)
    iocs = extract_file(_write(tmp_path, "iocs.bin", b"https://one.example\x00https://two.example\x00"))
    assert iocs["truncation"]["iocs"] is True

    monkeypatch.setattr(extractor, "MAX_IOCS", 5_000)
    monkeypatch.setattr(extractor, "MAX_OCCURRENCES_PER_IOC", 1)
    occurrences = extract_file(_write(tmp_path, "occurrences.bin",
                                      b"https://same.example\x00https://same.example\x00"))
    assert occurrences["truncation"]["occurrences"] is True
    assert _find(occurrences, "url")["occurrences_truncated"] is True

    monkeypatch.setattr(extractor, "MAX_OCCURRENCES_PER_IOC", 50)
    long_url = b"https://example.com/" + b"a" * (extractor.MAX_CANDIDATE_LENGTH + 1) + b"\x00"
    long_result = extract_file(_write(tmp_path, "long.bin", long_url))
    assert long_result["truncation"]["candidates"] is True
    assert not any(item["type"] == "url" for item in long_result["iocs"])
    assert _find(long_result, "domain", "example.com")


def test_rejected_occurrence_does_not_change_original_value():
    ioc = IOC("url", "https://example.com/a", "medium")
    accepted = Occurrence("ascii_string", 0, "ascii", "https://example.com/a")
    rejected = Occurrence("ascii_string", 32, "ascii", "HTTPS://example.com/a")
    assert ioc.add_occurrence(accepted, maximum=1) is True
    assert ioc.add_occurrence(rejected, maximum=1) is False
    result = ioc.as_dict()
    assert result["original_value"] == accepted.original_value
    assert result["occurrences"] == [accepted.as_dict()]
    assert result["occurrences_truncated"] is True


def test_source_string_and_deterministic_order_truncation(tmp_path, monkeypatch):
    path = _write(tmp_path, "many.bin", b"https://z.example\x00https://a.example\x00")
    real_extract = extractor.extract_strings
    rows = real_extract(path.read_bytes(), minimum=4, encoding="both", limit=10)
    monkeypatch.setattr(extractor, "extract_strings", lambda *args, **kwargs: list(reversed(rows)))
    shuffled = extract_file(path)
    monkeypatch.setattr(extractor, "extract_strings", lambda *args, **kwargs: rows)
    ordered = extract_file(path)
    assert shuffled["iocs"] == ordered["iocs"]

    monkeypatch.setattr(extractor, "MAX_EXTRACTED_STRINGS", 2)
    monkeypatch.setattr(extractor, "extract_strings", lambda *args, **kwargs: rows[:2])
    truncated = extract_file(path)
    assert truncated["truncation"]["strings"] is True


def test_truncated_source_strings_do_not_emit_partial_url_or_domain(tmp_path):
    partial_url = b"A" * 4000 + b"https://example.com/" + b"x" * 200
    partial_domain = b"B" * 4086 + b"example.com" + b"x" * 200
    path = _write(tmp_path, "cut-strings.bin", partial_url + b"\x00" + partial_domain + b"\x00")
    result = extract_file(path)
    assert result["truncation"]["source_strings_truncated"] is True
    assert not any(ioc["type"] == "url" for ioc in result["iocs"])
    assert not any(ioc["type"] == "domain" and ioc["value"] in {"example.com", "example.co"}
                   for ioc in result["iocs"])

