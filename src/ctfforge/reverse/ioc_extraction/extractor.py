"""Bounded static network IOC extraction reusing CTFForge's string parser."""
from pathlib import Path

from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.output import make_result
from ctfforge.reverse.formats import read_binary
from ctfforge.reverse.strings import MAX_FILE_BYTES, MAX_STRINGS, extract as extract_strings

from . import patterns
from .models import IOC, Occurrence
from .validators import normalize_domain, normalize_ip, validate_email, validate_url

MAX_EXTRACTED_STRINGS = 10_000
MAX_CANDIDATES = 50_000
MAX_IOCS = 5_000
MAX_OCCURRENCES_PER_IOC = 50
MAX_TOTAL_OCCURRENCES = 20_000
MAX_CANDIDATE_LENGTH = 2_048

_TYPE_ORDER = {"url": 0, "domain": 1, "ipv4": 2, "ipv6": 3, "email": 4}


def _source(encoding: str) -> str:
    return "ascii_string" if encoding == "ASCII" else "utf16le_string"


def _byte_offset(string_offset: int, character_offset: int, encoding: str) -> int:
    return string_offset + character_offset * (2 if encoding == "UTF-16LE" else 1)


def _trim_url(value: str) -> str:
    value = value.rstrip(patterns.TRAILING_URL_PUNCTUATION)
    while value.endswith(")") and value.count("(") < value.count(")"):
        value = value[:-1]
    while value.endswith("]") and value.count("[") < value.count("]"):
        value = value[:-1]
    return value


def _add_candidate(accumulators: dict, *, ioc_type: str, normalized: str, original: str,
                   row: dict, character_offset: int, total_occurrences: list[int],
                   truncation: dict) -> None:
    if not normalized or not original:
        return
    key = (ioc_type, normalized)
    if key not in accumulators:
        if len(accumulators) >= MAX_IOCS:
            truncation["iocs"] = True
            return
        confidence = "medium" if ioc_type == "url" else "high"
        accumulators[key] = IOC(ioc_type, normalized, confidence)
    occurrence = Occurrence(_source(row["encoding"]), _byte_offset(row["offset"], character_offset,
                                                                     row["encoding"]),
                            "ascii" if row["encoding"] == "ASCII" else "utf-16le", original)
    if accumulators[key].has_occurrence(occurrence):
        return
    if total_occurrences[0] >= MAX_TOTAL_OCCURRENCES:
        truncation["occurrences"] = True
        accumulators[key].occurrences_truncated = True
        return
    if accumulators[key].add_occurrence(occurrence, maximum=MAX_OCCURRENCES_PER_IOC):
        total_occurrences[0] += 1
    else:
        truncation["occurrences"] = True


def _candidates(row: dict, accumulators: dict, total_occurrences: list[int], truncation: dict,
                candidate_count: list[int]) -> bool:
    text = row.get("string", "")
    if not isinstance(text, str):
        return True
    url_spans = []

    def count_candidate() -> bool:
        if candidate_count[0] >= MAX_CANDIDATES:
            truncation["candidates"] = True
            return False
        candidate_count[0] += 1
        return True

    for match in patterns.URL.finditer(text):
        if not count_candidate():
            return False
        raw_candidate = match.group(0)
        if len(raw_candidate) > MAX_CANDIDATE_LENGTH:
            truncation["candidates"] = True
            continue
        original = _trim_url(raw_candidate)
        validated = validate_url(original)
        if not validated:
            continue
        normalized, hostname = validated
        host_match = re_search_host(text, match.start(), original, hostname)
        if host_match:
            url_spans.append((_byte_offset(row["offset"], host_match[0], row["encoding"]),
                              _byte_offset(row["offset"], host_match[1], row["encoding"])))
        _add_candidate(accumulators, ioc_type="url", normalized=normalized, original=original,
                       row=row, character_offset=match.start(), total_occurrences=total_occurrences,
                       truncation=truncation)

    for regex, ioc_type, validator in (
        (patterns.IPV4, "ipv4", lambda value: normalize_ip(value, 4)),
        (patterns.IPV6, "ipv6", lambda value: normalize_ip(value, 6)),
        (patterns.EMAIL, "email", validate_email),
        (patterns.DOMAIN, "domain", normalize_domain),
    ):
        for match in regex.finditer(text):
            if not count_candidate():
                return False
            original = match.group(0)
            if len(original) > MAX_CANDIDATE_LENGTH:
                continue
            if ioc_type == "email":
                validated = validator(original)
                if not validated:
                    continue
                normalized, _ = validated
                _add_candidate(accumulators, ioc_type=ioc_type, normalized=normalized,
                               original=original, row=row, character_offset=match.start(),
                               total_occurrences=total_occurrences, truncation=truncation)
                original_domain = original.rsplit("@", 1)[-1]
                domain_start = match.start() + len(original) - len(original_domain)
                domain_start_byte = _byte_offset(row["offset"], domain_start, row["encoding"])
                domain_end_byte = domain_start_byte + len(original_domain) * (2 if row["encoding"] == "UTF-16LE" else 1)
                url_spans.append((domain_start_byte, domain_end_byte))
                continue
            normalized = validator(original)
            if not normalized:
                continue
            start_byte = _byte_offset(row["offset"], match.start(), row["encoding"])
            end_byte = _byte_offset(row["offset"], match.end(), row["encoding"])
            if ioc_type == "domain" and any(start_byte >= start and end_byte <= end
                                             for start, end in url_spans):
                continue
            _add_candidate(accumulators, ioc_type=ioc_type, normalized=normalized,
                           original=original, row=row, character_offset=match.start(),
                           total_occurrences=total_occurrences, truncation=truncation)
    return True


def re_search_host(text: str, url_start: int, original_url: str, hostname: str) -> tuple[int, int] | None:
    """Locate parsed hostname within its source URL without assuming URL spelling."""
    host_in_url = original_url.find(hostname)
    if host_in_url < 0:
        # IDNA host may differ from the Unicode spelling; use the parsed authority span.
        authority_start = original_url.find("//") + 2
        authority = original_url[authority_start:].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        host_port = authority.rsplit("@", 1)[-1]
        if host_port.startswith("["):
            start_in_url = authority_start + authority.find("[") + 1
            end_in_url = start_in_url + len(hostname)
        else:
            host_port = host_port.rsplit(":", 1)[0] if host_port.count(":") == 1 else host_port
            start_in_url = authority_start + authority.rfind(host_port)
            end_in_url = start_in_url + len(host_port)
    else:
        start_in_url, end_in_url = host_in_url, host_in_url + len(hostname)
    return url_start + start_in_url, url_start + end_in_url


def extract_file(path_value: str | Path, *, minimum: int = 4) -> dict:
    """Extract validated network indicators from one bounded local binary file.

    Extraction is static and offline. Confidence describes syntax extraction, not
    maliciousness or threat likelihood. At each configured cap the result reports
    truncation explicitly.
    """
    path, data = read_binary(path_value, maximum=MAX_FILE_BYTES)
    rows = extract_strings(data, minimum=minimum, encoding="both", limit=MAX_EXTRACTED_STRINGS)
    rows.sort(key=lambda row: (row.get("offset", 0), row.get("encoding", ""), row.get("string", "")))
    accumulators = {}
    total_occurrences = [0]
    candidate_count = [0]
    truncation = {"strings": len(rows) >= MAX_EXTRACTED_STRINGS,
                  "source_strings_truncated": False,
                  "candidates": False, "iocs": False, "occurrences": False}
    for row in rows:
        if row.get("truncated", False):
            truncation["source_strings_truncated"] = True
            continue
        if not _candidates(row, accumulators, total_occurrences, truncation, candidate_count):
            break
    iocs = [item.as_dict() for _, item in sorted(
        accumulators.items(), key=lambda entry: (_TYPE_ORDER[entry[0][0]], entry[0][1]))]
    result = make_result("reverse", str(path), tool="ioc-extract", file_size=len(data),
                         status="success", ioc_count=len(iocs), candidate_count=candidate_count[0],
                         source_string_count=len(rows), iocs=iocs, truncation=truncation,
                         limits={"file_bytes": MAX_FILE_BYTES, "source_strings": MAX_EXTRACTED_STRINGS,
                                 "candidates": MAX_CANDIDATES, "iocs": MAX_IOCS,
                                 "occurrences_per_ioc": MAX_OCCURRENCES_PER_IOC,
                                 "total_occurrences": MAX_TOTAL_OCCURRENCES,
                                 "candidate_characters": MAX_CANDIDATE_LENGTH},
                         note="IOC presence is not evidence of maliciousness. No network access or execution is performed.")
    return result
