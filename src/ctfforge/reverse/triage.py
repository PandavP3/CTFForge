"""Explainable, bounded orchestration of existing native binary analyzers."""
import hashlib
import json
import os
import stat
import ast
from datetime import datetime, timezone
from pathlib import Path

from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.registration import build_core_registry
from ctfforge.core.tool import ToolContext, ToolResult

MAX_TRIAGE_FILE_BYTES = 64 * 1024 * 1024
MAX_RELEVANT_STRINGS = 100
MAX_REPORTED_SECTIONS = 256
MAX_EVIDENCE_ITEMS = 1000
MAX_REPORT_BYTES = 8 * 1024 * 1024
STRING_INDICATORS = (
    ("powershell", "script interpreter reference"),
    ("cmd.exe", "command interpreter reference"),
    ("/bin/sh", "shell reference"),
    ("bash -c", "shell invocation reference"),
    ("virtualalloc", "memory allocation API reference"),
    ("writeprocessmemory", "process memory API reference"),
    ("createremotethread", "remote thread API reference"),
    ("invoke-expression", "dynamic script evaluation reference"),
    ("frombase64string", "encoded-data decoding reference"),
    ("currentversion\\run", "Windows autorun registry path reference"),
    ("http://", "cleartext URL reference"),
    ("https://", "URL reference"),
)
CORRELATION_SCORE_PRIORITY = (
    "yara_with_string_indicator",
    "import_with_string_indicator",
    "entropy_and_wx_section",
    "packer_signature_and_section",
)
SUSPICIOUS_IMPORTS = {
    "virtualalloc", "virtualprotect", "writeprocessmemory", "createremotethread",
    "winexec", "shellexecutea", "shellexecutew", "urldownloadtofilea", "urldownloadtofilew",
    "internetopen", "internetopena", "internetopenw", "cryptunprotectdata",
}
PACKER_SECTION_MARKERS = ("upx0", "upx1", ".aspack", ".adata", ".themida", ".vmp0", ".vmp1", ".petite")


def _snapshot(path: Path) -> tuple[int, str, tuple[int, ...]]:
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as stream:
            file_stat = os.fstat(stream.fileno())
            if not stat.S_ISREG(file_stat.st_mode):
                raise CTFForgeError(f"Target is not a regular file: {path}")
            if file_stat.st_size > MAX_TRIAGE_FILE_BYTES:
                raise CTFForgeError(
                    f"Target exceeds the {MAX_TRIAGE_FILE_BYTES}-byte triage limit."
                )
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                total += len(chunk)
                if total > MAX_TRIAGE_FILE_BYTES:
                    raise CTFForgeError(
                        f"Target exceeds the {MAX_TRIAGE_FILE_BYTES}-byte triage limit."
                    )
                digest.update(chunk)
    except CTFForgeError:
        raise
    except OSError as exc:
        raise CTFForgeError(f"Cannot read target file {path}: {exc}") from exc
    signature = (file_stat.st_dev, file_stat.st_ino, total,
                 file_stat.st_mtime_ns, file_stat.st_ctime_ns)
    return total, digest.hexdigest(), signature


def _run(registry, name: str, arguments: dict) -> ToolResult:
    handler = registry.resolve_handler("reverse", name)
    return handler(ToolContext("reverse", name, arguments))


def _component(registry, components: dict, name: str, tool: str, arguments: dict) -> dict | None:
    try:
        result = _run(registry, tool, arguments)
    except Exception as exc:
        message = str(exc)[:500]
        status = "unavailable" if tool == "yara" and "optional" in message.casefold() else "failed"
        components[name] = {"status": status, "tool": tool, "error": message}
        return None
    status = result.get("status", "success")
    if not isinstance(status, str) or status not in {
            "success", "timed_out", "failed", "unavailable", "skipped", "invalid", "error"}:
        components[name] = {"status": "failed", "tool": tool,
                            "error": f"Unexpected analyzer status: {status!r}"}
    else:
        component_status = "failed" if status in ("invalid", "error") else status
        components[name] = {"status": component_status, "tool": tool}
        if component_status == "skipped" and result.get("reason"):
            components[name]["reason"] = result["reason"]
        if component_status in ("failed", "unavailable", "timed_out") and result.get("error"):
            components[name]["error"] = str(result["error"])[:500]
    return result


def _skip(components: dict, name: str, reason: str) -> None:
    components[name] = {"status": "skipped", "reason": reason}


def _evidence_builder():
    items = []
    truncated = [False]

    def add(category: str, source: str, observation: str, *, significance: str,
            confidence: str, kind: str, file_offset=None, section=None, details=None):
        if len(items) >= MAX_EVIDENCE_ITEMS:
            truncated[0] = True
            return None
        row = {"id": f"E{len(items) + 1:04d}", "category": category, "source": source,
               "observation": observation, "significance": significance,
               "confidence": confidence, "kind": kind,
               "supporting_details": details or {}}
        if isinstance(file_offset, int) and not isinstance(file_offset, bool):
            row["file_offset"] = file_offset
        if section:
            row["section"] = str(section)
        items.append(row)
        return row

    return items, add, truncated


def _collect_evidence(components: dict, results: dict):
    evidence, add, evidence_truncated = _evidence_builder()
    identity = results.get("identity")
    fmt = identity.get("format") if identity else "Unknown"
    if identity:
        metadata = identity.get("metadata", {})
        add("file_identity", "info", f"Signature/structure analysis identified the file as {fmt}.",
            significance="informational", confidence="high", kind="factual",
            details={"format": fmt, "metadata": metadata})
        if identity.get("extension_mismatch"):
            add("file_identity", "info", "Filename extension does not match the detected format.",
                significance="low", confidence="high", kind="factual",
                details={"extension": identity.get("extension"),
                         "expected_format": identity.get("expected_format"), "detected_format": fmt})

    strings_result = results.get("strings")
    relevant_count = 0
    if strings_result:
        indicators = []
        for row in strings_result.get("strings", ()):
            text = row.get("string", "")
            folded = text.casefold()
            for marker, label in STRING_INDICATORS:
                if marker in folded:
                    indicators.append((row, marker, label))
                    if len(indicators) >= MAX_RELEVANT_STRINGS:
                        break
            if len(indicators) >= MAX_RELEVANT_STRINGS:
                break
        for row, marker, label in indicators:
            relevant_count += 1
            excerpt = row.get("string", "")[:120]
            add("strings", "strings", f"Extracted string contains a {label} ({marker!r}).",
                significance="low", confidence="low", kind="heuristic",
                file_offset=row.get("offset"),
                details={"encoding": row.get("encoding"), "indicator": marker, "excerpt": excerpt})
        components["strings"].update({"string_count": strings_result.get("string_count", 0),
                                      "relevant_indicator_count": relevant_count,
                                      "output_limit": strings_result.get("output_limit"),
                                      "truncated": strings_result.get("string_count", 0) >=
                                                   strings_result.get("output_limit", MAX_RELEVANT_STRINGS)})

    entropy_result = results.get("entropy")
    if entropy_result:
        high_blocks = [block for block in entropy_result.get("blocks", ())
                       if block.get("high_entropy_indicator")]
        components["entropy"].update({"overall_entropy": entropy_result.get("overall_entropy"),
                                      "block_size": entropy_result.get("block_size"),
                                      "block_count": len(entropy_result.get("blocks", ())),
                                      "blocks": [{"offset": row.get("offset"), "size": row.get("size"),
                                                 "entropy": row.get("entropy"),
                                                 "high_entropy_indicator": row.get("high_entropy_indicator")}
                                                for row in entropy_result.get("blocks", ())[:256]],
                                      "blocks_truncated": len(entropy_result.get("blocks", ())) > 256,
                                      "high_entropy_block_count": len(high_blocks)})
        if high_blocks:
            add("entropy", "entropy",
                f"{len(high_blocks)} block(s) met the existing high-entropy heuristic threshold.",
                significance="low", confidence="low", kind="heuristic",
                file_offset=high_blocks[0].get("offset"),
                details={"entropy_threshold": 7.2,
                         "block_offsets": [block.get("offset") for block in high_blocks[:100]],
                         "block_offsets_truncated": len(high_blocks) > 100,
                         "overall_entropy": entropy_result.get("overall_entropy")})

    packer_result = results.get("packer")
    if packer_result:
        components["packer"].update({"format": packer_result.get("format"),
                                     "summary": packer_result.get("summary"),
                                     "indicator_count": len(packer_result.get("indicators", ())),
                                     "section_count": len(packer_result.get("sections", ()))})
        for indicator in packer_result.get("indicators", ()):
            kind = indicator.get("kind")
            details = indicator.get("evidence", {})
            if kind == "known_signature":
                signature = details.get("signature", "known marker")
                row = add("packer", "packer", f"Known packer-related marker {signature!r} was present.",
                          significance="medium", confidence="high", kind="factual",
                          file_offset=details.get("offset"),
                          details={"indicator_kind": kind, **details})
            elif kind in ("entry_point_layout", "writable_executable_section", "section_name"):
                section_name = None
                if kind == "section_name":
                    section_name = next((section.get("name") for section in packer_result.get("sections", ())
                                         if section.get("name") and section["name"] in str(details)), None)
                elif kind == "writable_executable_section" and isinstance(details, str):
                    prefix = "Section "
                    suffix = " is writable and executable."
                    if details.startswith(prefix) and details.endswith(suffix):
                        try:
                            candidate = ast.literal_eval(details[len(prefix):-len(suffix)])
                        except (SyntaxError, ValueError):
                            candidate = None
                        if isinstance(candidate, str) and any(
                                section.get("name") == candidate
                                for section in packer_result.get("sections", ())):
                            section_name = candidate
                file_offset = None
                if section_name:
                    file_offset = next((section.get("offset") for section in packer_result.get("sections", ())
                                        if section.get("name") == section_name), None)
                row = add("packer", "packer", str(details), significance="low" if kind == "section_name" else "medium",
                          confidence="low", kind="heuristic", file_offset=file_offset, section=section_name,
                          details={"indicator_kind": kind, "evidence": details})
            else:
                continue
            if row is None:
                continue

        for section in packer_result.get("sections", ()):
            if section.get("entropy") is not None and section["entropy"] >= 7.2:
                row = add("entropy", "packer",
                          f"Section {section.get('name')!r} sample has high entropy ({section['entropy']} bits/byte).",
                          significance="low", confidence="low", kind="heuristic",
                          file_offset=section.get("offset"), section=section.get("name"),
                          details={"entropy": section.get("entropy"),
                                   "sampled_bytes": section.get("sampled_bytes")})

    symbol_result = results.get("symbols")
    if symbol_result:
        if fmt == "ELF":
            entries = symbol_result.get("entries", ())
            funcs = [symbol for symbol in entries if symbol.get("type") == 2 and symbol.get("name")]
            components["symbols"].update({"format": "ELF", "symbol_count": len(entries),
                                           "function_count": len(funcs),
                                           "function_names": [item["name"] for item in funcs[:200]],
                                           "functions_truncated": len(funcs) > 200,
                                           "warnings": symbol_result.get("warnings", [])})
            components["functions"] = {"status": "success", "source": "symbols",
                                        "function_count": len(funcs), "derived_without_reparsing": True}
        elif fmt == "PE":
            imports = []
            for library in symbol_result.get("imports", ()):
                for symbol in library.get("symbols", ()):
                    name = symbol.get("name")
                    if name:
                        imports.append({"library": library.get("library"), "name": name,
                                        "file_offset": symbol.get("file_offset")})
            exports = symbol_result.get("exports", ())
            components["symbols"].update({"format": "PE", "import_count": len(imports),
                                           "imports": imports[:200],
                                           "imports_truncated": len(imports) > 200,
                                           "export_count": len(exports),
                                           "exports": [{"name": item.get("name"),
                                                        "ordinal": item.get("ordinal"),
                                                        "address_rva": item.get("address_rva")}
                                                       for item in exports[:200]],
                                           "exports_truncated": len(exports) > 200,
                                           "warnings": symbol_result.get("warnings", [])})
            components["functions"] = {"status": "success", "source": "symbols",
                                        "function_count": len(exports), "derived_without_reparsing": True}
            suspicious = [item for item in imports if item["name"].casefold() in SUSPICIOUS_IMPORTS]
            for item in suspicious[:50]:
                add("imports", "symbols",
                    f"PE import {item['name']} from {item.get('library') or 'unknown library'} may enable sensitive behavior.",
                    significance="low", confidence="low", kind="heuristic",
                    file_offset=item.get("file_offset"),
                    details={"name": item["name"], "library": item.get("library")})
            components["symbols"]["suspicious_import_count"] = len(suspicious)

    yara_result = results.get("yara")
    if yara_result:
        components["yara"].update({"match_count": yara_result.get("match_count"),
                                   "reported_match_count": yara_result.get("reported_match_count"),
                                   "matches_truncated": yara_result.get("matches_truncated", False),
                                   "string_instances_truncated": yara_result.get("string_instances_truncated", False),
                                   "results_complete": yara_result.get("results_complete", False),
                                   "timeout_seconds": yara_result.get("timeout_seconds"),
                                   "duration_seconds": yara_result.get("duration_seconds"),
                                   "matches": yara_result.get("matches", [])})
        for match in yara_result.get("matches", ())[:MAX_RELEVANT_STRINGS]:
            add("yara", "yara", f"YARA rule {match.get('rule')} matched the target.",
                significance="medium", confidence="high", kind="factual",
                details={"rule": match.get("rule"), "namespace": match.get("namespace"),
                         "tags": match.get("tags", []), "metadata": match.get("metadata", {}),
                         "strings": match.get("strings", []),
                         "string_instance_count": match.get("string_instance_count", 0)})
        components["yara"]["evidence_truncated"] = len(yara_result.get("matches", ())) > MAX_RELEVANT_STRINGS

    # Collection summaries for formats and sections are kept bounded in the report.
    structure_result = results.get("structure")
    if structure_result:
        sections = structure_result.get("sections", ())
        section_rows = []
        for section in sections[:MAX_REPORTED_SECTIONS]:
            if fmt == "ELF":
                section_rows.append({key: section.get(key) for key in
                                     ("name", "address", "offset", "size", "flags")})
            else:
                section_rows.append({key: section.get(key) for key in
                                     ("name", "virtual_address", "raw_offset", "virtual_size",
                                      "raw_size", "permissions")})
        if fmt == "ELF":
            components["structure"].update({"format": "ELF", "class_bits": structure_result.get("class_bits"),
                                             "endianness": structure_result.get("endianness"),
                                             "machine": structure_result.get("machine"),
                                             "type": structure_result.get("type"),
                                             "entry_point": structure_result.get("entry_point"),
                                             "program_header_count": len(structure_result.get("program_headers", ()))})
        else:
            components["structure"].update({"format": "PE", "class_bits": structure_result.get("class_bits"),
                                             "endianness": structure_result.get("endianness"),
                                             "machine": structure_result.get("machine"),
                                             "entry_point_rva": structure_result.get("entry_point_rva"),
                                             "image_base": structure_result.get("image_base"),
                                             "subsystem": structure_result.get("subsystem")})
        components["structure"].update({"sections": section_rows,
                                         "sections_truncated": len(sections) > MAX_REPORTED_SECTIONS})
        add("structure", "elf" if fmt == "ELF" else "pe",
            f"Native structural analysis parsed {len(sections)} section(s) from {fmt}.",
            significance="informational", confidence="high", kind="factual",
            details={"format": fmt, "section_count": len(sections)})

    return evidence, evidence_truncated[0]


def correlate(evidence: list[dict]) -> list[dict]:
    """Apply named, deterministic correlation rules; each rule emits at most one finding."""
    findings = []
    used = set()

    def add(rule: str, title: str, explanation: str, rows: list[dict], *, kind="heuristic"):
        ids = sorted({row["id"] for row in rows})
        if len(ids) < 2 or tuple(ids) in used:
            return
        used.add(tuple(ids))
        findings.append({"id": f"C{len(findings) + 1:03d}", "rule": rule, "title": title,
                         "kind": kind, "evidence_ids": ids, "explanation": explanation})

    by_kind = {}
    for item in evidence:
        by_kind.setdefault(item.get("supporting_details", {}).get("indicator_kind"), []).append(item)
    for rows in by_kind.values():
        rows.sort(key=lambda row: row.get("id", ""))
    for wx in by_kind.get("writable_executable_section", ()):
        same_section_entropy = [row for row in evidence
                                if row["category"] == "entropy" and row.get("section")
                                and row.get("section") == wx.get("section")]
        if same_section_entropy:
            same_section_entropy.sort(key=lambda row: row.get("id", ""))
            add("entropy_and_wx_section", "High entropy and writable-executable section",
                "The same section has a high-entropy sample and both write and execute permissions; this may reflect packing or another layout choice.",
                [wx, same_section_entropy[0]])

    signatures = by_kind.get("known_signature", ())
    named_sections = by_kind.get("section_name", ())
    if signatures and named_sections:
        add("packer_signature_and_section", "Packer marker with packer-like section name",
            "A known packer-related byte marker and a packer-like section name occur in the same file; this is supporting evidence, not proof of packing.",
            [signatures[0], named_sections[0]])

    yara = sorted((item for item in evidence if item["category"] == "yara"), key=lambda row: row.get("id", ""))
    strings = sorted((item for item in evidence if item["category"] == "strings"), key=lambda row: row.get("id", ""))
    if yara and strings:
        add("yara_with_string_indicator", "YARA match with related string indicators",
            "A supplied YARA rule matched and the extracted strings also contain a listed behavior indicator; validate the rule and context.",
            [yara[0], strings[0]])

    imports = sorted((item for item in evidence if item["category"] == "imports"), key=lambda row: row.get("id", ""))
    if imports and strings:
        add("import_with_string_indicator", "Sensitive import with string indicator",
            "A sensitive API import and a listed string indicator coexist; either observation can be benign in context.",
            [imports[0], strings[0]])

    mismatches = sorted((item for item in evidence if item["category"] == "file_identity"
                         and item["supporting_details"].get("expected_format")), key=lambda row: row.get("id", ""))
    identity = sorted((item for item in evidence if item["category"] == "file_identity"
                       and item["supporting_details"].get("format") in ("PE", "ELF")), key=lambda row: row.get("id", ""))
    if mismatches and identity:
        add("extension_mismatch_executable", "Extension mismatch with executable format",
            "The detected PE/ELF structure differs from the filename extension hint.",
            [mismatches[0], identity[0]], kind="factual")
    return findings


def assess(evidence: list[dict], correlations: list[dict], components: dict,
           required_components: set[str]) -> dict:
    """Assign an ordinal triage level; weights are not malware probabilities."""
    # Evidence IDs are the unit of scoring. Collapse duplicate IDs deterministically
    # before either correlation or individual factors inspect category membership.
    evidence_by_id = {}
    for row in sorted(evidence, key=lambda item: (
            item.get("id", ""), json.dumps(item, sort_keys=True, ensure_ascii=True, default=str))):
        evidence_by_id.setdefault(row["id"], row)
    evidence = list(evidence_by_id.values())
    consumed = set()
    drivers = []
    score = 0

    def contribute(title: str, weight: int, rows: list[dict], *, require_all: bool = False) -> bool:
        nonlocal score
        all_ids = {row["id"] for row in rows}
        ids = sorted(all_ids - consumed)
        if not ids or (require_all and len(ids) != len(all_ids)):
            return False
        score += weight
        consumed.update(ids)
        drivers.append({"factor": title, "points": weight, "evidence_ids": ids})
        return True

    ordered_correlations = sorted(correlations, key=lambda row: (
        CORRELATION_SCORE_PRIORITY.index(row["rule"])
        if row.get("rule") in CORRELATION_SCORE_PRIORITY else len(CORRELATION_SCORE_PRIORITY),
        tuple(sorted(set(row.get("evidence_ids", ())))), row.get("rule", ""), row.get("title", "")))
    correlations_by_rule = {}
    for correlation in ordered_correlations:
        correlations_by_rule.setdefault(correlation.get("rule"), correlation)
    for rule in CORRELATION_SCORE_PRIORITY:
        correlation = correlations_by_rule.get(rule)
        if correlation:
            ids = correlation.get("evidence_ids", ())
            if ids and all(item in evidence_by_id for item in ids):
                rows = [evidence_by_id[item] for item in ids]
                contribute(correlation.get("title", rule), 2, rows, require_all=True)

    signatures = [row for row in evidence if row["supporting_details"].get("indicator_kind") == "known_signature"]
    if signatures:
        contribute("Known packer-related signature", 2, signatures)

    yara = [row for row in evidence if row["category"] == "yara"]
    if yara:
        contribute("YARA rule match", 2, yara)
    if any(row["category"] == "imports" and row["id"] not in consumed for row in evidence):
        contribute("Sensitive import reference", 1,
                   [row for row in evidence if row["category"] == "imports"])
    if any(row["category"] == "strings" and row["id"] not in consumed for row in evidence):
        contribute("Suspicious string indicator", 1,
                   [row for row in evidence if row["category"] == "strings"])
    if any(row.get("supporting_details", {}).get("indicator_kind") == "writable_executable_section"
           and row["id"] not in consumed for row in evidence):
        contribute("Writable-executable section", 1,
                   [row for row in evidence if row.get("supporting_details", {}).get("indicator_kind")
                    == "writable_executable_section"])
    if any(row.get("supporting_details", {}).get("indicator_kind") == "section_name"
           and row["id"] not in consumed for row in evidence):
        contribute("Packer-like section name", 1,
                   [row for row in evidence if row.get("supporting_details", {}).get("indicator_kind") == "section_name"])
    if any(row.get("supporting_details", {}).get("indicator_kind") == "entry_point_layout"
           and row["id"] not in consumed for row in evidence):
        contribute("Unusual entry-point placement", 1,
                   [row for row in evidence if row.get("supporting_details", {}).get("indicator_kind") == "entry_point_layout"])
    if any(row["category"] == "entropy" and row["id"] not in consumed for row in evidence):
        contribute("High entropy heuristic", 1,
                   [row for row in evidence if row["category"] == "entropy"])

    failed = [name for name in required_components
              if components.get(name, {}).get("status") not in ("success", "skipped")]
    unknown = [name for name in required_components
               if components.get(name, {}).get("status") == "skipped"
               and components.get(name, {}).get("reason") == "unsupported_format"]
    incomplete = bool(failed or unknown)
    if incomplete and score == 0:
        level = "inconclusive"
    elif score >= 7:
        level = "critical"
    elif score >= 5:
        level = "high"
    elif score >= 3:
        level = "medium"
    elif score > 0:
        level = "low"
    else:
        level = "informational"
    explanations = [driver["factor"] for driver in drivers]
    if not explanations:
        explanations.append("No configured triage indicators were observed; this is not a clean-file verdict.")
    if incomplete:
        explanations.append("Some requested analysis was unavailable or incomplete: " + ", ".join(sorted(set(failed + unknown))) + ".")
    return {"level": level, "score": score, "score_is_probability": False,
            "incomplete": incomplete, "drivers": drivers, "explanation": explanations,
            "model": "0 informational; 1-2 low; 3-4 medium; 5-6 high; 7+ critical. Correlation scoring priority is YARA+strings, imports+strings, entropy+write/execute, then packer signature+section. A correlation receives its full weight only when all supporting evidence is unused; otherwise its individual indicators may score independently. Each evidence item is used in at most one scoring group. High entropy alone is weak and contributes at most one point.",
            "limitations": ["This assessment is deterministic triage, not a probability or malware verdict.",
                            "Missing or skipped analysis is unknown, not evidence that a file is clean."]}


def _export(output_value, path: Path, rules_path: Path | None, report: dict) -> dict:
    output_path = Path(output_value).expanduser()
    try:
        resolved = output_path.resolve()
        if resolved == path.resolve() or (rules_path and resolved == rules_path.resolve()):
            raise CTFForgeError("Triage report must not overwrite its target or YARA rules file.")
        if not output_path.parent.is_dir():
            raise CTFForgeError(f"Report output directory does not exist: {output_path.parent}")
        report["export"] = {"status": "success", "path": str(output_path)}
        payload = json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(payload) > MAX_REPORT_BYTES:
            raise CTFForgeError(f"Triage report exceeds the {MAX_REPORT_BYTES}-byte export limit.")
        with output_path.open("xb") as stream:
            stream.write(payload)
        return report["export"]
    except FileExistsError:
        report["export"] = {"status": "failed", "error": f"Refusing to overwrite existing report: {output_path}"}
    except (OSError, TypeError, ValueError, CTFForgeError) as exc:
        report["export"] = {"status": "failed", "error": str(exc)}
    report["report_status"] = "export_failed"
    return report["export"]


def analyze(context: ToolContext) -> ToolResult:
    args = context.arguments
    path_value = args.get("file")
    if not isinstance(path_value, (str, Path)):
        raise CTFForgeError("A target file path is required.")
    path = Path(path_value).expanduser()
    try:
        if not path.is_file():
            raise CTFForgeError(f"Target is not a regular file: {path}")
    except OSError as exc:
        raise CTFForgeError(f"Cannot access target file {path}: {exc}") from exc
    profile = args.get("profile", "standard")
    if profile not in ("quick", "standard"):
        raise CTFForgeError("Triage profile must be quick or standard.")
    timeout = args.get("timeout", 10)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 60:
        raise CTFForgeError("Triage timeout must be an integer from 1 to 60 seconds.")
    rules_value = args.get("rules")
    rules_path = Path(rules_value).expanduser() if rules_value else None
    initial_size, sha256, initial_stat = _snapshot(path)

    registry = build_core_registry()
    components = {}
    results = {}
    base_args = {"file": path}
    for name, tool, extra in (
        ("identity", "info", {}),
        ("strings", "strings", {"min_length": 4, "encoding": "both", "limit": 5000}),
        ("entropy", "entropy", {"block_size": 4096}),
        ("packer", "packer", {}),
    ):
        output = _component(registry, components, name, tool, {**base_args, **extra})
        if output is not None:
            results[name] = output
    identity = results.get("identity")
    detected_format = identity.get("format", "Unknown") if identity else "Unknown"
    if profile == "standard" and detected_format in ("ELF", "PE"):
        structure_tool = "elf" if detected_format == "ELF" else "pe"
        for name, tool in (("structure", structure_tool), ("symbols", "symbols")):
            output = _component(registry, components, name, tool, base_args)
            if output is not None:
                results[name] = output
        if "symbols" in results:
            # The symbols handlers already return STT_FUNC rows or PE exports; reuse
            # these rather than reparsing the same tables with the functions handler.
            components["functions"] = {"status": "success", "source": "symbols",
                                        "derived_without_reparsing": True}
        else:
            components["functions"] = {"status": "skipped", "reason": "symbol_analysis_unavailable"}
    elif profile == "standard":
        for name in ("structure", "symbols", "functions"):
            _skip(components, name, "unsupported_format")
    else:
        for name in ("structure", "symbols", "functions"):
            _skip(components, name, "quick_profile")

    skip_yara = bool(args.get("skip_yara", False))
    if skip_yara:
        _skip(components, "yara", "explicitly_skipped")
    elif rules_path is None:
        _skip(components, "yara", "no_rules_supplied")
    else:
        output = _component(registry, components, "yara", "yara",
                            {"file": path, "rules": rules_path, "timeout": timeout})
        if output is not None:
            results["yara"] = output

    evidence, evidence_truncated = _collect_evidence(components, results)
    correlations = correlate(evidence)
    required = {"identity", "strings", "entropy", "packer"}
    if profile == "standard":
        required.update(("structure", "symbols"))
    if rules_path is not None and not skip_yara:
        required.add("yara")
    assessment = assess(evidence, correlations, components, required)
    skipped = [{"component": name, "reason": value.get("reason")}
               for name, value in components.items() if value.get("status") == "skipped"]
    detected_meta = identity.get("metadata", {}) if identity else {}
    report = {"report_schema_version": "1.0", "generated_at": datetime.now(timezone.utc).isoformat(),
              "profile": profile,
              "target": {"filename": path.name, "path": str(path), "size": initial_size,
                         "sha256": sha256, "format": detected_format,
                         "architecture": detected_meta.get("machine"),
                         "bitness": detected_meta.get("class_bits"),
                         "endianness": detected_meta.get("endianness")},
              "components": components, "evidence": evidence, "correlations": correlations,
              "assessment": assessment, "skipped_analyses": skipped,
              "truncation": {"strings": components.get("strings", {}).get("truncated", False),
                             "yara_matches": components.get("yara", {}).get("matches_truncated", False),
                             "yara_string_instances": components.get("yara", {}).get("string_instances_truncated", False),
                             "sections": components.get("structure", {}).get("sections_truncated", False),
                             "evidence": evidence_truncated},
              "limitations": ["A triage result is an investigative assessment, not a definitive malware verdict.",
                              "No target binaries are executed; no external utilities are invoked automatically.",
                              "Only listed string patterns and deterministic correlations are considered.",
                              "YARA compilation time is not bounded by yara-python's scan timeout."]}
    final_size, final_sha, final_stat = _snapshot(path)
    if (final_size, final_sha, final_stat) != (initial_size, sha256, initial_stat):
        raise CTFForgeError("Target changed during triage; no report was returned.")
    if args.get("output"):
        _export(args["output"], path, rules_path, report)
    return report
