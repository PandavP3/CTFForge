"""Cautious signature and layout indicators for static packer triage."""
from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.hashing import shannon_entropy
from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult
from .formats import MAX_BINARY_BYTES, parse_elf, parse_pe, read_binary

MAX_ENTROPY_SCAN = 64 * 1024 * 1024
SECTION_SAMPLE = 1024 * 1024
PACKER_MARKERS = (b"UPX!", b"MPRESS1", b"MPRESS2", b"ASPack", b"Themida", b".vmp0", b".vmp1")
PACKER_SECTION_NAMES = ("UPX0", "UPX1", ".aspack", ".adata", ".themida", ".vmp0", ".vmp1", ".petite")


def analyze(context: ToolContext) -> ToolResult:
    path, data = read_binary(context.arguments.get("file"), maximum=MAX_BINARY_BYTES)
    signatures = [{"signature": marker.decode("ascii", "replace"), "offset": data.find(marker)}
                  for marker in PACKER_MARKERS if data.find(marker) >= 0]
    indicators = [{"kind": "known_signature", "evidence": row} for row in signatures]
    fmt, sections, entry = "unknown", [], None
    if data.startswith(b"\x7fELF"):
        info = parse_elf(data)
        fmt, sections, entry = "ELF", info["sections"], info["entry_point"]
        executable = [seg for seg in info["program_headers"] if "execute" in seg["flags"]]
        if entry and not any(seg["virtual_address"] <= entry < seg["virtual_address"] + seg["memory_size"]
                             for seg in executable):
            indicators.append({"kind": "entry_point_layout", "evidence": "Entry point is outside executable PT_LOAD segments."})
    elif data.startswith(b"MZ"):
        info = parse_pe(data)
        fmt, sections, entry = "PE", info["sections"], info["entry_point_rva"]
        entry_section = next((s for s in sections if s["virtual_address"] <= entry <
                              s["virtual_address"] + max(s["virtual_size"], s["raw_size"])), None)
        if entry and (entry_section is None or "execute" not in entry_section["permissions"]):
            indicators.append({"kind": "entry_point_layout", "evidence": "Entry point is not in a mapped executable section."})
    else:
        return make_result("reverse", str(path), tool="packer", format=fmt, indicators=indicators,
                           summary="Unknown format; only raw known-signature checks were performed.",
                           note="Indicators are heuristic and do not establish packing or malicious behavior.")
    scanned = 0
    section_results = []
    for section in sections:
        if fmt == "PE":
            name, off, size, flags = section["name"], section["raw_offset"], section["raw_size"], section["permissions"]
        else:
            name, off, size, flags = section["name"], section["offset"], section["size"], section["flags"]
        if any(marker.casefold() in name.casefold() for marker in PACKER_SECTION_NAMES):
            indicators.append({"kind": "section_name", "evidence": f"Section name {name!r} resembles a known packer marker."})
        if "write" in flags and "execute" in flags:
            indicators.append({"kind": "writable_executable_section", "evidence": f"Section {name!r} is writable and executable."})
        sample_size = min(size, SECTION_SAMPLE, max(0, MAX_ENTROPY_SCAN - scanned))
        entropy = None
        if sample_size:
            sample = data[off:off + sample_size]
            scanned += len(sample)
            entropy = round(shannon_entropy(sample), 6)
            if entropy >= 7.2:
                indicators.append({"kind": "high_entropy", "evidence": f"Section {name!r} sample entropy is {entropy} bits/byte."})
        section_results.append({"name": name, "offset": off, "size": size,
                                "sampled_bytes": sample_size, "entropy": entropy, "flags": flags})
    known = any(row["kind"] == "known_signature" for row in indicators)
    summary = ("Known packer-related signature found; verify the evidence and file provenance." if known else
               "No known marker found. Layout and entropy indicators, if any, require manual review." if indicators else
               "No packer indicators found in inspected metadata.")
    return make_result("reverse", str(path), tool="packer", format=fmt, indicators=indicators,
                       sections=section_results[:8192], entropy_scan_bytes=scanned, summary=summary,
                       note="Static indicators are not proof of packing or malware; high entropy alone is not conclusive. No unpacking or execution is performed.")
