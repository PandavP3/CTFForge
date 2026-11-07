# Architecture

CTFForge uses a `src` package layout. `ctfforge.core` contains reusable infrastructure: CLI wiring, config, logging, platform checks, subprocess handling, evidence, hashing, file identification, strings, output formats, and the tool contract/registry. Challenge logic belongs in independent category packages under `src/ctfforge/` and is imported lazily only when its handler is resolved.

Each category owns its implementation, optional dependencies, documentation, controlled samples, and tests. The core must not import category packages during startup. Optional system programs are discovered with PATH lookup and are never installed or invoked by `doctor`.

Phase 1 provides common hashing, strings, flag detection, environment checks, configuration, and report primitives. Automatic category identification and cross-category orchestration are reserved for the integration phase.

The guided solver foundation lives in core modules for input normalization, flag-format validation, sessions, conservative offline decoders, and recommendations. The solver itself does not invoke registered category handlers yet; its category value is persisted as the solver's priority for future category integrations. Solve sessions are local files under `sessions/` by default.

## Tool contract and registry

`ctfforge.core.tool.ToolSpec` is immutable metadata for one tool: lowercase category and tool names, description, a `module.path:callable` handler reference, optional Python import names, and optional usage/help text. `ToolContext` is the common input passed by a future CLI or interactive dispatcher; `ToolHandler` accepts one context and returns the common result dictionary (`ToolResult`).

`ctfforge.core.registry.ToolRegistry` is instance-scoped. It registers individual specs or a non-empty category batch, lists categories and tools in stable order, looks up a tool, and resolves its handler. A handler reference is imported only on `resolve_handler`; listing metadata does not import category packages. Missing declared optional dependencies produce a category-specific error that points to that category's requirements file. A failed import or missing handler is reported as a registry resolution error. The registry does not run handlers or invoke external commands.

The current common registration in `ctfforge.core.registration` exposes three existing operations under the `common` category: `hash`, `strings`, and `identify`. The first two retain the existing `ctfforge hash FILE` and `ctfforge strings FILE` commands; those command paths now resolve the registered adapters while preserving their printed output. `identify` is available through the registry only; this phase adds no CLI route for it.

Compatibility handlers live in `ctfforge.core.tool_adapters`. They validate the normalized file argument, call the existing functions in `hashing.py`, `strings.py`, and `file_detection.py`, and wrap the values in the existing common result envelope. They do not reimplement those operations. `build_core_registry()` returns a fresh registry; `register_core_tools(registry)` can add the same declarations to an application-owned registry. Neither helper imports the adapter module until a tool handler is resolved.

When a category is implemented, its registration function will declare metadata and references without importing handler modules:

```python
from ctfforge.core.tool import ToolSpec


def register_tools(registry):
    registry.register_category("crypto", [
        ToolSpec(
            category="crypto",
            name="xor",
            description="Analyze or decode XOR challenge data.",
            handler_ref="ctfforge.crypto.xor:run",
            usage="ctfforge crypto xor --file INPUT",
        ),
    ])
```

The category module and handler file are created as part of that category's implementation phase; no unimplemented category packages are pre-created. A future application startup step can call the registration functions for implemented categories, while the CLI and interactive mode use the same registry and dispatcher.

## Crypto category

`ctfforge.crypto.registration` registers two independent handlers: `xor` and `hashid`. The CLI builds the core registry and resolves only the requested handler. XOR analysis in `ctfforge.crypto.xor` supports bounded file, UTF-8 text, and hex input; absent a key it ranks single-byte XOR candidates, while explicit single-byte and repeating-key modes decrypt directly. `ctfforge.crypto.hashid` performs structural, heuristic identification for MD5/NTLM, SHA-1, SHA-256/384/512, bcrypt, and SHA-256/512 crypt strings. It does not perform cracking. No third-party Crypto dependency is required.

## Steganography category

`ctfforge.steg.registration` registers `metadata`, `structure`, and `lsb` without importing their handlers. Metadata imports Pillow only when selected and inspects JPEG, PNG, TIFF, and WebP metadata; Pillow is isolated in `requirements/steg.txt`. Structure uses the standard library and existing signature detection for bounded checks, PNG chunk/CRC parsing, JPEG markers, common end markers, extension mismatches, and recognizable embedded signatures. LSB analysis imports Pillow only when selected and scans PNG, TIFF, BMP, GIF, and lossless WebP images, within 32 MiB, 4 million pixels, and 16 MiB output limits. It extracts each selected channel independently, in row-major order, for bit planes 0-7. MSB-first byte packing is the default: the first traversed pixel supplies the output byte's most significant bit; LSB-first is also available. Candidates are ranked by printable-byte ratio, UTF-8 validity, selected readable markers, and null-byte ratio. These transparent heuristics do not prove hidden content. JPEG is rejected because lossy compression can destroy basic LSB data. Binary export uses exclusive creation and refuses overwrite; bounded UTF-8 text can be included on request. No extracted content is executed or automatically opened.

## Web category

`ctfforge.web.registration` lazily registers JWT, HTTP header, cookie, CORS, URL, and directory-discovery handlers. JWT and URL analysis are offline; response analyzers accept supplied headers or fetch when `--url` is supplied. JWT signatures are not verified; cookie values are redacted; header findings do not establish a vulnerability. Discovery requires an explicit HTTP(S) target and local wordlist, uses 1–5 workers, 0.1–10 requests/second, 0.2–30 second timeouts, and reads at most 64 KiB per response. It does not recurse, follow redirects, bypass access controls, or exploit. Standard-library networking is used with TLS verification enabled and no additional web dependencies.

## Forensics category

`ctfforge.forensics.registration` lazily registers `pcap`, `carve`, and `logs`. The PCAP analyzer reads PCAP/PCAPNG offline with a 64 MiB and 100,000-packet bound. The native parser handles Ethernet/VLAN, IPv4/IPv6, TCP/UDP, simple DNS question extraction, and HTTP request lines. It is intentionally not a full dissection engine. Optional TShark uses fixed `-r`/field-output arguments with bounded runtime/output and no shell; `auto` falls back to native output when unavailable. TShark is not installed by CTFForge.

Carving scans a bounded 128 MiB source for JPEG, PNG, PDF, and ZIP signatures. Boundary detection is format-aware where practical; recovery requires explicit offsets, refuses incomplete candidates, writes with exclusive creation, and caps the run to 20 outputs of 25 MiB. Optional Binwalk is run only with signature-scan flags, never extraction flags. Logs preserve original source lines and 1-based references, sort parseable timestamps chronologically, and identify common auth/syslog and combined HTTP access lines. Heuristic findings do not establish malicious intent. All external commands use allowlisted executable names, argument arrays, timeouts, and bounded captured output; no external utility is installed automatically. No Python dependency is required.

## Interactive terminal

`ctfforge interactive` is a presentation layer over `build_core_registry()`: categories and tools come from registry metadata, and selected handlers receive the existing `ToolContext`. The existing `common` category appears under the menu's Miscellaneous entry. `InteractiveInput` is an optional backward-compatible `ToolSpec` field describing prompt types, choices, defaults, required fields, and exclusive input groups. No handler logic or direct CLI route is duplicated. Categories without registered tools are display-only Coming Soon entries. The launcher uses standard-library input/output, a loop-based navigation state machine, and a plain-text fallback when terminal Unicode or ANSI styling is unavailable.

## Reverse Engineering category

`ctfforge.reverse.registration` lazily registers native reverse tools and optional external utility wrappers. The shared `formats.py` module reads binaries as bounded immutable byte strings and centralizes checked ELF/PE parsing. Native input files are capped at 128 MiB (strings and entropy at 64 MiB); ELF program and section counts, symbol scans, PE sections, imports, exports, string counts, export bytes, entropy block size, and block counts all have explicit limits. No binaries are executed or loaded. Selected external wrappers may pass an input path to the named inspection utility using the bounded runner described below.

ELF parsing supports ELF32/ELF64, both byte orders, program headers, section headers/names, and section-based `.symtab`/`.dynsym` entries. Extended numbering is reported as unsupported. PE parsing supports PE32/PE32+, COFF/optional headers, sections, bounded data-directory metadata, import descriptors/thunks, and export tables. Malformed ranges become clear errors or parser warnings. Binary identification also checks Mach-O thin signatures and common archive signatures; Mach-O universal files are identified but their slice tables are not decoded. Strings are bounded ASCII/UTF-16LE extracts with offsets and exclusive-create export. Entropy uses Shannon entropy and labels high-entropy blocks as possible compression/encryption indicators only; it does not establish malicious behavior.

`disassembly.py` imports Capstone lazily; Capstone is optional and declared only in `requirements/reverse.txt`. It reuses `formats.py` metadata for ELF/PE architecture and file-to-virtual-address mapping when available. Raw binaries require explicit architecture and bitness; ARM mode and ARM/MIPS endianness are never guessed. Decoding is capped at 1 MiB and 10,000 instructions per call (defaults 4096 bytes and 1000 instructions). `instruction_analysis.py` aggregates the shared decoded records without decoding a second time. Optional JSON output is capped at 8 MiB and exclusively created.

`function_analysis.py` reports only validated ELF `STT_FUNC` symbols and PE exported functions. It does not infer boundaries for stripped or raw binaries. `packer_detection.py` distinguishes known byte-marker matches from heuristic section-name, permission, entry-point, and entropy indicators. Entropy sampling is capped at 64 MiB total and 1 MiB per section. High entropy is not proof of packing, encryption, or malware. No new tool executes or unpacks analyzed files.

### Optional reverse engineering utilities

`ctfforge.integrations.reverse_tools` provides fixed-argument adapters over the existing bounded process runner in `integrations/_process.py`. The runner's executable allowlist includes `file`, `readelf`, and `objdump`; it resolves them with `shutil.which`, invokes an argument array with `shell=False`, applies timeouts, and independently caps stdout and stderr. `external-status` only performs executable lookup. `external-file`, `external-elf`, and `external-objdump` validate regular-file inputs and expose only allowlisted mode names; no arbitrary argument forwarding exists. `objdump` disassembly output has a configurable maximum cap (up to 2 MB per stream). Missing tools, timeout, truncation, and nonzero process exits are represented in structured results. The tools are optional on Windows and Linux, are never installed automatically, and never execute the analyzed file. They supplement the native parsers without modifying them.
