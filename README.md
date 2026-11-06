# CTFForge

CTFForge is a modular, Linux-first toolkit for CTF competitions, practice labs, and authorized security education. It targets Python 3.10+ and supports Linux (including Kali) and Windows development.

The repository contains the shared foundation, an initial generic offline solver, and the first independent specialist category: Crypto. Category-specific implementations and dependencies remain isolated from the core.

## Install on Linux / Kali Linux

The current foundation uses only the Python standard library at runtime. Use a virtual environment so it works with Kali's externally managed Python environment:

```bash
cd /path/to/CTF_TOOLS
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
ctfforge --help
ctfforge doctor
```

If `venv` is unavailable, install your distribution's Python venv package first (for example `python3-venv` on Debian/Kali). Optional system tools are listed in `requirements/kali-tools.md`; CTFForge detects them but does not install or run them automatically. Avoid `sudo pip` and don't install into the system Python.

## Windows development install

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
py -m pip install -e .
python -m ctfforge --help
```

For development tools, install `python -m pip install -r requirements/dev.txt` inside the virtual environment. Python package dependencies are split by category in `requirements/`; external Kali tools are listed in `requirements/kali-tools.md` and are never installed automatically.

## Phase 1 commands

```text
python -m ctfforge doctor
python -m ctfforge hash evidence.bin
python -m ctfforge strings evidence.bin
python -m ctfforge detect challenge-directory/
```

## Guided solver (initial offline foundation)

The first solver slice accepts a local artifact, UTF-8 text, or binary-safe stdin. Provide a category and either a flag regular expression or literal prefix:

```bash
python -m ctfforge solve --category crypto --flag-format 'CTF{.*}' --file ./challenge.txt
python -m ctfforge solve --category crypto --flag-prefix 'CTF{' --input 'SGVsbG8='
cat challenge.bin | python -m ctfforge solve --category steg --flag-format 'CTF{.*}' --stdin
python -m ctfforge continue SESSION_ID --result 'decoded text from an external operation'
```

Each solve stores a local session under `sessions/` with the original input, evidence, decoded artifacts, `session.json`, and a JSON report. Review the session directory before sharing it because it contains a copy of the supplied challenge. The current engine performs common offline text decoding (Base64, hex, URL/HTML/Unicode escapes, ROT13 when evidence supports it, gzip, and zlib), validates only the supplied flag expression, and records continuation results. Category-specific analysis and broader transformation support are not connected yet.

## Crypto tools

The initial Crypto category provides independent XOR analysis and heuristic hash-format identification. Both use only the Python standard library; install no additional Crypto packages:

```bash
ctfforge crypto xor --file challenge.bin
ctfforge crypto xor --hex 1c0d1d --key K
ctfforge crypto xor --input 'ciphertext text' --repeat-key ICE
ctfforge crypto xor --hex 3c2d --limit 20
ctfforge crypto hashid --input '5f4dcc3b5aa765d61d8327deb882cf99'
ctfforge crypto hashid --file hash.txt
```

XOR accepts one file, UTF-8 text, or hexadecimal input. With no key it ranks single-byte XOR candidates; `--key` accepts one UTF-8 byte and `--repeat-key` accepts a UTF-8 repeating key. File and decoded hex input are limited to 16 MiB. Hash identification checks structure for MD5, NTLM, SHA-1/256/384/512, bcrypt, and SHA-256/512 crypt. It is heuristic, can return multiple candidates (for example MD5 and NTLM), and does not crack passwords.

## Steganography file inspection

The Steganography category includes image metadata inspection, bounded file-structure analysis, and heuristic LSB analysis. Metadata supports JPEG/JPG, PNG, TIFF, and WebP through the optional Pillow dependency. LSB analysis supports PNG, TIFF, BMP, GIF, and lossless WebP. Install Pillow only when needed:

```bash
python -m pip install -r requirements/steg.txt
ctfforge steg metadata --file image.jpg
ctfforge steg structure --file suspicious.png
ctfforge steg lsb --file hidden.png
ctfforge steg lsb --file hidden.png --channel red --bit-plane 0
ctfforge steg lsb --file hidden.png --channel green --bit-order lsb --output extracted.bin
ctfforge steg lsb --file hidden.png --channel blue --text
```

Metadata inspection reports dimensions, color mode, available EXIF and GPS fields, timestamps, and image text metadata without changing the source. Structure analysis checks signatures, extensions, PNG chunks and CRCs, JPEG markers, common endings, trailing bytes, and a small set of embedded signatures. Both tools bound processed file size to 32 MiB. LSB analysis independently checks red, green, blue, and (when present) alpha channels, with bit planes 0 through 7. Pixels are traversed row-major; default byte packing is MSB-first (first pixel becomes the byte's high bit), and `--bit-order lsb` reverses that packing order. The default checks plane 0 and all available channels. Scores use printable-byte ratio, UTF-8 validity, common readable markers, and null-byte ratio; they rank candidates only.

Use `--output` with one selected channel to write its stream as binary to a new file. Existing output files are never overwritten. `--text` includes valid UTF-8 extracted content in the JSON result, capped at 4096 characters; choose one channel. Results are bounded to 32 MiB input, 4 million pixels, 16 MiB output, and short previews. JPEG is intentionally rejected for basic LSB recovery because lossy compression changes pixel values and can destroy embedded bits. Other image transformations can also alter pixels. Readable text is a candidate for investigation, not proof that data was hidden. No extracted content is executed or opened.

## Web security toolkit

JWT and URL analysis are offline. Header, cookie, and CORS tools accept repeated `--header 'Name: value'` values or fetch headers from `--url`. Directory discovery sends bounded GET requests to a user-provided HTTP(S) target and local wordlist; use it only with explicit authorization.

```bash
ctfforge web jwt --token 'eyJ...'
ctfforge web headers --url https://example.test
ctfforge web cookies --url https://example.test
ctfforge web cors --url https://example.test
ctfforge web url --input 'https://example.test/a?x=1&x=2#section'
ctfforge web discover --url https://lab.example.test --wordlist ./paths.txt
```

JWT signatures are never verified and signature bytes are not displayed. Header and CORS results are indicators, not proof of vulnerability or exploitability. Cookie values are redacted. URL analysis never visits URLs. HTTP uses standard-library urllib with TLS verification enabled, timeouts, and bounded reads; discovery defaults to two requests per second and two workers, has no recursion, and does not follow redirects. No additional dependency is required.

## Digital forensics

Forensics provides offline PCAP/PCAPNG analysis, selective file carving, and authentication/syslog/Apache/Nginx log timelines:

```bash
ctfforge forensics pcap --file capture.pcap --backend auto --format json
ctfforge forensics pcap --file capture.pcapng --backend native --format csv
ctfforge forensics carve --file suspicious.bin --output-dir recovered
ctfforge forensics carve --file suspicious.bin --output-dir recovered --extract-offset 0x120
ctfforge forensics logs --file auth.log
ctfforge forensics logs --file access.log --format csv
```

Native packet parsing supports Ethernet (including VLAN), IPv4/IPv6, TCP, UDP, basic DNS questions, and HTTP request-line metadata. It is not a complete protocol dissector. PCAP input is capped at 64 MiB and 100,000 packets. `--backend auto` uses TShark when available and otherwise reports its absence while providing the native summary; `--backend tshark` requires the executable. Install TShark using the official Wireshark instructions for your operating system; CTFForge never installs it.

Carving scans at most 128 MiB and recognizes JPEG, PNG, PDF, and ZIP signatures. Recovery is opt-in by a candidate offset, limited to 20 files of at most 25 MiB each, uses unique exclusive-create filenames, and never executes recovered content. Binwalk is optional; CTFForge invokes only a signature scan and never requests extraction. Install Binwalk through your operating system's package manager or its official project instructions; it is not installed automatically.

Log analysis preserves each original line and its 1-based line number. Detection patterns are investigative indicators and do not establish malicious intent. Source captures and logs are read only; findings may be incomplete for malformed, unsupported, or truncated formats. External tool output and runtime are bounded. No Python dependency is added.

## Interactive terminal launcher

Start the menu with:

```text
ctfforge interactive
```

The launcher lists all 15 planned categories. Registered categories are selectable; categories without registered tools are marked `Coming Soon`.

```text
[1] Cryptography
[2] Web Exploitation
[3] Steganography
[4] Digital Forensics
[5] Reverse Engineering
...
[15] Miscellaneous
[0] Exit
```

Choose a category number, then a tool number. Use `b` to go back, `h` to return home, and `0` to exit where shown. After a tool runs, choose to run it again, return to its category, go home, or exit. At an input prompt, `:back`, `:home`, or `:exit` navigates without running the tool. Ctrl+C and end-of-input close cleanly. Tool inputs, defaults, validation, usage, and help come from registered metadata; execution calls the same handlers as direct commands. Existing direct commands remain available, for example `ctfforge crypto xor --input TEXT` and `ctfforge forensics logs --file auth.log`.

Reverse Engineering lists ten registry-backed tools: info, strings, entropy, ELF, PE, symbols, disassembly, instruction analysis, function metadata, and packer indicators.

## Planned categories

Hashing, strings, and file identification from the existing `common` registry category are available under Miscellaneous. Binary Exploitation, OSINT, Network Analysis, Linux, Windows / AD, Mobile, Cloud, Wireless, and Blockchain are shown as `Coming Soon` until they have registered tools. No placeholder handlers are registered.

## Reverse Engineering

Native static reverse analyzers are available from both the `ctfforge interactive` menu and direct CLI commands:

```bash
ctfforge reverse info --file sample.bin
ctfforge reverse strings --file sample.bin --min-length 5 --encoding both --limit 5000
ctfforge reverse strings --file sample.bin --output strings.txt
ctfforge reverse entropy --file sample.bin --block-size 4096
ctfforge reverse elf --file program.elf
ctfforge reverse pe --file program.exe
ctfforge reverse symbols --file program.elf
ctfforge reverse disasm --file sample.bin --arch x86 --bits 64 --offset 0x1000
ctfforge reverse instructions --file sample.bin --arch x86 --bits 64 --details
ctfforge reverse functions --file program.elf
ctfforge reverse packer --file sample.exe
```

The ten tools identify binary format and architecture, extract ASCII/UTF-16LE strings with file offsets, calculate overall/block Shannon entropy, inspect ELF/PE structures, list available ELF symbols or PE imports/exports, disassemble bounded ranges, summarize decoded instruction groups, report symbol-derived functions, and identify static packer indicators. ELF supports 32/64-bit and little/big-endian files; PE supports PE32 and PE32+. Identification also recognizes common Mach-O signatures and archives, but does not deeply parse every format. Extended ELF numbering and Mach-O universal slice tables are unsupported.

Disassembly and instruction analysis use optional Capstone. Install it explicitly with `python -m pip install -r requirements/reverse.txt`; it is never installed automatically. Supported architecture families are x86 (16/32/64-bit), ARM/Thumb, ARM64/AArch64, and MIPS, subject to the installed Capstone build. ELF/PE metadata supplies architecture only when reliable. Raw binaries require explicit architecture and bitness; ARM requires `--mode arm|thumb`, and ARM/MIPS raw data requires explicit endianness. Each decode reads at most 1 MiB and decodes at most 10,000 instructions (defaults: 4096 bytes and 1000 instructions). Example: `ctfforge reverse disasm --file sample.bin --arch x86 --bits 64 --offset 0x1000 --max-bytes 4096 --max-instructions 1000`.

Instruction summaries count only decoded instructions and report remaining undecoded/unprocessed bytes separately. Static counts do not establish runtime behavior. Function analysis reports only ELF `STT_FUNC` symbols and PE exports; stripped files may have no function results, and arbitrary function boundaries are not inferred. Packer output separates known signatures from heuristic section, permission, entry-point, and entropy indicators. High entropy alone is not proof of packing, encryption, or malware. Analysis is read-only: files are never executed or unpacked. Optional JSON exports use exclusive creation and refuse to overwrite existing files. Interactive mode discovers all ten tools from the registry.

After installation, use `ctfforge` in place of `python -m ctfforge`. See [ARCHITECTURE.md](ARCHITECTURE.md) and [SECURITY.md](SECURITY.md).
