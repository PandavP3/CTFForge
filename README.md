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

After installation, use `ctfforge` in place of `python -m ctfforge`. See [ARCHITECTURE.md](ARCHITECTURE.md) and [SECURITY.md](SECURITY.md).
