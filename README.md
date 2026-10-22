# CTFForge

CTFForge is a modular, Linux-first toolkit for CTF competitions, practice labs, and authorized security education. It targets Python 3.10+ and supports Linux (including Kali) and Windows development.

The repository contains the shared foundation and an initial generic offline solver. Category-specific tools are added as independent packages in later phases; no category implementation or category dependency is bundled into the core.

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

After installation, use `ctfforge` in place of `python -m ctfforge`. See [ARCHITECTURE.md](ARCHITECTURE.md) and [SECURITY.md](SECURITY.md).
