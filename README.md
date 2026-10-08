# CTFForge

CTFForge is a modular, Linux-first toolkit for CTF competitions, practice labs, and authorized security education. It is developed on Windows and targets Python 3.10+.

The repository currently contains **Phase 1: foundation only**. Category tools are added as independent packages in later phases; no category implementation or category dependency is bundled into the core.

## Development install

```powershell
python -m pip install -e .
python -m ctfforge --help
```

For development tools, install `python -m pip install -r requirements/dev.txt`. Python package dependencies are split by category in `requirements/`; external Kali tools are listed in `requirements/kali-tools.md` and are never installed automatically.

## Phase 1 commands

```text
python -m ctfforge doctor
python -m ctfforge hash evidence.bin
python -m ctfforge strings evidence.bin
python -m ctfforge detect challenge-directory/
```

## Guided solver (initial offline foundation)

The first solver slice accepts a local artifact, UTF-8 text, or binary-safe stdin. Provide a category and either a flag regular expression or literal prefix:

```powershell
python -m ctfforge solve --category crypto --flag-format 'CTF{.*}' --file .\challenge.txt
python -m ctfforge solve --category crypto --flag-prefix 'CTF{' --input 'SGVsbG8='
cat challenge.bin | python -m ctfforge solve --category steg --flag-format 'CTF{.*}' --stdin
python -m ctfforge continue SESSION_ID --result 'decoded text from an external operation'
```

Each solve stores a local session under `sessions/` with the original input, evidence, decoded artifacts, `session.json`, and a JSON report. Review the session directory before sharing it because it contains a copy of the supplied challenge. The current engine performs common offline text decoding (Base64, hex, URL/HTML/Unicode escapes, ROT13 when evidence supports it, gzip, and zlib), validates only the supplied flag expression, and records continuation results. Category-specific analysis and broader transformation support are not connected yet.

After installation, use `ctfforge` in place of `python -m ctfforge`. See [ARCHITECTURE.md](ARCHITECTURE.md) and [SECURITY.md](SECURITY.md).
