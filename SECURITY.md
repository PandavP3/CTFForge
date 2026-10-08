# Security policy and scope

CTFForge is for CTF competitions, local vulnerable machines, practice labs, and explicitly authorized testing. Users are responsible for obtaining authorization before testing systems they do not own.

The Phase 1 core performs local file inspection. Its subprocess helper accepts argument arrays, disables shell execution, and does not invoke privilege escalation. `doctor` only checks whether optional executables are discoverable on PATH. No network scanning is implemented in this phase.

Do not submit real credentials, private keys, or personal data as sample material. Report security issues privately to the project maintainers.
