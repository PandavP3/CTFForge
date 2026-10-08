# Architecture

CTFForge uses a `src` package layout. `ctfforge.core` contains only reusable infrastructure: CLI wiring, config, logging, platform checks, safe subprocess handling, evidence, hashing, file identification, strings, and output formats. Challenge logic belongs in independent category packages under `src/ctfforge/` and must be imported lazily by its own CLI route.

Each category owns its implementation, optional dependencies, documentation, controlled samples, and tests. The core must not import category packages during startup. Optional system programs are discovered with PATH lookup and are never installed or invoked by `doctor`.

Phase 1 provides common hashing, strings, flag detection, environment checks, configuration, and report primitives. Automatic category identification and cross-category orchestration are reserved for the integration phase.

The guided solver foundation lives in core modules for input normalization, flag-format validation, sessions, conservative offline decoders, and recommendations. The CLI loads no category engine yet; its category value is persisted as the solver's priority for future category integrations. Solve sessions are local files under `sessions/` by default.
