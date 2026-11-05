# Architecture

CTFForge uses a `src` package layout. `ctfforge.core` contains reusable infrastructure: CLI wiring, config, logging, platform checks, subprocess handling, evidence, hashing, file identification, strings, output formats, and the tool contract/registry. Challenge logic belongs in independent category packages under `src/ctfforge/` and is imported lazily only when its handler is resolved.

Each category owns its implementation, optional dependencies, documentation, controlled samples, and tests. The core must not import category packages during startup. Optional system programs are discovered with PATH lookup and are never installed or invoked by `doctor`.

Phase 1 provides common hashing, strings, flag detection, environment checks, configuration, and report primitives. Automatic category identification and cross-category orchestration are reserved for the integration phase.

The guided solver foundation lives in core modules for input normalization, flag-format validation, sessions, conservative offline decoders, and recommendations. The CLI loads no category engine yet; its category value is persisted as the solver's priority for future category integrations. Solve sessions are local files under `sessions/` by default.

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
