"""Persistent, local solve-session storage."""

import json
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .exceptions import CTFForgeError
from .solver_input import SolverInput


class SessionStore:
    def __init__(self, root: Path | None = None):
        self.root = root or Path.cwd() / "sessions"

    def create(self, artifact: SolverInput, category: str, flag_format: str) -> dict[str, Any]:
        stamp = datetime.now().astimezone().strftime("%Y-%m-%d_%H%M%S")
        session_id = f"{stamp}_{uuid.uuid4().hex[:6]}"
        directory = self.root / session_id
        for name in ("input", "evidence", "extracted", "decoded", "reports"):
            (directory / name).mkdir(parents=True, exist_ok=True)
        input_name = Path(artifact.name).name or "stdin.bin"
        input_path = directory / "input" / input_name
        input_path.write_bytes(artifact.data)
        state: dict[str, Any] = {
            "session_id": session_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "UNSOLVED",
            "original_file": str(input_path.relative_to(directory)),
            "source": artifact.source,
            "category": category,
            "flag_format": flag_format,
            "operations": [],
            "artifacts": [],
            "blocked_operations": [],
            "recommendations": [],
            "user_results": [],
            "flags": [],
        }
        self.save(session_id, state)
        return state

    def load(self, session_id: str) -> dict[str, Any]:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", session_id):
            raise CTFForgeError("Invalid session ID.")
        path = self.root / session_id / "session.json"
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise CTFForgeError(f"Session not found: {session_id}") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise CTFForgeError(f"Cannot load session {session_id}: {exc}") from exc
        if state.get("session_id") != session_id:
            raise CTFForgeError("Session metadata does not match its directory.")
        return state

    def save(self, session_id: str, state: dict[str, Any]) -> None:
        directory = self.root / session_id
        directory.mkdir(parents=True, exist_ok=True)
        destination = directory / "session.json"
        temporary = directory / "session.json.tmp"
        temporary.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
        temporary.replace(destination)

    def directory(self, session_id: str) -> Path:
        self.load(session_id)
        return self.root / session_id

    def add_artifact(self, session_id: str, relative_path: str, content: bytes, *, kind: str) -> Path:
        directory = self.directory(session_id)
        target = (directory / relative_path).resolve()
        if directory.resolve() not in target.parents:
            raise CTFForgeError("Artifact path escapes its solve session.")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return target
