"""Evidence-driven, offline-first solve flow for the first CTFForge solver slice."""

import hashlib
import re
from pathlib import Path
from typing import Any

from .encoding import detect_decodings, hash_kind
from .evidence import Evidence
from .exceptions import CTFForgeError
from .file_detection import identify_file
from .flag_format import compile_flag_pattern, find_flags
from .hashing import hash_file
from .output import make_result, write_report
from .recommendations import CYBERCHEF_URL
from .sessions import SessionStore
from .solver_input import SolverInput

MAX_DECODE_STEPS = 12
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024


def _text(data: bytes) -> str:
    return data.decode("utf-8", errors="ignore")


def _analyze_payload(state: dict[str, Any], store: SessionStore, data: bytes, label: str) -> None:
    pattern = compile_flag_pattern(state["flag_format"], state.get("flag_prefix"))
    seen_payloads = {hashlib.sha256(data).hexdigest()}
    queue: list[tuple[bytes, str]] = [(data, label)]
    steps = 0
    while queue and steps < MAX_DECODE_STEPS:
        current, current_label = queue.pop(0)
        decoded_text = _text(current)
        for flag in find_flags(decoded_text, pattern):
            if flag not in state["flags"]:
                state["flags"].append(flag)
        candidates = detect_decodings(current[:MAX_ARTIFACT_BYTES])
        if candidates:
            candidate = candidates[0]
            digest = hashlib.sha256(candidate.output).hexdigest()
            if digest not in seen_payloads:
                seen_payloads.add(digest)
                steps += 1
                artifact_rel = f"decoded/{steps:02d}-{candidate.name}.bin"
                store.add_artifact(state["session_id"], artifact_rel, candidate.output, kind="decoded")
                operation = {
                    "input": current_label, "operation": candidate.operation,
                    "detected": candidate.name, "confidence": candidate.confidence,
                    "output": artifact_rel, "sha256": digest,
                }
                state["operations"].append(operation)
                state["artifacts"].append(artifact_rel)
                state["evidence"].append(Evidence(
                    description=f"Detected and locally decoded {candidate.name}",
                    source=current_label,
                    value={"confidence": candidate.confidence, "output": artifact_rel},
                ).to_dict())
                queue.append((candidate.output, artifact_rel))
    if state["flags"]:
        state["status"] = "SOLVED"
        state["blocked_operations"] = []
    elif steps:
        state["status"] = "PARTIALLY_SOLVED"


def solve(artifact: SolverInput, category: str, flag_format: str, *, flag_prefix: str | None = None,
          sessions_root: Path | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    compile_flag_pattern(flag_format, flag_prefix)
    store = SessionStore(sessions_root)
    state = store.create(artifact, category, flag_format)
    state["flag_prefix"] = flag_prefix
    original = artifact.data
    original_path = store.directory(state["session_id"]) / state["original_file"]
    state["file_type"] = identify_file(original_path)
    state["hashes"] = hash_file(original_path)
    state["evidence"] = [Evidence(
        description="Input identified and hashed", source=artifact.source,
        value={"file_type": state["file_type"], "hashes": state["hashes"]},
    ).to_dict()]
    _analyze_payload(state, store, original, artifact.name)
    if not state["flags"]:
        kind = hash_kind(_text(original).strip())
        if kind:
            state["status"] = "BLOCKED"
            state["blocked_operations"].append({"operation": "hash recovery", "detected": kind,
                                                 "reason": "A cryptographic hash cannot be reversed by decoding."})
            state["recommendations"].append({"next_step": "Use a challenge-provided clue or an authorized local wordlist; no crack was attempted."})
        elif state["status"] != "PARTIALLY_SOLVED":
            state["status"] = "UNSOLVED"
            if re.search(r"[A-Za-z0-9+/]{12,}={0,2}", _text(original)):
                state["status"] = "BLOCKED"
                state["recommendations"].append({"tool": "CyberChef", "operation": "From Base64",
                                                  "url": CYBERCHEF_URL,
                                                  "reason": "No confident local decoding produced a valid flag."})
                state["blocked_operations"].append({"operation": "manual encoding review",
                                                     "detected": "possible Base64", "confidence": 60,
                                                     "input": _text(original).strip(),
                                                     "reason": "The local decoder did not validate a useful output."})
    store.save(state["session_id"], state)
    result = _result(state, artifact.name)
    _write_session_report(store, state, result)
    return state, result


def continue_session(session_id: str, result_text: str, *, sessions_root: Path | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    store = SessionStore(sessions_root)
    state = store.load(session_id)
    if not result_text:
        raise CTFForgeError("Continuation result cannot be empty.")
    result_path = store.add_artifact(session_id, f"evidence/user-result-{len(state['user_results']) + 1:02d}.txt",
                                    result_text.encode("utf-8"), kind="user_result")
    state["user_results"].append({"path": str(result_path.relative_to(store.directory(session_id))),
                                  "length": len(result_text)})
    state["operations"].append({"operation": "user-supplied continuation", "output": str(result_path.name)})
    _analyze_payload(state, store, result_text.encode("utf-8"), str(result_path.name))
    if not state["flags"] and state["status"] != "PARTIALLY_SOLVED":
        state["status"] = "UNSOLVED"
    store.save(session_id, state)
    result = _result(state, state["original_file"])
    _write_session_report(store, state, result)
    return state, result


def _result(state: dict[str, Any], target: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    if state["flags"]:
        findings.extend({"type": "validated_flag", "value": flag} for flag in state["flags"])
    for operation in state["operations"]:
        findings.append({"type": "transformation", **operation})
    if state["status"] == "BLOCKED":
        if any(item.get("detected") == "MD5" or item.get("detected") == "SHA1" or item.get("detected") == "SHA256"
               for item in state["blocked_operations"]):
            guidance = "The artifact looks like a hash. Decoding cannot reverse it; check challenge clues or an authorized local wordlist."
        else:
            guidance = "Local analysis did not validate a transformation. Follow the operation recommendation, then return its output with `ctfforge continue`."
    elif state["status"] == "PARTIALLY_SOLVED":
        guidance = "Local transformations produced evidence, but none matched the required flag format. Inspect the decoded artifacts or continue with a new result."
    elif state["status"] == "UNSOLVED":
        guidance = "No locally supported transformation produced a flag. Add challenge clues or provide a result with `ctfforge continue`."
    else:
        guidance = ""
    result = make_result(state["category"], str(target), findings=findings, evidence=state.get("evidence", []),
                         artifacts=state.get("artifacts", []), confidence=99 if state["flags"] else 0,
                         recommendations=state.get("recommendations", []), possible_flags=state["flags"],
                         status=state["status"], flag_format=state["flag_format"],
                         session_id=state["session_id"], blocked_operations=state["blocked_operations"],
                         next_step=guidance)
    return result


def _write_session_report(store: SessionStore, state: dict[str, Any], result: dict[str, Any]) -> None:
    report_path = store.directory(state["session_id"]) / "reports" / "report.json"
    write_report(result, "json", report_path)
    state["report"] = str(report_path.relative_to(store.directory(state["session_id"])))
    store.save(state["session_id"], state)
