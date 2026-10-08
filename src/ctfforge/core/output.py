"""Common result schema and JSON, CSV, Markdown, and HTML writers."""

import csv
import html
import json
from pathlib import Path
from typing import Any


def make_result(category: str, target: str, **values: Any) -> dict[str, Any]:
    result = {"category": category, "target": target, "evidence": [], "findings": [],
              "artifacts": [], "indicators": [], "confidence": 0, "recommendations": [],
              "tools_used": [], "possible_flags": []}
    result.update(values)
    return result


def render_report(result: dict[str, Any], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(result, indent=2, ensure_ascii=False)
    if fmt == "csv":
        import io
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=("category", "target", "confidence", "findings", "recommendations"))
        writer.writeheader()
        row = dict(result)
        row["findings"] = json.dumps(row.get("findings", []), ensure_ascii=False)
        row["recommendations"] = json.dumps(row.get("recommendations", []), ensure_ascii=False)
        writer.writerow({key: row.get(key) for key in writer.fieldnames})
        return buffer.getvalue()
    if fmt == "markdown":
        return (f"# CTFForge report: {result.get('target', '')}\n\n"
                f"- Category: {result.get('category', '')}\n- Confidence: {result.get('confidence', 0)}\n\n"
                f"## Findings\n\n" + _list_items(result.get("findings", [])) + "\n## Recommendations\n\n"
                + _list_items(result.get("recommendations", [])))
    if fmt == "html":
        body = html.escape(json.dumps(result, indent=2, ensure_ascii=False))
        return f"<!doctype html><meta charset='utf-8'><title>CTFForge report</title><pre>{body}</pre>\n"
    raise ValueError(f"Unsupported report format: {fmt}")


def _list_items(items: list[Any]) -> str:
    return "\n".join(f"- {item}" for item in items) if items else "- None"


def write_report(result: dict[str, Any], fmt: str, destination: Path) -> None:
    destination.write_text(render_report(result, fmt), encoding="utf-8")
