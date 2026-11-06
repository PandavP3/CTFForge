"""Evidence-preserving parsers and heuristic timelines for common logs."""
import csv
import io
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult

AUTH = re.compile(r"(?P<result>Failed|Accepted)\s+(?P<method>\S+)\s+for\s+(?:(?:invalid user)\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[\da-fA-F:.]+)", re.I)
SYSLOG = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+(?P<message>.*)$")
APACHE = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^]]+)\] "(?P<request>[^\"]*)" (?P<status>\d{3}) (?P<size>\S+)')


def _timestamp(text: str, apache: bool = False):
    try:
        if apache:
            return datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z")
        return datetime.strptime(text + " 2000", "%b %d %H:%M:%S %Y")
    except ValueError:
        return None


def analyze(context: ToolContext) -> ToolResult:
    path = Path(context.arguments["file"]).expanduser()
    try: lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc: raise CTFForgeError(f"Cannot read log: {exc}") from exc
    events, malformed = [], 0
    for lineno, source in enumerate(lines, 1):
        event = {"line": lineno, "timestamp": None, "source_ip": None, "username": None,
                 "event_type": "unclassified", "status": None, "path": None, "source": source}
        auth = AUTH.search(source)
        access = APACHE.match(source)
        syslog = SYSLOG.match(source)
        if auth:
            event.update(event_type="authentication", status=auth.group("result").lower(),
                         username=auth.group("user"), source_ip=auth.group("ip"))
            if syslog: event["timestamp"] = syslog.group("ts")
        elif access:
            parts = access.group("request").split()
            event.update(event_type="http_access", status=int(access.group("status")), source_ip=access.group("ip"),
                         timestamp=access.group("ts"), path=parts[1] if len(parts) > 1 else None)
        elif syslog:
            event.update(event_type="syslog", timestamp=syslog.group("ts"))
            if any(word in syslog.group("message").lower() for word in ("error", "failed", "denied")):
                event["status"] = "error"
        else:
            malformed += 1
        ts = event["timestamp"]
        parsed = _timestamp(ts, apache=True) if ts and "/" in ts else _timestamp(ts) if ts else None
        event["epoch"] = parsed.timestamp() if parsed and parsed.tzinfo else parsed.replace(year=2000).timestamp() if parsed else None
        event["_hour"] = parsed.hour if parsed else None
        events.append(event)
    events.sort(key=lambda e: (e["epoch"] is None, e["epoch"] or 0, e["line"]))
    findings = []
    auth_groups = defaultdict(list)
    for event in events:
        if event["event_type"] == "authentication" and event["source_ip"]:
            auth_groups[(event["source_ip"], event["username"])].append(event)
    for (ip, user), records in auth_groups.items():
        failures = [e for e in records if e["status"] == "failed"]
        if len(failures) >= 3:
            findings.append({"severity": "medium", "pattern": "repeated_authentication_failures", "source_ip": ip,
                             "username": user, "lines": [e["line"] for e in failures]})
            success = next((e for e in records if e["status"] == "accepted" and e["line"] > failures[-1]["line"]), None)
            if success:
                findings.append({"severity": "high", "pattern": "success_after_repeated_failures", "source_ip": ip,
                                 "username": user, "line": success["line"]})
    http_by_ip, error_by_ip = Counter(), Counter()
    for event in events:
        if event["event_type"] != "http_access": continue
        http_by_ip[event["source_ip"]] += 1
        code = event["status"]
        if code >= 400:
            error_by_ip[(event["source_ip"], code)] += 1
        if event["path"] and re.search(r"(?:\.\./|/\.git|/wp-login|/admin|/etc/passwd)", event["path"], re.I):
            findings.append({"severity": "info", "pattern": "suspicious_path", "line": event["line"], "path": event["path"], "source_ip": event["source_ip"]})
        parsed = event["_hour"]
        if parsed is not None and (parsed < 6 or parsed >= 22):
            findings.append({"severity": "info", "pattern": "outside_common_hours", "line": event["line"], "source_ip": event["source_ip"]})
    for (ip, code), count in error_by_ip.items():
        if count >= 5: findings.append({"severity": "info", "pattern": "repeated_http_errors", "source_ip": ip, "status": code, "count": count})
    for ip, count in http_by_ip.items():
        if count >= 20: findings.append({"severity": "info", "pattern": "multiple_http_events", "source_ip": ip, "count": count})
    for event in events:
        event.pop("epoch", None)
        event.pop("_hour", None)
    return make_result("forensics", str(path), tool="logs", timeline=events, findings=findings,
                       malformed_line_count=malformed, input_line_count=len(lines),
                       evidence_note="Original source lines and 1-based line references are preserved. Findings are investigative patterns, not conclusions.")
