"""Lazy registration for web analysis tools."""

from ctfforge.core.registry import ToolRegistry
from ctfforge.core.tool import ToolSpec


def register_web_tools(registry: ToolRegistry) -> None:
    registry.register_category("web", (
        ToolSpec("jwt", "web", "Decode and statically inspect JWT structure and claims.", "ctfforge.web.jwt_analyzer:analyze", usage="ctfforge web jwt --token TOKEN", help="Decoding does not authenticate a JWT; signatures are never verified."),
        ToolSpec("headers", "web", "Review HTTP security response headers.", "ctfforge.web.headers:analyze", usage="ctfforge web headers (--url URL | --header HEADER)", help="Fetches headers only when --url is supplied; absence alone does not prove vulnerability."),
        ToolSpec("cookies", "web", "Review cookie flags, scope, and lifetime.", "ctfforge.web.cookies:analyze", usage="ctfforge web cookies (--url URL | --header 'Set-Cookie: ...')", help="Cookie values are redacted by default."),
        ToolSpec("cors", "web", "Review CORS response policy headers.", "ctfforge.web.cors:analyze", usage="ctfforge web cors (--url URL | --header HEADER)", help="Uses a controlled OPTIONS request when fetching; findings indicate risk, not exploitability."),
        ToolSpec("url", "web", "Parse and inspect a URL without visiting it.", "ctfforge.web.url_analyzer:analyze", usage="ctfforge web url --input URL"),
        ToolSpec("discover", "web", "Perform bounded HTTP path discovery against an authorized target.", "ctfforge.web.directory_discovery:analyze", usage="ctfforge web discover --url URL --wordlist FILE", help="Only run against explicitly authorized targets. No recursion, exploitation, or cross-host redirect following."),
    ))
