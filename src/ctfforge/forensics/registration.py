"""Lazy registration for digital forensics tools."""
from ctfforge.core.registry import ToolRegistry
from ctfforge.core.tool import InteractiveInput as I, ToolSpec


def register_forensics_tools(registry: ToolRegistry) -> None:
    registry.register_category("forensics", (
        ToolSpec("pcap", "forensics", "Summarize PCAP/PCAPNG captures and optionally use TShark.",
                 "ctfforge.forensics.pcap:analyze", usage="ctfforge forensics pcap --file CAPTURE [--backend native|tshark|auto]",
                 help="Native decoder covers Ethernet, IPv4/IPv6, TCP, UDP, basic DNS and HTTP metadata only.",
                 interactive_inputs=(I("file", "PCAP or PCAPNG capture path", "path", must_exist=True),
                                     I("backend", "Analysis backend", choices=("auto", "native", "tshark"), default="auto"),
                                     I("format", "Output format", choices=("json", "csv"), default="json"))),
        ToolSpec("carve", "forensics", "Identify and selectively recover bounded JPEG, PNG, PDF, and ZIP candidates.",
                 "ctfforge.forensics.carving:analyze", usage="ctfforge forensics carve --file IMAGE --output-dir DIR [--extract-offset OFFSET]",
                 help="Extraction is opt-in by candidate offset. Binwalk integration scans signatures only; it never extracts.",
                 interactive_inputs=(I("file", "Source file path", "path", must_exist=True),
                                     I("output_dir", "Output directory for selected recovered files", "path"),
                                     I("extract_offset", "Candidate offset to recover (blank to finish and scan only)", "int", required=False, multiple=True, minimum=0),
                                     I("backend", "Analysis backend", choices=("auto", "native", "binwalk"), default="auto"))),
        ToolSpec("logs", "forensics", "Parse common authentication, syslog, Apache, and Nginx logs.",
                 "ctfforge.forensics.logs:analyze", usage="ctfforge forensics logs --file LOG [--format json|csv]",
                 help="Patterns are investigative indicators, not conclusions; source lines are preserved.",
                 interactive_inputs=(I("file", "Log file path", "path", must_exist=True),
                                     I("format", "Output format", choices=("json", "csv"), default="json"))),
    ))
