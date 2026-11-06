"""TShark invocation using fixed, non-extracting field output."""
from pathlib import Path
from ._process import ProcessResult, run_bounded


def analyze_capture(path: Path, *, timeout: float = 30, output_limit: int = 2_000_000) -> ProcessResult:
    fields = ["frame.number", "frame.time_epoch", "frame.protocols", "ip.src", "ip.dst",
              "ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport", "udp.srcport",
              "udp.dstport", "dns.qry.name", "http.request.method", "http.host", "http.request.uri"]
    args = ["-n", "-r", str(path.resolve()), "-T", "fields", "-E", "separator=\t", "-E", "quote=d", "-E", "occurrence=f"]
    for field in fields:
        args.extend(("-e", field))
    return run_bounded("tshark", args, timeout=timeout, output_limit=output_limit)
