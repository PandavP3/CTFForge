"""Bounded, offline PCAP/PCAPNG summaries with an explicit protocol scope."""
import ipaddress
import struct
import csv
import io
from collections import Counter
from pathlib import Path

from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.output import make_result
from ctfforge.core.tool import ToolContext, ToolResult
from ctfforge.integrations.tshark import analyze_capture

MAX_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_PACKETS = 100_000


def identify_capture(data: bytes) -> str:
    if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return "PCAP"
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        return "PCAPNG"
    return "unknown"


def _pcap_packets(data: bytes):
    magic = data[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    if len(data) < 24: raise ValueError("truncated PCAP global header")
    major, minor, _, _, snaplen, linktype = struct.unpack_from(endian + "HHiIII", data, 4)
    if major != 2 or snaplen < 1 or snaplen > MAX_CAPTURE_BYTES: raise ValueError("invalid PCAP header")
    offset, count, truncated = 24, 0, False
    while offset < len(data) and count < MAX_PACKETS:
        if offset + 16 > len(data): raise ValueError("truncated PCAP packet header")
        sec, frac, included, original = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if included > snaplen or included > MAX_CAPTURE_BYTES: raise ValueError("invalid PCAP packet length")
        end = offset + included
        if end > len(data): raise ValueError("truncated PCAP packet")
        ts = sec + frac / (1_000_000_000 if nano else 1_000_000)
        yield ts, linktype, data[offset:end]
        count += 1; offset = end
        if original < included: raise ValueError("captured packet shorter than original length")
    return


def _pcapng_packets(data: bytes):
    offset, endian, links, count, truncated = 0, None, [], 0, False
    while offset + 12 <= len(data) and count < MAX_PACKETS:
        block_type = data[offset:offset + 4]
        if block_type == b"\x0a\x0d\x0d\x0a":
            if offset + 12 > len(data): raise ValueError("truncated PCAPNG section header")
            bom = data[offset + 8:offset + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">" if bom == b"\x1a\x2b\x3c\x4d" else None
            if endian is None: raise ValueError("invalid PCAPNG byte-order magic")
            length = struct.unpack_from(endian + "I", data, offset + 4)[0]
        elif endian:
            length = struct.unpack_from(endian + "I", data, offset + 4)[0]
        else:
            raise ValueError("PCAPNG block has no section header")
        if length < 12 or length % 4 or offset + length > len(data): raise ValueError("invalid or truncated PCAPNG block")
        if struct.unpack_from(endian + "I", data, offset + length - 4)[0] != length:
            raise ValueError("PCAPNG block length trailer does not match")
        if block_type == b"\x0a\x0d\x0d\x0a": links = []
        elif block_type == (struct.pack(endian + "I", 1)) and length >= 20:
            links.append(struct.unpack_from(endian + "H", data, offset + 8)[0])
        elif block_type == struct.pack(endian + "I", 6) and length >= 32:
            iface, hi, lo, caplen = struct.unpack_from(endian + "IIII", data, offset + 8)
            start = offset + 28; end = start + caplen
            if end > offset + length - 4: raise ValueError("truncated PCAPNG packet data")
            ts = ((hi << 32) | lo) / 1_000_000
            yield ts, links[iface] if iface < len(links) else 1, data[start:end]
            count += 1
        offset += length


def _decode_frame(frame: bytes, linktype: int):
    if linktype != 1 or len(frame) < 14: return None
    etype, pos = struct.unpack_from("!H", frame, 12)[0], 14
    while etype in (0x8100, 0x88a8) and len(frame) >= pos + 4:
        etype = struct.unpack_from("!H", frame, pos + 2)[0]; pos += 4
    if etype == 0x0800:
        if len(frame) < pos + 20: return None
        ihl = (frame[pos] & 15) * 4
        if ihl < 20 or len(frame) < pos + ihl: return None
        proto = frame[pos + 9]
        src = str(ipaddress.ip_address(frame[pos + 12:pos + 16])); dst = str(ipaddress.ip_address(frame[pos + 16:pos + 20]))
        pos += ihl
    elif etype == 0x86dd:
        if len(frame) < pos + 40: return None
        proto = frame[pos + 6]
        src = str(ipaddress.ip_address(frame[pos + 8:pos + 24])); dst = str(ipaddress.ip_address(frame[pos + 24:pos + 40]))
        pos += 40
    else: return {"protocol": "other", "src": None, "dst": None, "sport": None, "dport": None, "payload": b""}
    protocol = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}.get(proto, "other")
    sport = dport = None
    tcp_flags = None
    if protocol in ("tcp", "udp") and len(frame) >= pos + 4:
        sport, dport = struct.unpack_from("!HH", frame, pos)
        if protocol == "tcp" and len(frame) >= pos + 14:
            tcp_flags = frame[pos + 13]
        pos += (frame[pos + 12] >> 4) * 4 if protocol == "tcp" and len(frame) >= pos + 13 else 8
    return {"protocol": protocol, "src": src, "dst": dst, "sport": sport, "dport": dport,
            "tcp_flags": tcp_flags, "payload": frame[pos:]}


def _dns_name(payload: bytes, offset: int):
    labels, pos, depth = [], offset, 0
    while pos < len(payload) and depth < 20:
        size = payload[pos]; pos += 1
        if size == 0: break
        if size & 0xc0 or size > 63 or pos + size > len(payload): return None
        labels.append(payload[pos:pos + size].decode("ascii", "replace")); pos += size; depth += 1
    return ".".join(labels) if labels else None


def _native(data: bytes, kind: str):
    iterator = _pcap_packets(data) if kind == "PCAP" else _pcapng_packets(data)
    protocols, sources, destinations, conversations = Counter(), Counter(), Counter(), Counter()
    dns, http, times, ports, syn_attempts = [], [], [], Counter(), Counter()
    truncated = False
    try:
        for timestamp, linktype, frame in iterator:
            if len(times) >= MAX_PACKETS: break
            times.append(timestamp)
            packet = _decode_frame(frame, linktype)
            if not packet: protocols["unparsed"] += 1; continue
            proto = packet["protocol"]; protocols[proto] += 1
            src, dst, sport, dport = packet["src"], packet["dst"], packet["sport"], packet["dport"]
            if src: sources[src] += 1
            if dst: destinations[dst] += 1
            if sport is not None:
                ports[sport] += 1; ports[dport] += 1
                key = (proto, min((src, sport), (dst, dport)), max((src, sport), (dst, dport)))
                conversations[key] += 1
                if proto == "tcp" and packet["tcp_flags"] is not None and packet["tcp_flags"] & 0x02 and not packet["tcp_flags"] & 0x10:
                    syn_attempts[(src, dst, dport)] += 1
            payload = packet["payload"]
            if proto == "udp" and (sport == 53 or dport == 53) and len(payload) >= 12:
                qd = struct.unpack_from("!H", payload, 4)[0]
                name = _dns_name(payload, 12) if qd else None
                if name: dns.append({"name": name, "source": src, "destination": dst, "timestamp": timestamp})
            if proto == "tcp" and (sport in (80, 8080, 8000) or dport in (80, 8080, 8000)):
                line = payload.split(b"\r\n", 1)[0].decode("latin-1", "replace")
                parts = line.split()
                if len(parts) >= 3 and parts[0] in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"):
                    http.append({"method": parts[0], "path": parts[1][:2048], "host": None, "source": src, "destination": dst})
    except (ValueError, struct.error): truncated = True
    rows = [{"protocol": key[0], "endpoint_a": key[1], "endpoint_b": key[2], "packets": count}
            for key, count in conversations.most_common(1000)]
    findings = []
    unusual = {p: count for p, count in ports.items() if p > 1024 and count >= 20}
    if unusual: findings.append({"severity": "info", "observation": "Repeated activity on high-numbered ports.", "ports": unusual})
    repeated = [row for row in rows if row["packets"] >= 25]
    if repeated: findings.append({"severity": "info", "observation": "Repeated packets in one conversation; could be normal application traffic.", "conversations": len(repeated)})
    attempted = [{"source": src, "destination": dst, "destination_port": port, "syn_packets": count}
                 for (src, dst, port), count in syn_attempts.items() if count >= 10]
    if attempted:
        findings.append({"severity": "info", "observation": "Repeated TCP connection initiation packets observed; this may be normal retry behavior.", "connections": attempted[:100]})
    return {"packet_count": len(times), "protocol_distribution": dict(protocols), "source_ips": sources.most_common(100),
            "destination_ips": destinations.most_common(100), "conversations": rows, "dns_queries": dns[:10000],
            "http_requests": http[:10000], "capture_start": min(times) if times else None,
            "capture_end": max(times) if times else None, "truncated_or_malformed": truncated, "findings": findings}


def _tshark_fields(output: str):
    protocols, sources, destinations, conversations = Counter(), Counter(), Counter()
    dns, http, times = [], [], []
    reader = csv.reader(io.StringIO(output), delimiter="\t", quotechar='"')
    for fields in reader:
        fields += [""] * (15 - len(fields))
        _, timestamp, proto_text, ip_src, ip_dst, ip6_src, ip6_dst, tcp_src, tcp_dst, udp_src, udp_dst, query, method, host, uri = fields[:15]
        try:
            if timestamp: times.append(float(timestamp))
        except ValueError:
            pass
        source, destination = ip_src or ip6_src, ip_dst or ip6_dst
        for proto in filter(None, proto_text.split(":")):
            protocols[proto] += 1
        if source: sources[source] += 1
        if destination: destinations[destination] += 1
        sport, dport = tcp_src or udp_src, tcp_dst or udp_dst
        transport = "tcp" if tcp_src or tcp_dst else "udp" if udp_src or udp_dst else None
        if source and destination and sport and dport and transport:
            a, b = (source, int(sport)), (destination, int(dport))
            conversations[(transport, min(a, b), max(a, b))] += 1
        if query: dns.append({"name": query, "timestamp": timestamp or None})
        if method: http.append({"method": method, "host": host or None, "path": uri or None})
    return {"packet_count": sum(1 for _ in csv.reader(io.StringIO(output), delimiter="\t")),
            "protocol_distribution": dict(protocols), "source_ips": sources.most_common(100),
            "destination_ips": destinations.most_common(100),
            "conversations": [{"protocol": key[0], "endpoint_a": key[1], "endpoint_b": key[2], "packets": n}
                              for key, n in conversations.most_common(1000)],
            "dns_queries": dns[:10000], "http_requests": http[:10000],
            "capture_start": min(times) if times else None, "capture_end": max(times) if times else None,
            "truncated_or_malformed": False, "findings": []}


def analyze(context: ToolContext) -> ToolResult:
    args = context.arguments; path = Path(args["file"]).expanduser()
    try:
        with path.open("rb") as stream: data = stream.read(MAX_CAPTURE_BYTES + 1)
    except OSError as exc: raise CTFForgeError(f"Cannot read capture: {exc}") from exc
    if len(data) > MAX_CAPTURE_BYTES: raise CTFForgeError(f"Capture exceeds {MAX_CAPTURE_BYTES} byte limit.")
    kind = identify_capture(data)
    if kind == "unknown": raise CTFForgeError("Input is not a recognized PCAP or PCAPNG capture.")
    backend = args.get("backend", "auto")
    tshark_status = None
    tshark_summary = None
    if backend in ("auto", "tshark"):
        external = analyze_capture(path)
        tshark_status = {"available": external.available, "returncode": external.returncode,
                         "timed_out": external.timed_out, "output_truncated": external.output_truncated,
                         "error": external.error}
        if backend == "tshark" and not external.available: raise CTFForgeError(external.error or "TShark unavailable.")
        if external.available and external.returncode == 0 and not external.timed_out:
            tshark_summary = _tshark_fields(external.stdout)
        elif backend == "tshark":
            raise CTFForgeError(external.error or f"TShark exited with status {external.returncode}.")
    summary = _native(data, kind)
    if backend in ("tshark", "auto") and tshark_summary is not None:
        summary = tshark_summary
    return make_result("forensics", str(path), tool="pcap", capture_format=kind, backend="native",
                       native_scope=["Ethernet", "IPv4", "IPv6", "TCP", "UDP", "basic DNS", "HTTP request line metadata"],
                       tshark=tshark_status, observations=summary,
                       limitation="Native analysis is a limited protocol summary, not full dissection. Indicators are observations, not security conclusions.",
                       recommendations=["Retain the original capture unchanged; validate important observations with an independently configured dissector."])
