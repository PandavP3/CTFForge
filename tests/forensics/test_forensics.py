import json
import struct
from io import BytesIO

import pytest

from ctfforge.core.cli import main
from ctfforge.core.exceptions import CTFForgeError
from ctfforge.core.registration import build_core_registry
from ctfforge.core.tool import ToolContext
from ctfforge.forensics.carving import analyze as carve, scan
from ctfforge.forensics.logs import analyze as logs
from ctfforge.forensics.pcap import analyze as pcap, identify_capture


def ctx(tool, **args): return ToolContext("forensics", tool, args)


def pcap_file(records):
    data = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for packet in records:
        data += struct.pack("<IIII", 1, 0, len(packet), len(packet)) + packet
    return data


def frame(src="10.0.0.1", dst="8.8.8.8", proto=17, sport=12345, dport=53, payload=b""):
    srcb, dstb = bytes(map(int, src.split("."))), bytes(map(int, dst.split(".")))
    transport = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload if proto == 17 else struct.pack("!HHIIHHHH", sport, dport, 1, 0, 0x5000, 0, 0, 0) + payload
    ip = bytes([0x45, 0]) + struct.pack("!H", 20 + len(transport)) + b"\0\0\0\0" + bytes([64, proto]) + b"\0\0" + srcb + dstb
    return b"\0" * 12 + b"\x08\x00" + ip + transport


def test_pcap_identification_protocol_distribution_dns_tcp_and_conversation(tmp_path, monkeypatch):
    qname = b"\x07example\x03com\0" + struct.pack("!HH", 1, 1)
    dns = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0" + qname
    raw = pcap_file([frame(payload=dns), frame(proto=6, sport=50000, dport=80, payload=b"GET / HTTP/1.1\r\nHost: test\r\n")])
    file = tmp_path / "sample.pcap"; file.write_bytes(raw)
    monkeypatch.setattr("ctfforge.forensics.pcap.analyze_capture", lambda *a, **k: type("R", (), {"available": False, "returncode": None, "timed_out": False, "output_truncated": False, "error": "missing"})())
    assert identify_capture(raw) == "PCAP"
    result = pcap(ctx("pcap", file=file, backend="auto"))
    summary = result["observations"]
    assert summary["packet_count"] == 2
    assert summary["protocol_distribution"] == {"udp": 1, "tcp": 1}
    assert summary["dns_queries"][0]["name"] == "example.com"
    assert summary["http_requests"][0]["path"] == "/"
    assert summary["conversations"]


def test_pcapng_identification_and_malformed_truncated(tmp_path, monkeypatch):
    shb = b"\x0a\x0d\x0d\x0a" + struct.pack("<I", 28) + b"\x4d\x3c\x2b\x1a" + struct.pack("<HHqI", 1, 0, -1, 28)
    idb = struct.pack("<IIHHII", 1, 20, 1, 0, 65535, 20)
    epb = struct.pack("<IIIIIII", 6, 32, 0, 0, 0, 0, 32)
    raw = shb + idb + epb
    assert identify_capture(raw) == "PCAPNG"
    path = tmp_path / "truncated.pcapng"; path.write_bytes(raw[:-4])
    monkeypatch.setattr("ctfforge.forensics.pcap.analyze_capture", lambda *a, **k: type("R", (), {"available": False, "returncode": None, "timed_out": False, "output_truncated": False, "error": "missing"})())
    result = pcap(ctx("pcap", file=path, backend="native"))
    assert result["observations"]["truncated_or_malformed"]
    bad = tmp_path / "bad.pcap"; bad.write_bytes(b"\xd4\xc3\xb2\xa1short")
    malformed = pcap(ctx("pcap", file=bad, backend="native"))
    assert malformed["observations"]["truncated_or_malformed"]


def test_carving_signatures_boundaries_and_opt_in_recovery(tmp_path):
    jpg = b"\xff\xd8\xffdata\xff\xd9"
    pdf = b"%PDF-1.4\nhello\n%%EOF"
    src = tmp_path / "blob.bin"; src.write_bytes(b"prefix" + jpg + b"middle" + pdf)
    out = tmp_path / "recovered"
    result = carve(ctx("carve", file=src, output_dir=out, backend="native"))
    assert [row["type"] for row in result["candidates"]] == ["jpeg", "pdf"]
    assert result["extracted"] == []
    offsets = [row["offset"] for row in result["candidates"]]
    extracted = carve(ctx("carve", file=src, output_dir=out, extract_offset=offsets, backend="native"))
    assert [row["size"] for row in extracted["extracted"]] == [len(jpg), len(pdf)]
    again = carve(ctx("carve", file=src, output_dir=out, extract_offset=offsets[:1], backend="native"))
    assert again["extracted"][0]["path"] != extracted["extracted"][0]["path"]


def test_carving_png_zip_truncation_and_invalid_offset(tmp_path):
    chunk = lambda kind, body: len(body).to_bytes(4, "big") + kind + body + b"\0\0\0\0"
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IEND", b"")
    zip_data = b"PK\x03\x04" + b"x" * 20 + b"PK\x05\x06" + b"\0" * 18
    src = tmp_path / "mix"; src.write_bytes(png + zip_data + b"%PDF-incomplete")
    result = carve(ctx("carve", file=src, output_dir=tmp_path / "out", backend="native"))
    assert [r["type"] for r in result["candidates"]] == ["png", "zip", "pdf"]
    assert [r["complete"] for r in result["candidates"]] == [True, True, False]
    with pytest.raises(CTFForgeError): carve(ctx("carve", file=src, output_dir=tmp_path / "out", extract_offset=[999], backend="native"))


def test_carving_recovered_file_size_and_count_limits(tmp_path, monkeypatch):
    import ctfforge.forensics.carving as module
    jpeg = b"\xff\xd8\xffx\xff\xd9"
    src = tmp_path / "several.bin"; src.write_bytes(jpeg * 3)
    monkeypatch.setattr(module, "MAX_RECOVERED_SIZE", 5)
    with pytest.raises(CTFForgeError, match="size limit"):
        carve(ctx("carve", file=src, output_dir=tmp_path / "out", extract_offset=[0], backend="native"))
    monkeypatch.setattr(module, "MAX_RECOVERED_SIZE", 100)
    monkeypatch.setattr(module, "MAX_RECOVERED", 1)
    with pytest.raises(CTFForgeError, match="At most"):
        carve(ctx("carve", file=src, output_dir=tmp_path / "out", extract_offset=[0, 6], backend="native"))


def test_logs_auth_http_malformed_order_and_source_preservation(tmp_path):
    lines = [
        "Nov  6 01:00:00 host sshd[10]: Failed password for invalid user bob from 1.2.3.4 port 22 ssh2",
        "Nov  6 01:01:00 host sshd[10]: Failed password for bob from 1.2.3.4 port 22 ssh2",
        "Nov  6 01:02:00 host sshd[10]: Failed password for bob from 1.2.3.4 port 22 ssh2",
        "Nov  6 01:03:00 host sshd[10]: Accepted password for bob from 1.2.3.4 port 22 ssh2",
        '5.6.7.8 - - [06/Nov/2026:12:30:00 +0000] "GET /../../etc/passwd HTTP/1.1" 404 12',
        "this is malformed",
    ]
    path = tmp_path / "auth.log"; path.write_text("\n".join(lines))
    result = logs(ctx("logs", file=path))
    assert result["malformed_line_count"] == 1
    assert result["timeline"][0]["line"] == 1
    assert result["timeline"][0]["source"] == lines[0]
    assert "repeated_authentication_failures" in [row["pattern"] for row in result["findings"]]
    assert "success_after_repeated_failures" in [row["pattern"] for row in result["findings"]]
    assert "suspicious_path" in [row["pattern"] for row in result["findings"]]


def test_log_http_failures_export_csv_and_cli(tmp_path, capsys):
    path = tmp_path / "access.log"
    path.write_text("\n".join(f'1.1.1.1 - - [06/Nov/2026:12:00:{i:02d} +0000] "GET / HTTP/1.1" 500 2' for i in range(6)))
    result = logs(ctx("logs", file=path))
    assert any(row["pattern"] == "repeated_http_errors" for row in result["findings"])
    assert main(["forensics", "logs", "--file", str(path), "--format", "csv"]) == 0
    assert "line,timestamp,source_ip" in capsys.readouterr().out


def test_registration_lazy_and_cli(tmp_path, capsys):
    registry = build_core_registry()
    assert [spec.name for spec in registry.list_tools("forensics")] == ["carve", "logs", "pcap"]
    registry.resolve_handler("forensics", "logs")
    log = tmp_path / "x.log"; log.write_text("not a known log format")
    assert main(["forensics", "logs", "--file", str(log)]) == 0
    assert json.loads(capsys.readouterr().out)["input_line_count"] == 1


def test_tshark_unavailable_and_failure_handling(tmp_path, monkeypatch):
    path = tmp_path / "sample.pcap"; path.write_bytes(pcap_file([]))
    class Result:
        available = False; returncode = None; timed_out = False; output_truncated = False; error = "not installed"
    monkeypatch.setattr("ctfforge.forensics.pcap.analyze_capture", lambda *a, **k: Result())
    with pytest.raises(CTFForgeError, match="not installed"):
        pcap(ctx("pcap", file=path, backend="tshark"))
    assert pcap(ctx("pcap", file=path, backend="auto"))["tshark"]["available"] is False
    Result.available = True; Result.returncode = 2; Result.error = None
    with pytest.raises(CTFForgeError, match="status 2"):
        pcap(ctx("pcap", file=path, backend="tshark"))
