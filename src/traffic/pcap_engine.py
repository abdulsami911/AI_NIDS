"""TShark-backed IP flow extraction for AI-NIDS.

TCP opening flags and DNS headers identify the initiator when available at flow
creation. Other flows use first-observed direction. IP octets are measured at
the network layer; dashboard byte totals use the original frame lengths.
"""
from __future__ import annotations

import csv
from decimal import Decimal, InvalidOperation
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

LEGACY_FEATURES = (
    "proto", "dur", "spkts", "dpkts",
    "sinpkt", "dinpkt", "is_sm_ips_ports",
)
FEATURES = (*LEGACY_FEATURES, "service")
IP_FEATURES = (*FEATURES, "sbytes", "dbytes")
SCHEMAS = {
    "pcap_7f_v1": LEGACY_FEATURES,
    "pcap_8f_experimental": FEATURES,
    "pcap_ip_bytes_v1": IP_FEATURES,
}
SERVICES = {s: s for s in ("dns", "http", "smtp", "ftp", "ftp-data", "ssh",
                            "pop3", "dhcp", "snmp", "irc", "radius")}
SERVICES.update({"tls": "ssl", "ssl": "ssl", "pop": "pop3", "bootp": "dhcp",
                 "quic": "quic", "gquic": "quic"})
TSHARK_FIELDS = (
    "frame.number", "frame.time_epoch", "frame.len", "ip.src", "ip.dst",
    "ipv6.src", "ipv6.dst", "ip.proto", "ipv6.nxt", "tcp.srcport",
    "tcp.dstport", "udp.srcport", "udp.dstport", "icmp.type", "icmpv6.type",
    "tcp.flags.fin", "tcp.flags.reset", "tcp.flags.ack", "tcp.flags.syn", "dns.flags.response",
    "_ws.col.Protocol",
    "frame.protocols", "ip.len", "ipv6.plen", "ip.flags.mf", "ip.frag_offset",
    "ipv6.fraghdr.offset", "frame.interface_id", "vlan.id", "tcp.stream", "udp.stream",
)


def _first(value: str) -> str:
    """First occurrence is outer-layer protocol when tshark decodes nested frames."""
    return (value or "").split(",", 1)[0].strip()


def transport_of(r: dict) -> str | None:
    # ip.proto/ipv6.nxt distinguish real transport from quoted headers in ICMP errors.
    if _first(r.get("icmp.type", "")) or _first(r.get("icmpv6.type", "")):
        return None
    stack = r.get("frame.protocols", "").split(":")
    if r.get("frame.protocols"):
        if stack.count("ip") + stack.count("ipv6") != 1:
            return None
        if (r.get("ip.flags.mf") in ("1", "True") or int(r.get("ip.frag_offset") or 0)
                or r.get("ipv6.fraghdr.offset")):
            return None
        return next((p for p in stack if p in ("tcp", "udp")), None)
    top = _first(r.get("ip.proto", "")) or _first(r.get("ipv6.nxt", ""))
    if top == "6":
        return "tcp"
    if top == "17":
        return "udp"
    if top:  # ICMP, IPv6 extension header, other transport: currently unsupported
        return None
    display = _first(r.get("_ws.col.Protocol", "")).upper()
    if display in ("ICMP", "ICMPV6", "ARP"):
        return None
    if r.get("tcp.srcport") and r.get("tcp.dstport"):
        return "tcp"
    if r.get("udp.srcport") and r.get("udp.dstport"):
        return "udp"
    return None


def _avg_ms(times: list[Decimal]) -> float:
    if len(times) <= 1:
        return 0.0
    return float(((max(times) - min(times)) / Decimal(len(times) - 1)) * 1000)


def build_from_rows(rows, idle_timeout=60, max_duration=60):
    """Return (flows, packets, summary). Works with iterable tshark field dictionaries."""
    active = {}
    flows = []
    packet_map = []
    total_frames = 0
    unsupported = 0
    idle = Decimal(str(idle_timeout))
    max_age = Decimal(str(max_duration))

    for r in rows:
        total_frames += 1
        proto = transport_of(r)
        src = _first(r.get("ip.src", "")) or _first(r.get("ipv6.src", ""))
        dst = _first(r.get("ip.dst", "")) or _first(r.get("ipv6.dst", ""))
        if not src or not dst or proto not in ("tcp", "udp"):
            unsupported += 1
            continue
        if ("ip.len" in r and int(r.get("ip.len") or 0) < 20
                and int(r.get("ipv6.plen") or 0) <= 0):
            unsupported += 1
            continue
        prefix = "tcp" if proto == "tcp" else "udp"
        sport = _first(r.get(prefix + ".srcport", ""))
        dport = _first(r.get(prefix + ".dstport", ""))
        if not sport or not dport:
            unsupported += 1
            continue
        try:
            frame = int(r["frame.number"])
            timestamp = Decimal(_first(r["frame.time_epoch"]))
            size = int(_first(r["frame.len"]))
        except (KeyError, ValueError, InvalidOperation) as exc:
            raise ValueError(f"Invalid packet metadata in frame {r.get('frame.number')}") from exc
        if size < 0 or not timestamp.is_finite():
            raise ValueError(f"Invalid packet data in frame {frame}")

        src_ep, dst_ep = (src, sport), (dst, dport)
        key = (proto, tuple(sorted((src_ep, dst_ep))), r.get("frame.interface_id"),
               r.get("vlan.id"), r.get(proto + ".stream"))
        flow = active.get(key)
        if (flow is None or flow["closed"] or timestamp - flow["last"] > idle
                or flow["start"] - timestamp > idle
                or max(flow["last"], timestamp) - min(flow["start"], timestamp) >= max_age):
            reply = (r.get("tcp.flags.syn") in ("1", "True") and r.get("tcp.flags.ack") in ("1", "True")
                     or r.get("dns.flags.response") in ("1", "True"))
            origin, peer = (dst_ep, src_ep) if reply else (src_ep, dst_ep)
            flow = {
                "flow_id": f"FLOW-{len(flows)+1:05d}", "proto": proto,
                "src_ip": origin[0], "src_port": origin[1], "dst_ip": peer[0], "dst_port": peer[1],
                "start": timestamp, "last": timestamp, "forward": [], "backward": [],
                "total_bytes": 0, "closed": False, "fin_sides": set(), "service": "-",
                "sbytes": 0, "dbytes": 0,
            }
            flows.append(flow)
            active[key] = flow
        if flow["service"] == "-":
            protocols = r.get("frame.protocols", "").split(":")
            protocols.append(_first(r.get("_ws.col.Protocol", "")).lower())
            flow["service"] = next((SERVICES[p] for p in protocols if p in SERVICES), "-")

        forward = src_ep == (flow["src_ip"], flow["src_port"])
        direction = "forward" if forward else "backward"
        flow[direction].append(timestamp)
        flow["start"] = min(flow["start"], timestamp)
        flow["last"] = max(flow["last"], timestamp)
        flow["total_bytes"] += size
        byte_key = "sbytes" if forward else "dbytes"
        if flow[byte_key] is not None:
            if r.get("ip.len"):
                flow[byte_key] += int(r["ip.len"])
            elif r.get("ipv6.plen") and int(r["ipv6.plen"]) > 0:
                flow[byte_key] += 40 + int(r["ipv6.plen"])
            else:
                flow[byte_key] = None
        packet_map.append({
            "flow_id": flow["flow_id"], "frame_number": frame,
            "timestamp": str(timestamp), "src_ip": src, "src_port": sport,
            "dst_ip": dst, "dst_port": dport, "protocol": proto.upper(),
            "direction": direction, "packet_size": size,
        })
        if proto == "tcp":
            if _first(r.get("tcp.flags.fin", "")) in ("1", "True"):
                flow["fin_sides"].add(direction)
            elif len(flow["fin_sides"]) == 2 and r.get("tcp.flags.ack") in ("1", "True"):
                flow["closed"] = True
            if _first(r.get("tcp.flags.reset", "")) in ("1", "True"):
                flow["closed"] = True

    output = []
    for f in flows:
        n1, n2 = len(f["forward"]), len(f["backward"])
        output.append({
            "flow_id": f["flow_id"], "src_ip": f["src_ip"], "src_port": f["src_port"],
            "dst_ip": f["dst_ip"], "dst_port": f["dst_port"],
            "total_packets": n1 + n2, "total_bytes": f["total_bytes"],
            "start_time": str(f["start"]), "end_time": str(f["last"]),
            "proto": f["proto"], "dur": float(f["last"] - f["start"]),
            "spkts": n1, "dpkts": n2, "sinpkt": _avg_ms(f["forward"]),
            "dinpkt": _avg_ms(f["backward"]),
            "is_sm_ips_ports": int(f["src_ip"] == f["dst_ip"] and f["src_port"] == f["dst_port"]),
            "service": f["service"], "sbytes": f["sbytes"], "dbytes": f["dbytes"],
        })
    return output, packet_map, {
        "total_frames": total_frames, "analyzed_packets": len(packet_map),
        "unsupported_packets": unsupported, "flow_count": len(output),
    }


def extract_pcap(capture_path: Path, tshark="tshark"):
    """Read a real PCAP/PCAPNG with tshark, then build flows and original-frame map."""
    capture_path = Path(capture_path).resolve()
    if not capture_path.is_file():
        raise FileNotFoundError(capture_path)
    command = [tshark, "-n", "-r", str(capture_path), "-T", "fields", "-E", "header=y",
               "-E", "separator=/t", "-E", "occurrence=f"]
    for field in TSHARK_FIELDS:
        command.extend(["-e", field])
    with TemporaryDirectory(prefix="ai_nids_") as temp_dir:
        temporary_tsv = Path(temp_dir) / "packets.tsv"
        with temporary_tsv.open("w", encoding="utf-8", newline="") as output:
            try:
                result = subprocess.run(command, stdout=output, stderr=subprocess.PIPE,
                                        text=True, timeout=180, check=False)
            except FileNotFoundError as exc:
                raise RuntimeError("TShark not found; install it with sudo apt install tshark") from exc
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("TShark timed out on the capture") from exc
        if result.returncode:
            raise RuntimeError("TShark could not read the capture: " + result.stderr[-1200:])
        with temporary_tsv.open("r", newline="", encoding="utf-8") as source:
            reader = csv.DictReader(source, delimiter="\t")
            if not reader.fieldnames or "frame.number" not in reader.fieldnames:
                raise RuntimeError("TShark produced no valid packet header")
            return build_from_rows(reader)
