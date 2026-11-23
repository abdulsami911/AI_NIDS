from dataclasses import dataclass, field
from statistics import fmean
from src.traffic.tshark_extractor import Packet


@dataclass(slots=True)
class Flow:
    src: str
    dst: str
    sport: int | None
    dport: int | None
    proto: str
    first: int
    last: int
    orientation: str
    packets: list = field(default_factory=list)
    fins: set = field(default_factory=set)
    closed: bool = False
    initial_seq: str = ""
    reason: str = "capture boundary"
    out_of_order: bool = False

    def add(self, p):
        forward = (p.src, p.sport) == (self.src, self.sport)
        self.packets.append((p, forward))
        self.out_of_order |= p.ns < self.last
        self.first, self.last = min(self.first, p.ns), max(self.last, p.ns)
        flags = p.flags or 0
        if flags & 1:
            self.fins.add(forward)
        if flags & 4:
            self.closed, self.reason = True, "TCP reset"
        elif len(self.fins) == 2 and flags & 16 and not flags & 1:
            self.closed, self.reason = True, "TCP close"

    def summary(self):
        sizes = [p.length for p, _ in self.packets]
        times = sorted(p.ns for p, _ in self.packets)
        gaps = [(b-a)/1e6 for a, b in zip(times, times[1:])]
        forward = [p.length for p, direction in self.packets if direction]
        dur = (self.last - self.first) / 1e9
        return {"dur": dur, "proto": self.proto, "spkts": len(forward), "dpkts": len(sizes)-len(forward),
                "sbytes_wire": sum(forward), "dbytes_wire": sum(sizes)-sum(forward),
                "bytes": sum(sizes), "packets": len(sizes), "min_len": min(sizes), "max_len": max(sizes),
                "mean_len": fmean(sizes), "mean_gap_ms": fmean(gaps) if gaps else None,
                "max_gap_ms": max(gaps, default=None), "pps": len(sizes)/dur if dur else None,
                "bytes_per_second": sum(sizes)/dur if dur else None,
                "orientation": self.orientation, "boundary": self.reason,
                "truncated_frames": sum(p.truncated for p, _ in self.packets), "out_of_order": self.out_of_order}

    def unsupported(self):
        if self.proto == "icmpv6":
            return "ICMPv6 absent from training"
        if not any(forward for _, forward in self.packets):
            return "No observed initiator packets"
        return None


class FlowBuilder:
    def __init__(self, idle_seconds=30, active_seconds=60):
        if not 1 <= idle_seconds <= 3600 or active_seconds <= 0:
            raise ValueError("Invalid flow timeout")
        self.idle_ns, self.active_ns = idle_seconds * 10**9, active_seconds * 10**9
        self.current = {}
        self.flows = []

    def add(self, p: Packet):
        ends = tuple(sorted(((p.src, p.sport), (p.dst, p.dport))))
        key = (p.circuit, ends, p.proto, p.stream)
        flow = self.current.get(key)
        flags = p.flags or 0
        syn = flags & 2 and not flags & 16
        boundary = None
        if flow and p.ns - flow.last > self.idle_ns:
            boundary = "idle timeout"
        elif flow and p.ns - flow.first >= self.active_ns:
            boundary = "active timeout"
        elif flow and syn and (p.seq != flow.initial_seq or flow.fins):
            boundary = "new TCP opening"
        if flow is None or flow.closed or boundary:
            if flow and boundary:
                flow.reason = boundary
            reverse = bool(flags & 2 and flags & 16) or p.echo_reply
            src, dst, sport, dport = (p.dst, p.src, p.dport, p.sport) if reverse else (p.src, p.dst, p.sport, p.dport)
            orientation = "TCP opening" if flags & 2 else "echo type" if p.proto.startswith("icmp") else "first observed"
            flow = Flow(src, dst, sport, dport, p.proto, p.ns, p.ns, orientation)
            if syn:
                flow.initial_seq = p.seq
            self.current[key] = flow
            self.flows.append(flow)
        flow.add(p)
