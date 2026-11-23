
import csv
from collections import defaultdict
from decimal import Decimal
from pathlib import Path

BASE = Path("reports/pcap_analysis")

FLOWS_FILE = BASE / "flows.csv"
MAPPING_FILE = BASE / "packet_flow_map.csv"
OUTPUT_FILE = BASE / "pcap_ml_features.csv"

MODEL_FEATURES = [
    "proto",
    "dur",
    "spkts",
    "dpkts",
    "sinpkt",
    "dinpkt",
    "is_sm_ips_ports",
]

METADATA = [
    "flow_id",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "total_packets",
]


def average_interval_ms(timestamps):
    """Average time between consecutive same-direction packets."""
    if len(timestamps) < 2:
        return 0.0

    timestamps = sorted(timestamps)

    intervals = [
        timestamps[i] - timestamps[i - 1]
        for i in range(1, len(timestamps))
    ]

    average_seconds = sum(intervals) / len(intervals)
    return float(average_seconds * 1000)


def load_packet_timestamps():
    packet_times = defaultdict(
        lambda: {"forward": [], "backward": []}
    )

    with MAPPING_FILE.open(newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for packet in reader:
            flow_id = packet["flow_id"]
            direction = packet["direction"]

            if direction not in ("forward", "backward"):
                raise ValueError(
                    f"Invalid packet direction: {direction}"
                )

            timestamp = Decimal(packet["timestamp"])

            packet_times[flow_id][direction].append(timestamp)

    return packet_times


def create_features():
    packet_times = load_packet_timestamps()
    records = []
    skipped = 0

    with FLOWS_FILE.open(newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for flow in reader:
            proto = flow["transport"].lower()

            # First model version supports TCP and UDP.
            if proto not in ("tcp", "udp"):
                skipped += 1
                continue

            flow_id = flow["flow_id"]

            if flow_id not in packet_times:
                raise ValueError(
                    f"Missing packets for flow {flow_id}"
                )

            forward = packet_times[flow_id]["forward"]
            backward = packet_times[flow_id]["backward"]

            spkts = len(forward)
            dpkts = len(backward)

            expected_packets = int(flow["total_packets"])

            if spkts + dpkts != expected_packets:
                raise ValueError(
                    f"Packet count mismatch in {flow_id}"
                )

            if spkts != int(flow["forward_packets"]):
                raise ValueError(
                    f"Forward count mismatch in {flow_id}"
                )

            if dpkts != int(flow["backward_packets"]):
                raise ValueError(
                    f"Backward count mismatch in {flow_id}"
                )

            duration = Decimal(flow["duration_seconds"])

            if duration < 0:
                raise ValueError(
                    f"Negative duration in {flow_id}"
                )

            same_endpoints = int(
                flow["src_ip"] == flow["dst_ip"]
                and flow["src_port"] == flow["dst_port"]
            )

            record = {
                "flow_id": flow_id,
                "src_ip": flow["src_ip"],
                "src_port": flow["src_port"],
                "dst_ip": flow["dst_ip"],
                "dst_port": flow["dst_port"],
                "total_packets": expected_packets,

                # UNSW-NB15-compatible candidate features.
                "proto": proto,
                "dur": float(duration),
                "spkts": spkts,
                "dpkts": dpkts,
                "sinpkt": average_interval_ms(forward),
                "dinpkt": average_interval_ms(backward),
                "is_sm_ips_ports": same_endpoints,
            }

            records.append(record)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=METADATA + MODEL_FEATURES,
        )
        writer.writeheader()
        writer.writerows(records)

    print("\n=== AI-NIDS FEATURE EXTRACTION ===")
    print(f"Eligible TCP/UDP flows: {len(records)}")
    print(f"Unsupported flows skipped: {skipped}")
    print(f"ML features per flow: {len(MODEL_FEATURES)}")
    print(f"Saved: {OUTPUT_FILE}")

    print("\nFirst 5 feature records:")

    for record in records[:5]:
        print(
            f"{record['flow_id']} | "
            f"{record['proto']} | "
            f"duration={record['dur']:.6f}s | "
            f"spkts={record['spkts']} | "
            f"dpkts={record['dpkts']} | "
            f"sinpkt={record['sinpkt']:.3f}ms | "
            f"dinpkt={record['dinpkt']:.3f}ms"
        )


if __name__ == "__main__":
    create_features()

