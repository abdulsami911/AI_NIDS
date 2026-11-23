
import csv
import argparse
from pathlib import Path
from decimal import Decimal


def get_transport(row):
    protocol = (row.get("_ws.col.protocol") or "").strip().upper()

    # Detect ICMP before examining transport-port fields.
    # ICMP errors can contain quoted TCP/UDP packets.
    if protocol in ("ICMP", "ICMPV6"):
        return protocol

    if row.get("tcp.srcport") or row.get("tcp.dstport"):
        return "TCP"

    if row.get("udp.srcport") or row.get("udp.dstport"):
        return "UDP"

    return None


def build_flows(input_file, output_dir, timeout=60):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    flows = []
    active_flows = {}
    packet_mapping = []
    skipped = 0
    timeout = Decimal(str(timeout))

    with open(input_file, newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file, delimiter="\t")

        for row in reader:
            src_ip = row.get("ip.src") or row.get("ipv6.src")
            dst_ip = row.get("ip.dst") or row.get("ipv6.dst")

            # ARP and other packets without IP endpoints
            # are excluded from IP-flow construction.
            if not src_ip or not dst_ip:
                skipped += 1
                continue

            transport = get_transport(row)

            if transport is None:
                skipped += 1
                continue

            src_port = row.get("tcp.srcport") or row.get("udp.srcport") or ""
            dst_port = row.get("tcp.dstport") or row.get("udp.dstport") or ""

            source_endpoint = (src_ip, src_port)
            destination_endpoint = (dst_ip, dst_port)

            # Sorting makes A->B and B->A use the same key.
            endpoints = tuple(sorted(
                [source_endpoint, destination_endpoint]
            ))

            flow_key = (transport, endpoints)

            timestamp = Decimal(row["frame.time_epoch"])
            packet_size = int(row["frame.len"])
            packet_number = int(row["frame.number"])

            flow = active_flows.get(flow_key)

            # Start a new flow after a period of inactivity.
            if flow is None or timestamp - flow["last"] > timeout:
                flow = {
                    "flow_id": f"FLOW-{len(flows) + 1:05d}",
                    "transport": transport,
                    "protocol": row.get("_ws.col.protocol", ""),
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "first": timestamp,
                    "last": timestamp,
                    "forward_packets": 0,
                    "backward_packets": 0,
                    "forward_bytes": 0,
                    "backward_bytes": 0,
                }

                flows.append(flow)
                active_flows[flow_key] = flow

            flow["last"] = timestamp

            is_forward = source_endpoint == (
                flow["src_ip"], flow["src_port"]
            )

            direction = "forward" if is_forward else "backward"

            if is_forward:
                flow["forward_packets"] += 1
                flow["forward_bytes"] += packet_size
            else:
                flow["backward_packets"] += 1
                flow["backward_bytes"] += packet_size

            packet_mapping.append({
                "frame_number": packet_number,
                "flow_id": flow["flow_id"],
                "timestamp": str(timestamp),
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "transport": transport,
                "direction": direction,
                "packet_size": packet_size
            })

    # Export one row per reconstructed network flow.
    flow_rows = []

    for flow in flows:
        duration = flow["last"] - flow["first"]
        total_packets = (
            flow["forward_packets"] + flow["backward_packets"]
        )
        total_bytes = (
            flow["forward_bytes"] + flow["backward_bytes"]
        )

        flow_rows.append({
            "flow_id": flow["flow_id"],
            "transport": flow["transport"],
            "protocol": flow["protocol"],
            "src_ip": flow["src_ip"],
            "src_port": flow["src_port"],
            "dst_ip": flow["dst_ip"],
            "dst_port": flow["dst_port"],
            "start_time": str(flow["first"]),
            "end_time": str(flow["last"]),
            "duration_seconds": str(duration),
            "forward_packets": flow["forward_packets"],
            "backward_packets": flow["backward_packets"],
            "total_packets": total_packets,
            "forward_bytes": flow["forward_bytes"],
            "backward_bytes": flow["backward_bytes"],
            "total_bytes": total_bytes,
        })

    flows_path = output_dir / "flows.csv"
    mapping_path = output_dir / "packet_flow_map.csv"

    with open(flows_path, "w", newline="", encoding="utf-8") as file:
        if flow_rows:
            writer = csv.DictWriter(
                file, fieldnames=flow_rows[0].keys()
            )
            writer.writeheader()
            writer.writerows(flow_rows)

    with open(mapping_path, "w", newline="", encoding="utf-8") as file:
        if packet_mapping:
            writer = csv.DictWriter(
                file, fieldnames=packet_mapping[0].keys()
            )
            writer.writeheader()
            writer.writerows(packet_mapping)

    print("\n=== AI-NIDS FLOW EXTRACTION ===")
    print(f"Total flows created: {len(flows)}")
    print(f"Packets assigned: {len(packet_mapping)}")
    print(f"Packets skipped: {skipped}")
    print(f"Flows saved: {flows_path}")
    print(f"Packet mapping saved: {mapping_path}")

    print("\nFirst 5 flows:")
    for flow in flow_rows[:5]:
        print(
            f"{flow['flow_id']} | "
            f"{flow['transport']} | "
            f"{flow['src_ip']}:{flow['src_port']} -> "
            f"{flow['dst_ip']}:{flow['dst_port']} | "
            f"{flow['total_packets']} packets"
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input_file")
    parser.add_argument(
        "--output-dir",
        default="reports/pcap_analysis"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=60
    )

    args = parser.parse_args()

    build_flows(
        args.input_file,
        args.output_dir,
        args.timeout
    )
