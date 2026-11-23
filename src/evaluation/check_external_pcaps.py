"""Evaluate the frozen UNSW capture pipeline on two capture-labeled USTC-TFC2016 samples."""
from collections import Counter
from hashlib import file_digest
import json

from src.prediction.pcap_service import ROOT, classify_flows, resolve_model
from src.traffic.pcap_engine import extract_pcap


def sha256(path):
    with path.open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


def main():
    model = resolve_model()
    report = {"dataset": "USTC-TFC2016", "label_scope": "capture",
              "model": str(model.relative_to(ROOT)), "model_sha256": sha256(model),
              "captures": []}
    for name, group in (("Gmail", "Benign"), ("Tinba", "Malware")):
        path = ROOT / "datasets/ustc_tfc2016" / f"{name}.pcap"
        flows, packets, counts = extract_pcap(path)
        results, _ = classify_flows(flows, model)
        if len(packets) != sum(f["total_packets"] for f in flows):
            raise ValueError("Flow and frame counts disagree")
        categories = Counter(f["predicted_category"] for f in results)
        alerts = [f for f in results if f["alert_raised"]]
        examples = []
        for flow in alerts[:3]:
            member_frames = [p["frame_number"] for p in packets if p["flow_id"] == flow["flow_id"]]
            examples.append({"flow_id": flow["flow_id"], "first_frame": member_frames[0],
                             "last_frame": member_frames[-1], "service": flow["service"],
                             "spkts": flow["spkts"], "dpkts": flow["dpkts"],
                             "prediction": flow["predicted_category"], "score": flow["model_score"]})
        report["captures"].append({
            "file": path.name, "sha256": sha256(path), "publisher_group": group,
            "source": f"https://github.com/davidyslu/USTC-TFC2016/blob/master/{group}/{name}.pcap",
            **counts, "assessed_flows": len(results) - categories["Unassessed"],
            "model_categories": dict(categories), "alerted_flows": len(alerts),
            "alerts_by_predicted_category": dict(Counter(f["predicted_category"] for f in alerts)),
            "example_alerts": examples})
    path = ROOT / "reports/evaluation/external_pcap_checks.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(path)
    for capture in report["captures"]:
        print(capture["file"], f'{capture["alerted_flows"]} alerts, {capture["assessed_flows"]} '
              f'assessed of {capture["flow_count"]} flows')


if __name__ == "__main__":
    main()
