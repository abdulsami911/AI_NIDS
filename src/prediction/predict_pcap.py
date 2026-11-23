"""Predict flow categories from a Wireshark capture or previously extracted feature CSVs."""
import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.prediction.pcap_service import MODELS, MODEL_TITLES, ROOT, classify_flows, resolve_model
from src.traffic.pcap_engine import IP_FEATURES, LEGACY_FEATURES, extract_pcap

DEFAULT_OUTPUT = ROOT / "reports/pcap_analysis"
DEFAULT_MODEL = MODELS / "capture_ensemble.joblib"
DEFAULT_FEATURES = DEFAULT_OUTPUT / "pcap_ml_features.csv"
DEFAULT_MAPPING = DEFAULT_OUTPUT / "packet_flow_map.csv"
METADATA = ["flow_id", "src_ip", "src_port", "dst_ip", "dst_port", "total_packets"]
PACKETS = ["frame_number", "flow_id", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
           "transport", "direction", "packet_size"]
PREDICTIONS = ["predicted_category", "is_predicted_attack", "model_score", "alert_raised"]


def validate_features(df, features, protocols):
    missing = set(METADATA + list(features)) - set(df)
    if missing:
        raise ValueError(f"Missing columns: {sorted(missing)}")
    if df.empty or df.flow_id.isna().any() or df.flow_id.eq("").any() or df.flow_id.duplicated().any():
        raise ValueError("Expected nonempty feature rows with unique flow IDs")
    df["proto"] = df.proto.str.strip().str.lower()
    if not df.proto.isin(protocols).all():
        raise ValueError("Unsupported protocol in flow features")
    for col in set(features) | {"total_packets"}:
        if col in ("proto", "service"):
            continue
        df[col] = pd.to_numeric(df[col], errors="raise")
        if not np.isfinite(df[col]).all() or (df[col] < 0).any():
            raise ValueError(f"Invalid measurement in {col}")
    for col in ["spkts", "dpkts", "total_packets"]:
        if (df[col] % 1 != 0).any():
            raise ValueError(f"Non-integer packet count in {col}")
    if not (df.spkts + df.dpkts == df.total_packets).all():
        raise ValueError("Packet count mismatch in feature records")
    if not df.is_sm_ips_ports.isin([0, 1]).all():
        raise ValueError("Invalid is_sm_ips_ports values")
    return df


def write_results(flows, mapping, output, model_path):
    if not set(PACKETS) <= set(mapping.columns) or mapping.frame_number.duplicated().any():
        raise ValueError("Invalid packet map or duplicate Wireshark frame numbers")
    mapping = mapping[mapping.flow_id.isin(flows.flow_id)].copy()
    observed = mapping.groupby("flow_id").size().reindex(flows.flow_id, fill_value=0)
    if not np.array_equal(observed.to_numpy(), flows.total_packets.to_numpy()):
        raise ValueError("Packet mapping and flow packet counts disagree")
    records, name = classify_flows(flows.to_dict("records"), model_path)
    if records:
        result = pd.DataFrame(records)
    else:
        result = pd.DataFrame(columns=[*flows, *PREDICTIONS, "review_flag", "feature_schema"])
    result["model_name"] = name
    packets = mapping.merge(result[["flow_id", *PREDICTIONS]], on="flow_id",
                            how="left", validate="many_to_one").rename(columns={
        "predicted_category": "flow_prediction", "is_predicted_attack": "flow_predicted_attack",
        "model_score": "flow_model_score", "alert_raised": "flow_alert_raised"})
    output.mkdir(parents=True, exist_ok=True)
    result.to_csv(output / "flow_predictions.csv", index=False)
    packets.to_csv(output / "packet_investigation.csv", index=False)
    print(f"{name} | {len(result)} flows | {len(packets)} mapped frames")
    print(f"Alerts: {int(result.alert_raised.sum())}")
    for category, count in result.predicted_category.value_counts().items():
        print(f"  {category}: {count}")
    print(f"Results: {output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, help="Analyze this PCAP or PCAPNG directly")
    parser.add_argument("--model", help="Trained algorithm name or trusted local artifact path")
    parser.add_argument("--features", type=Path)
    parser.add_argument("--mapping", type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if args.pcap and (args.features or args.mapping):
        parser.error("--pcap and pre-extracted CSV inputs cannot be combined")
    if args.model is None:
        path = resolve_model() if args.pcap else DEFAULT_MODEL
    elif args.model in (*MODEL_TITLES, "auto"):
        path = resolve_model(args.model)
    else:
        path = Path(args.model)
    if args.pcap:
        rows, frames, summary = extract_pcap(args.pcap)
        print(f"{summary['total_frames']} captured frames, {summary['unsupported_packets']} skipped")
        flows = pd.DataFrame(rows) if rows else pd.DataFrame(columns=METADATA + list(IP_FEATURES))
        mapping = pd.DataFrame(frames).rename(columns={"protocol": "transport"}).reindex(columns=PACKETS)
        output = args.output_dir or DEFAULT_OUTPUT / args.pcap.stem
    else:
        types = {k: str for k in METADATA if k != "total_packets"}
        flows = pd.read_csv(args.features or DEFAULT_FEATURES, dtype=types, keep_default_na=False)
        features = [c for c in IP_FEATURES if c in flows]
        flows = validate_features(flows, list(dict.fromkeys([*LEGACY_FEATURES, *features])), ["tcp", "udp"])
        mapping = pd.read_csv(args.mapping or DEFAULT_MAPPING, dtype=types, keep_default_na=False)
        output = args.output_dir or DEFAULT_OUTPUT
    write_results(flows, mapping, output, path)


if __name__ == "__main__":
    main()
