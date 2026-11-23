"""Classify measured flow features with a trusted, locally trained pipeline."""
import json
from functools import lru_cache
from hashlib import file_digest
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from src.traffic.pcap_engine import SCHEMAS

ROOT = Path(__file__).resolve().parents[2]
MODELS = ROOT / "artifacts/models"
SUITE = ROOT / "reports/evaluation/pcap_suite.json"
MODEL_TITLES = {"ensemble": "RF + XGBoost + KNN Ensemble", "random_forest": "Random Forest",
                "xgboost": "XGBoost", "knn": "K-Nearest Neighbors"}
ACTIVE_MODELS = ("ensemble", "random_forest", "xgboost", "knn")


def coverage_keys(frame):
    """Group counts into 0, 1, 2–3, 4–7, etc., retaining transport and observed service."""
    cats = frame.service if "service" in frame else ["*"] * len(frame)
    return [(proto, service, int(src).bit_length(), int(dst).bit_length())
            for proto, service, src, dst in zip(frame.proto, cats, frame.spkts, frame.dpkts)]


def normal_runner_up_gaps(probs, normal):
    """Score gap to a leading attack class when Normal ranks second."""
    scores = probs[:, normal]
    second = (probs > scores[:, None]).sum(axis=1) == 1
    return np.where(second, probs.max(axis=1) - scores, np.inf).astype(float)


def decision_positions(probs, normal, margin):
    positions = probs.argmax(axis=1)
    if margin > 0:
        positions[normal_runner_up_gaps(probs, normal) < margin] = normal
    return positions


def suite_report():
    return json.loads(SUITE.read_text()) if SUITE.is_file() else {}


@lru_cache(maxsize=16)
def _verified_digest(path, mtime_ns, size):
    with path.open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


def resolve_model(name="auto"):
    report = suite_report()
    if report:
        key = report["selected_model"] if name == "auto" else name
        if key not in report["models"]:
            raise ValueError(f"Unknown PCAP model {key}")
        record = report["models"][key]
        path = (MODELS / record["artifact"]).resolve()
        if not path.is_relative_to(MODELS):
            raise ValueError("Invalid PCAP artifact path")
        stat = path.stat()
        if _verified_digest(path, stat.st_mtime_ns, stat.st_size) != record["sha256"]:
            raise ValueError(f"PCAP artifact checksum mismatch for {key}")
        return path
    raise FileNotFoundError("Train the capture models with python -m src.models.train_pcap_suite")


def classify_flows(flows: list[dict], artifact_path: Path | None = None):
    if not flows:
        return [], "No supported TCP/UDP flows"
    path = Path(artifact_path) if artifact_path is not None else resolve_model()
    artifact = joblib.load(path)
    features = list(artifact.get("features", []))
    schema = SCHEMAS.get(artifact.get("feature_schema"))
    if schema is None or features != list(schema):
        raise ValueError("Model feature schema mismatch")
    frame = pd.DataFrame(flows)
    missing = set(features) - set(frame)
    if missing:
        raise ValueError(f"Missing flow features: {sorted(missing)}")
    frame = frame[features]
    if frame.isna().any().any() or not frame.proto.isin(["tcp", "udp"]).all():
        raise ValueError("Flow features are missing or contain an unsupported protocol")
    numeric = frame.drop(columns=["proto", "service"], errors="ignore").to_numpy(dtype=float)
    if not np.isfinite(numeric).all() or (numeric < 0).any():
        raise ValueError("Flow measurements must be finite and nonnegative")
    for col in ("spkts", "dpkts"):
        if (frame[col] % 1 != 0).any():
            raise ValueError("Expected integer packet counts")
    support = artifact.get("training_coverage")
    pairs = {(key[0], key[1]) for key in support} if support is not None else set()
    covered = []
    for i, (flow, key) in enumerate(zip(flows, coverage_keys(frame))):
        if support is None or key in support:
            covered.append(i)
        service = f"{key[0].upper()} / {key[1]}"
        reason = (f"No training flows for {service}" if key[:2] not in pairs else
                  f"No training flows for {service} in these forward and reverse packet-count ranges")
        flow.update(predicted_category="Unassessed", is_predicted_attack=None, model_score=None,
                    alert_raised=False, alert_score_threshold=artifact.get("alert_score_threshold"),
                    feature_schema=artifact["feature_schema"],
                    review_flag=reason)
    pipeline = artifact["pipeline"]
    # Score every reconstructed flow for SOC triage. Coverage still controls
    # whether the lead class is promoted to a prediction or allowed to alert.
    probs = np.asarray(pipeline.predict_proba(frame), dtype=float)
    classes = np.asarray(pipeline.named_steps["classifier"].classes_)
    margin = artifact.get("normal_runner_up_margin", 0)
    normal = 0
    if margin:
        normal_id = artifact["label_encoder"].transform(["Normal"])[0]
        normal = int(np.flatnonzero(classes == normal_id)[0])
    positions = decision_positions(probs, normal, margin)
    labels = artifact["label_encoder"].inverse_transform(classes[positions].astype(int))
    covered_set = set(covered)
    for i, (label, score, adjusted) in enumerate(zip(
            labels, probs[np.arange(len(frame)), positions], positions != probs.argmax(axis=1))):
        flow = flows[i]
        category = str(label).strip().title()
        if category == "Dos":
            category = "DoS"
        if i not in covered_set:
            flow["model_score"] = round(float(score), 4)
            flow["review_flag"] += (f"; ensemble lead {category} at {float(score):.1%}. "
                                    "Triage suggestion only—not a category or alert")
            continue
        flow["predicted_category"] = category
        flow["is_predicted_attack"] = category != "Normal"
        flow["model_score"] = round(float(score), 4)
        flow["alert_raised"] = category != "Normal" and float(score) > artifact.get("alert_score_threshold", -1)
        if flow["alert_raised"]:
            flow["review_flag"] = "Alert"
        elif category == "Normal":
            flow["review_flag"] = "Normal by validation margin" if adjusted else "Predicted Normal"
        else:
            flow["review_flag"] = "Below alert threshold"
    return flows, str(artifact.get("model_name", path.stem))
