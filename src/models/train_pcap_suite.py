"""Tune the three retained classifiers on UNSW-NB15 and publish their ensemble."""
import argparse
import shutil
import sys
import time
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from tempfile import mkdtemp

import joblib
import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTENC
from sklearn.compose import ColumnTransformer
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import StratifiedGroupKFold, train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import Pipeline, make_pipeline
from sklearn.preprocessing import FunctionTransformer, LabelEncoder, OneHotEncoder, StandardScaler
from threadpoolctl import threadpool_limits

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.models.benchmark import estimator, write_json
from src.prediction.model_loader import NAMES, digest
from src.prediction.ensemble import AverageProbabilityEnsemble
from src.prediction.pcap_service import (
    SUITE, MODELS, MODEL_TITLES, coverage_keys, decision_positions, normal_runner_up_gaps,
)
from src.preprocessing.preprocess import UNSW, load_split
from src.traffic.pcap_engine import IP_FEATURES, LEGACY_FEATURES, SCHEMAS

SEED = 42
TARGET_FALSE_ALARM_RATE = 0.05
MAX_VALIDATION_ATTACK_RECALL_LOSS = 0.02
# All choices, including the minority sampling target, are compared on training data.
TRIALS = (
    ("seven-feature baseline", "pcap_7f_v1", 0),
    ("service and directional IP bytes", "pcap_ip_bytes_v1", 0),
    ("enriched with capped SMOTENC 600", "pcap_ip_bytes_v1", 600),
    ("enriched with capped SMOTENC 1200", "pcap_ip_bytes_v1", 1200),
    ("enriched with capped SMOTENC 2400", "pcap_ip_bytes_v1", 2400),
)


def read_split(path):
    frame, labels = load_split(path)
    keep = frame.proto.isin(["tcp", "udp"])
    data = frame.loc[keep, list(IP_FEATURES)].reset_index(drop=True)
    return data, labels.loc[keep].reset_index(drop=True)


def validation_indices(frame, labels):
    # Keep identical baseline vectors together for every richer feature set as well.
    groups = frame.groupby(list(LEGACY_FEATURES), sort=False, dropna=False).ngroup()
    folds = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED)
    return next(folds.split(frame, labels, groups))


def training_indices(indices, labels, name):
    if name == "knn" and len(indices) > 30000:
        indices, _ = train_test_split(indices, train_size=30000, stratify=labels[indices],
                                      random_state=SEED)
    return indices


def fit(name, trial, frame, labels):
    _, schema, balance_target = trial
    columns = list(SCHEMAS[schema])
    data = frame[columns]
    cats = [c for c in columns if c in ("proto", "service")]
    if balance_target:
        counts = np.bincount(labels)
        target = {i: balance_target for i, n in enumerate(counts) if 0 < n < balance_target}
        if target:
            sampler = SMOTENC(categorical_features=cats, sampling_strategy=target,
                              k_neighbors=min(5, min(counts[i] for i in target) - 1),
                              random_state=SEED)
            data, labels = sampler.fit_resample(data, labels)

    numeric = [c for c in columns if c not in cats]
    transform = (make_pipeline(FunctionTransformer(np.log1p), StandardScaler())
                 if name == "knn" else "passthrough")
    preprocess = ColumnTransformer([
        ("numeric", transform, numeric),
        ("categories", OneHotEncoder(handle_unknown="ignore", sparse_output=False), cats),
    ])
    if name == "knn":
        model = KNeighborsClassifier(n_neighbors=9, weights="distance", algorithm="kd_tree", n_jobs=2)
    else:
        model = estimator(name)
    pipe = Pipeline([("preprocessor", preprocess), ("classifier", model)])
    pipe.fit(data, labels)
    return pipe, len(labels)


def fit_normal_margin(probabilities, normal, attacks):
    gaps = normal_runner_up_gaps(probabilities, normal)
    allowed = int(attacks.sum() * MAX_VALIDATION_ATTACK_RECALL_LOSS)
    attack_gaps = np.sort(gaps[attacks & np.isfinite(gaps)])
    limit = attack_gaps[allowed] if allowed < len(attack_gaps) else np.inf
    recovered = gaps[(~attacks) & (gaps < limit)]
    return float(np.nextafter(recovered.max(), np.inf)) if len(recovered) else 0.0


def scores(pipe, schema, frame, truth, encoder, training_coverage=None, alert_threshold=None, normal_margin=None):
    inputs = frame[list(SCHEMAS[schema])]
    probabilities = np.asarray(pipe.predict_proba(inputs), dtype=float)
    positions = probabilities.argmax(axis=1)
    predicted = pipe.named_steps["classifier"].classes_[positions]
    classes = encoder.classes_.tolist()
    ids = np.arange(len(classes))
    normal = classes.index("Normal")
    report = classification_report(truth, predicted, labels=ids, target_names=classes,
                                   output_dict=True, zero_division=0)
    attack, flagged = truth != normal, predicted != normal
    metrics = {
        "accuracy": float(np.mean(truth == predicted)),
        "macro_f1": report["macro avg"]["f1-score"],
        "macro_precision": report["macro avg"]["precision"],
        "macro_recall": report["macro avg"]["recall"],
        "false_positive_rate": float(flagged[~attack].mean()),
        "attack_recall": float(flagged[attack].mean()),
        "binary_f1": float(f1_score(attack, flagged, zero_division=0)),
        "per_class": {label: report[label] for label in classes},
        "confusion_matrix": confusion_matrix(truth, predicted, labels=ids).tolist(),
    }
    normal_column = int(np.flatnonzero(pipe.named_steps["classifier"].classes_ == normal)[0])
    if training_coverage is not None and (normal_margin is None or alert_threshold is None):
        raise ValueError("Test scoring requires both frozen validation cutoffs")
    if normal_margin is None:
        normal_margin = fit_normal_margin(probabilities, normal_column, attack)
    decided = decision_positions(probabilities, normal_column, normal_margin)
    final_ids = pipe.named_steps["classifier"].classes_[decided]
    flagged = final_ids != normal
    confidence = probabilities[np.arange(len(inputs)), decided]
    metrics["normal_runner_up_margin"] = normal_margin
    if alert_threshold is None:
        # Only validation calls can fit this threshold. Ties at the cutoff stay below alert.
        normal_scores = np.where(flagged[~attack], confidence[~attack], 0.0)
        alert_threshold = float(np.quantile(normal_scores, 1 - TARGET_FALSE_ALARM_RATE, method="higher"))
    metrics["alert_score_threshold"] = alert_threshold
    if training_coverage is not None:
        covered = np.array([key in training_coverage for key in coverage_keys(inputs)])
        alerts = covered & flagged & (confidence > alert_threshold)
        metrics["deployment"] = {
            "assessed": int(covered.sum()), "unassessed": int((~covered).sum()),
            "assessed_fraction": float(covered.mean()),
            "assessed_accuracy": float((truth[covered] == final_ids[covered]).mean()) if covered.any() else None,
            "raw_correct_normal": int((covered & ~attack & (predicted == normal)).sum()),
            "correct_normal": int((covered & ~attack & ~flagged).sum()),
            "normal_support": int((~attack).sum()),
            "reassigned_attacks_to_normal": int((covered & attack & (predicted != normal) & ~flagged).sum()),
            "attack_support": int(attack.sum()),
            "attack_predictions_per_attack_flow": float((covered & flagged)[attack].mean()),
            "false_alarms_per_normal_flow": float(alerts[~attack].mean()),
            "alerts_per_attack_flow": float(alerts[attack].mean()),
            "alert_precision": float(attack[alerts].mean()) if alerts.any() else None,
            "alert_count": int(alerts.sum()),
            "unassessed_per_class": {c: int((~covered & (truth == i)).sum()) for i, c in enumerate(classes)},
        }
    return metrics


def rank(metrics):
    return metrics["macro_f1"], -metrics["false_positive_rate"]


def ensemble_weight_candidates():
    """Require every retained model to vote while testing useful validation weights."""
    values = np.arange(0.1, 0.9, 0.1)
    for rf in values:
        for xgb in values:
            knn = round(1.0 - rf - xgb, 10)
            if knn >= 0.1:
                yield {"random_forest": float(rf), "xgboost": float(xgb), "knn": float(knn)}


def ensemble_rank(metrics):
    """Favor category quality, then fewer Normal errors, then attack recognition."""
    return (metrics["macro_f1"] - 0.5 * metrics["false_positive_rate"],
            -metrics["false_positive_rate"], metrics["attack_recall"])


def train_suite(names):
    train_path = UNSW / "UNSW_NB15_training-set.csv"
    test_path = UNSW / "UNSW_NB15_testing-set.csv"
    train, target = read_split(train_path)
    encoder = LabelEncoder().fit(target)
    labels = encoder.transform(target)
    fit_rows, val_rows = validation_indices(train, labels)
    directory = MODELS / "pcap_suite"
    directory.mkdir(parents=True, exist_ok=True)
    release = Path(mkdtemp(prefix="run-", dir=directory))
    print(f"{len(fit_rows):,} tuning rows, {len(val_rows):,} validation rows", flush=True)
    report = {"dataset": "UNSW-NB15 TCP/UDP", "seed": SEED, "created_utc": datetime.now(timezone.utc).isoformat(),
              "classes": encoder.classes_.tolist(), "train_rows": len(labels), "validation_rows": len(val_rows),
              "selection": "Highest validation macro-F1, then lowest normal false-positive rate",
              "validation_false_alarm_target": TARGET_FALSE_ALARM_RATE,
              "validation_max_attack_recall_loss_for_normal_margin": MAX_VALIDATION_ATTACK_RECALL_LOSS,
              "packages": {p: version(p) for p in ("scikit-learn", "imbalanced-learn", "numpy",
                                                   "pandas", "xgboost", "joblib")},
              "files_sha256": {train_path.name: digest(train_path)}, "models": {}}
    for name in names:
        subset = training_indices(fit_rows, labels, name)
        trials = []
        for trial in TRIALS:
            start = time.monotonic()
            model, sampled_rows = fit(name, trial, train.iloc[subset], labels[subset])
            metrics = scores(model, trial[1], train.iloc[val_rows], labels[val_rows], encoder)
            trials.append({"variant": trial[0], "schema": trial[1], "train_rows": len(subset),
                           "resampled_rows": sampled_rows, "metrics": metrics})
            print(f"{name} | {trial[0]} | validation macro-F1 {metrics['macro_f1']:.4f} "
                  f"| {time.monotonic()-start:.1f}s", flush=True)
            del model
        winner = max(range(len(trials)), key=lambda i: rank(trials[i]["metrics"]))
        trial = TRIALS[winner]
        final_rows = training_indices(np.arange(len(labels)), labels, name)
        pipe, sampled_rows = fit(name, trial, train.iloc[final_rows], labels[final_rows])
        coverage = set(coverage_keys(train.iloc[final_rows][list(SCHEMAS[trial[1]])]))
        path = release / (name + ".joblib")
        joblib.dump({"pipeline": pipe, "label_encoder": encoder, "features": list(SCHEMAS[trial[1]]),
                     "training_coverage": coverage,
                     "alert_score_threshold": trials[winner]["metrics"]["alert_score_threshold"],
                     "normal_runner_up_margin": trials[winner]["metrics"]["normal_runner_up_margin"],
                     "feature_schema": trial[1], "allowed_protocols": ["tcp", "udp"],
                     "model_name": f"{MODEL_TITLES[name]} ({release.name})", "training_dataset": "UNSW-NB15"},
                    path, compress=2)
        active_path = MODELS / f"capture_{name}.joblib"
        shutil.copy2(path, active_path)
        report["models"][name] = {"artifact": str(active_path.relative_to(MODELS)), "sha256": digest(active_path),
                                  "trials": trials, "selected_trial": winner, "train_rows": len(final_rows),
                                  "resampled_rows": sampled_rows}
        del pipe
    records = report["models"]
    if set(names) == set(NAMES):
        validation_members = {}
        for name in NAMES:
            selected = TRIALS[records[name]["selected_trial"]]
            subset = training_indices(fit_rows, labels, name)
            validation_members[name], _ = fit(name, selected, train.iloc[subset], labels[subset])
        ensemble_schema = "pcap_ip_bytes_v1"
        weighted_trials = []
        for weights in ensemble_weight_candidates():
            candidate = AverageProbabilityEnsemble(validation_members, weights)
            metrics = scores(candidate, ensemble_schema, train.iloc[val_rows], labels[val_rows], encoder)
            weighted_trials.append({"weights": weights, "metrics": metrics})
        selected_weight_trial = max(range(len(weighted_trials)),
                                    key=lambda i: ensemble_rank(weighted_trials[i]["metrics"]))
        weights = weighted_trials[selected_weight_trial]["weights"]
        ensemble_metrics = weighted_trials[selected_weight_trial]["metrics"]
        final_artifacts = {name: joblib.load(MODELS / records[name]["artifact"]) for name in NAMES}
        final_ensemble = AverageProbabilityEnsemble(
            {name: item["pipeline"] for name, item in final_artifacts.items()}, weights)
        # RF and XGBoost use the complete official training split. KNN uses a
        # computationally bounded stratified subset, so its smaller key set must
        # not make an otherwise in-distribution ensemble flow look unsupported.
        coverages = [set(final_artifacts[name]["training_coverage"])
                     for name in ("random_forest", "xgboost")]
        ensemble_artifact = {
            "pipeline": final_ensemble, "label_encoder": encoder, "features": list(SCHEMAS[ensemble_schema]),
            "training_coverage": set.intersection(*coverages),
            "alert_score_threshold": ensemble_metrics["alert_score_threshold"],
            "normal_runner_up_margin": ensemble_metrics["normal_runner_up_margin"],
            "feature_schema": ensemble_schema, "allowed_protocols": ["tcp", "udp"],
            "model_name": "Random Forest + XGBoost + KNN Ensemble",
            "training_dataset": "UNSW-NB15", "members": list(NAMES),
            "combination": "validation-selected weighted probability average", "weights": weights,
        }
        ensemble_path = MODELS / "capture_ensemble.joblib"
        joblib.dump(ensemble_artifact, ensemble_path, compress=2)
        records["ensemble"] = {
            "artifact": str(ensemble_path.relative_to(MODELS)), "sha256": digest(ensemble_path),
            "trials": [{"variant": "weighted probability average",
                        "schema": ensemble_schema, "train_rows": len(fit_rows),
                        "resampled_rows": None, "weights": item["weights"], "metrics": item["metrics"]}
                       for item in weighted_trials],
            "selected_trial": selected_weight_trial, "train_rows": len(train), "resampled_rows": None,
            "members": list(NAMES), "combination": "validation-selected weighted probability average",
            "weights": weights,
        }
        report["selected_model"] = "ensemble"
    else:
        report["selected_model"] = max(names, key=lambda n: rank(
            records[n]["trials"][records[n]["selected_trial"]]["metrics"]))
    # The winner is fixed before the first read of the official testing split.
    test, truth = read_split(test_path)
    report["test_rows"] = len(test)
    report["files_sha256"][test_path.name] = digest(test_path)
    for name, record in records.items():
        artifact = joblib.load(MODELS / record["artifact"])
        record["test"] = scores(artifact["pipeline"], artifact["feature_schema"],
                                test, encoder.transform(truth), encoder, artifact["training_coverage"],
                                artifact["alert_score_threshold"], artifact["normal_runner_up_margin"])
        print(f"{name} | official test macro-F1 {record['test']['macro_f1']:.4f}", flush=True)
    write_json(release / "evaluation.json", report)
    if set(names) == set(NAMES):
        write_json(SUITE, report)
        print(f"Published ensemble to {SUITE}", flush=True)
    else:
        print(f"Partial model comparison saved to {release / 'evaluation.json'}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--models", nargs="+", choices=NAMES, default=NAMES)
    args = parser.parse_args()
    with threadpool_limits(limits=2):
        train_suite(list(dict.fromkeys(args.models)))
