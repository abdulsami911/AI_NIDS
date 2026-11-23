"""Independent Normal/Attack comparison on the two NSL-KDD TXT splits."""
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from threadpoolctl import threadpool_limits

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.data.nsl import CATS, COLUMNS
from src.models.benchmark import NAMES, estimator, digest, write_json
from src.preprocessing.preprocess import ROOT, build_preprocessor

DATA = ROOT / "datasets/nsl_kdd"
OUT = ROOT / "reports/evaluation"
MODELS = ROOT / "artifacts/models"


def load(path):
    raw = pd.read_csv(path, header=None, low_memory=False)
    if raw.shape[1] not in (42, 43) or raw.isna().any().any():
        raise ValueError(f"Expected 41 populated predictors, attack name and optional difficulty in {path}")
    features = raw.iloc[:, :41].set_axis(COLUMNS, axis=1)
    labels = raw.iloc[:, 41].str.strip().str.rstrip(".").str.lower()
    return features, labels.ne("normal").astype(int).to_numpy()


def main():
    train_path, test_path = (DATA / s for s in ("KDDTrain+.txt", "KDDTest+.txt"))
    train, y_train = load(train_path)
    test, truth = load(test_path)
    MODELS.mkdir(exist_ok=True, parents=True)
    report = {"dataset": "NSL-KDD", "task": "Binary Normal vs Attack", "seed": 42,
              "train_rows": len(train), "test_rows": len(test), "classes": ["Normal", "Attack"],
              "files_sha256": {p.name: digest(p) for p in (train_path, test_path)}, "models": {}}
    for name in NAMES:
        rows = np.arange(len(train))
        if name == "knn" and len(rows) > 10000:
            rows, _ = train_test_split(rows, train_size=10000, stratify=y_train, random_state=42)
        scaled = name == "knn"
        if name == "random_forest":
            model = RandomForestClassifier(n_estimators=120, min_samples_leaf=2, class_weight="balanced",
                                           n_jobs=2, random_state=42)
        else:
            model = estimator(name)
        if name == "xgboost":
            model.set_params(objective="binary:logistic", eval_metric="logloss")
        prep = build_preprocessor(scaled, COLUMNS, CATS)
        # Dense encoded rows permit efficient nearest-neighbor batches on this laptop.
        prep.set_params(sparse_threshold=0)
        pipe = Pipeline([("preprocessor", prep), ("classifier", model)])
        pipe.fit(train.iloc[rows], y_train[rows])
        pred = np.concatenate([pipe.predict(test.iloc[i:i+512]) for i in range(0, len(test), 512)])
        matrix = confusion_matrix(truth, pred, labels=[0, 1])
        scores = classification_report(truth, pred, labels=[0, 1], target_names=report["classes"],
                                       output_dict=True, zero_division=0)
        record = {"model": name, "train_rows": len(rows), "test_rows": len(truth),
                  "accuracy": scores["accuracy"], "macro_f1": scores["macro avg"]["f1-score"],
                  "macro_precision": scores["macro avg"]["precision"], "macro_recall": scores["macro avg"]["recall"],
                  "attack_precision": scores["Attack"]["precision"], "attack_recall": scores["Attack"]["recall"],
                  "attack_f1": scores["Attack"]["f1-score"], "false_positive_rate": matrix[0, 1] / matrix[0].sum(),
                  "per_class": {c: scores[c] for c in report["classes"]}, "confusion_matrix": matrix.tolist()}
        artifact = MODELS / f"nsl_kdd_{name}.joblib"
        joblib.dump({"pipeline": pipe, "features": COLUMNS, "model_name": f"NSL-KDD {name}",
                     "dataset": "NSL-KDD", "task": "binary"}, artifact, compress=2)
        record["sha256"] = digest(artifact)
        report["models"][name] = record
        if name == "random_forest":
            write_json(OUT / "nsl_kdd_random_forest_metrics.json", {
                **record, "dataset": "NSL-KDD", "task": report["task"], "independent_benchmark": True})
        print(f"{name}: macro-F1 {record['macro_f1']:.4f}, accuracy {record['accuracy']:.4f}", flush=True)
    write_json(OUT / "nsl_kdd_suite.json", report)


if __name__ == "__main__":
    with threadpool_limits(limits=2):
        main()
