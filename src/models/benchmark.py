"""Train missing artifacts and evaluate every prediction on the named official test split."""
import argparse
import gc
import hashlib
import json
import math
import os
import platform
import time
from importlib.metadata import version
from pathlib import Path
from tempfile import NamedTemporaryFile, mkdtemp

import joblib
import numpy as np
import pandas as pd
from imblearn.over_sampling import RandomOverSampler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import LabelEncoder
from threadpoolctl import threadpool_limits

from src.data.nsl import CATS, load_nsl
from src.prediction.model_loader import REGISTRY, SCHEMA, NAMES, digest, matrix
from src.preprocessing.feature_config import CATEGORICAL_FEATURES
from src.preprocessing.preprocess import ROOT, PREP, build_preprocessor, load_data


def estimator(name):
    if name == "random_forest":
        return RandomForestClassifier(n_estimators=100, max_depth=25, min_samples_leaf=2, n_jobs=2, random_state=42)
    if name == "xgboost":
        from xgboost import XGBClassifier
        return XGBClassifier(n_estimators=150, max_depth=6, learning_rate=.1, subsample=.8,
                             colsample_bytree=.8, objective="multi:softprob", eval_metric="mlogloss",
                             tree_method="hist", n_jobs=2, random_state=42)
    return KNeighborsClassifier(n_neighbors=5, weights="distance", algorithm="brute", n_jobs=2)


def write_json(path, value):
    path.parent.mkdir(exist_ok=True, parents=True)
    with NamedTemporaryFile("w", dir=path.parent, delete=False) as temp:
        json.dump(value, temp, indent=2, default=str, allow_nan=False)
        temp.write("\n")
    os.replace(temp.name, path)


def reference(path):
    return {"path": str(path.relative_to(ROOT)), "sha256": digest(path)}


def run(family, names, evaluate_only=False, retrain=False):
    train, test, y_train, y_test = load_nsl() if family == "nsl" else load_data()
    columns = SCHEMA[family]
    train, test = train[columns], test[columns]
    folder = REGISTRY / family
    folder.mkdir(parents=True, exist_ok=True)
    previous_folder = PREP if family == "full" else folder
    fit_folder = Path(mkdtemp(prefix="fit-", dir=folder)) if retrain else previous_folder
    fit_folder.mkdir(parents=True, exist_ok=True)
    enc = LabelEncoder().fit(y_train)
    y, truth = enc.transform(y_train), enc.transform(y_test)
    files = (["datasets/nsl_kdd/KDDTrain+.txt", "datasets/nsl_kdd/KDDTest+.txt"] if family == "nsl"
             else [f"datasets/unsw_nb15/UNSW_NB15_{s}-set.csv" for s in ("training", "testing")])
    source = [reference(ROOT / p) for p in files]
    for name in names:
        print(f"{family}/{name} preparing", flush=True)
        scaled = name == "knn"
        encfile = fit_folder / "label_encoder.pkl"
        pf = fit_folder / (("scaled" if scaled else "tree") + "_preprocessor.pkl")
        mf = (fit_folder if retrain else folder) / f"{name}.pkl"
        legacy = ROOT / "artifacts/models" / f"{name}.pkl"
        if not retrain and family == "full" and name in {"random_forest", "xgboost"} and legacy.exists():
            mf = legacy
        metadata_path = folder / f"{name}.json"
        previous = json.loads(metadata_path.read_text()) if metadata_path.exists() else {}
        if previous and not retrain:
            # Honor the active version after an explicit refit.
            pf, mf, encfile = [ROOT / previous["files"][key]["path"]
                               for key in ("preprocessor", "model", "encoder")]
        if evaluate_only and not all(path.exists() for path in (pf, encfile, mf)):
            raise ValueError(f"Missing trained artifacts for {name}")
        if not encfile.exists():
            joblib.dump(enc, encfile)
        if list(joblib.load(encfile).classes_) != list(enc.classes_):
            raise ValueError("Saved encoder differs from training labels")
        if not pf.exists():
            prep = build_preprocessor(scaled, columns, CATS if family == "nsl" else CATEGORICAL_FEATURES)
            joblib.dump(prep.fit(train), pf)
        prep = joblib.load(pf)
        if list(prep.feature_names_in_) != columns:
            raise ValueError("Preprocessor feature mismatch")
        seconds = previous.get("train_seconds")
        subset = np.arange(len(y))
        if name == "knn" and len(y) > 10000:
            subset, _ = train_test_split(subset, train_size=10000, stratify=y, random_state=42)
        counts = np.bincount(y[subset])
        strategy = {i: 2000 for i, n in enumerate(counts) if 0 < n < 2000}
        sampled = np.asarray(subset)
        if strategy:
            sampled, _ = RandomOverSampler(sampling_strategy=strategy, random_state=42).fit_resample(
                sampled.reshape(-1, 1), y[subset])
            sampled = sampled.ravel()
        if mf.exists():
            model = joblib.load(mf)
        else:
            model = estimator(name)
            values = matrix(prep, train.iloc[sampled], name)
            start = time.monotonic()
            model.fit(values, y[sampled])
            seconds = time.monotonic() - start
            del values
            temp = mf.with_suffix(".tmp")
            joblib.dump(model, temp, compress=2)
            temp.replace(mf)
        print(f"{family}/{name} evaluating", flush=True)
        start = time.monotonic()
        labels = []
        for i in range(0, len(test), 1024):
            values = matrix(prep, test.iloc[i:i+1024], name)
            labels.extend(model.predict_proba(values).argmax(axis=1))
        latency = time.monotonic() - start
        predicted = np.array(labels)
        classes = enc.classes_.tolist()
        report = classification_report(truth, predicted, labels=range(len(classes)),
                                       target_names=classes, zero_division=0, output_dict=True)
        rare = [classes[i] for i, n in enumerate(np.bincount(y)) if n < 2000]
        attack = truth != classes.index("Normal")
        detected = predicted != classes.index("Normal")
        metrics = {"accuracy": accuracy_score(truth, predicted),
                   "macro_precision": report["macro avg"]["precision"],
                   "macro_recall": report["macro avg"]["recall"], "macro_f1": report["macro avg"]["f1-score"],
                   "weighted_f1": report["weighted avg"]["f1-score"],
                   "minority_classes": rare, "minority_recall": float(np.mean([report[c]["recall"] for c in rare])) if rare else report["macro avg"]["recall"],
                   "binary_f1": f1_score(attack, detected), "binary_recall": recall_score(attack, detected),
                   "inference_seconds": latency, "per_class": {c: report[c] for c in classes},
                   "confusion": confusion_matrix(truth, predicted, labels=range(len(classes))).tolist()}
        refs = {"preprocessor": reference(pf), "encoder": reference(encfile), "model": reference(mf)}
        ident = hashlib.sha256(json.dumps([family, columns, refs], sort_keys=True).encode()).hexdigest()[:16]
        parameters = {k: str(v) if isinstance(v, float) and not math.isfinite(v) else v
                      for k, v in model.get_params().items()}
        record = {"family": family, "schema": columns, "name": name, "version": ident,
                  "files": refs, "sources": source, "classes": classes, "metrics": metrics,
                  "train_seconds": seconds, "train_rows": len(train), "test_rows": len(test),
                  "selected_train_rows": len(subset), "resampled_rows": len(sampled), "seed": 42,
                  "parameters": parameters, "python": platform.python_version(),
                  "packages": {p: version(p) for p in ["scikit-learn","xgboost","pandas","numpy","imbalanced-learn","joblib"]}}
        write_json(metadata_path, record)
        print(f"{family}/{name} macro-F1 {metrics['macro_f1']:.4f} accuracy {metrics['accuracy']:.4f}", flush=True)
        del model
        gc.collect()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--family", choices=SCHEMA, required=True)
    parser.add_argument("--models", nargs="+", choices=NAMES, default=NAMES)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--evaluate-only", action="store_true")
    mode.add_argument("--retrain", action="store_true", help="Fit fresh versioned models and preprocessors")
    args = parser.parse_args()
    with threadpool_limits(limits=2):
        run(args.family, args.models, args.evaluate_only, args.retrain)
