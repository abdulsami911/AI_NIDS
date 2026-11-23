"""Load only project-owned, versioned artifact manifests."""
import hashlib
import json
from functools import lru_cache
from pathlib import Path

import joblib
import numpy as np
from scipy import sparse
from threadpoolctl import threadpool_limits

from src.data.nsl import COLUMNS
from src.preprocessing.preprocess import ROOT
from src.preprocessing.feature_config import CATEGORIES, SCHEMAS

REGISTRY = ROOT / "artifacts/registry"
SCHEMA = {**SCHEMAS, "nsl": COLUMNS}
NAMES = ["random_forest", "xgboost", "knn"]


def digest(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def catalog(family):
    if family not in SCHEMA:
        raise ValueError("Unknown model family")
    return [json.loads(p.read_text()) for p in sorted((REGISTRY / family).glob("*.json"))]


def preferred(models):
    # Resolve near ties using rare-class recall then latency.
    top = max(m["metrics"]["macro_f1"] for m in models)
    return max((m for m in models if m["metrics"]["macro_f1"] >= top - .005),
               key=lambda m: (m["metrics"]["minority_recall"], -m["metrics"]["inference_seconds"]))


def select(family, name=None):
    entries = catalog(family)
    if name and name != "auto":
        entries = [m for m in entries if m["name"] == name]
    if not entries:
        raise ValueError(f"No trained compatible model for {family} / {name or 'auto'}")
    return preferred(entries)


@lru_cache(maxsize=2)
def _load(family, name, version):
    manifest = select(family, name)
    if (manifest["family"], manifest["version"], manifest["schema"]) != (family, version, SCHEMA[family]):
        raise ValueError("Incompatible model manifest or feature schema")
    parts = []
    for role in ["preprocessor", "model", "encoder"]:
        item = manifest["files"][role]
        path = (ROOT / item["path"]).resolve()
        if not path.is_relative_to(ROOT / "artifacts") or digest(path) != item["sha256"]:
            raise ValueError("Artifact integrity check failed")
        parts.append(joblib.load(path))
    prep, model, enc = parts
    if (list(prep.feature_names_in_) != SCHEMA[family] or
            len(prep.get_feature_names_out()) != model.n_features_in_ or
            list(enc.classes_) != manifest["classes"] or
            (family != "nsl" and list(enc.classes_) != CATEGORIES) or
            list(model.classes_) != list(range(len(enc.classes_)))):
        raise ValueError("Incompatible model, preprocessor or label encoding")
    return prep, model, enc


def matrix(prep, frame, name):
    values = prep.transform(frame)
    if name == "knn" and sparse.issparse(values):
        values = values.toarray()
    return values.astype(np.float64 if name == "knn" else np.float32)


def predict(frame, manifest):
    family, name = manifest["family"], manifest["name"]
    if list(frame.columns) != SCHEMA[family] or manifest["schema"] != SCHEMA[family]:
        raise ValueError(f"Incompatible {family} feature schema or ordering")
    prep, model, enc = _load(family, name, manifest["version"])
    with threadpool_limits(limits=2):
        values = matrix(prep, frame, name)
        prob = model.predict_proba(values)
    indices = prob.argmax(axis=1)
    return list(zip(enc.inverse_transform(indices).tolist(), prob.max(axis=1).astype(float).tolist()))
