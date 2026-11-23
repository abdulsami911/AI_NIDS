
from pathlib import Path
import json
import time

import joblib
import numpy as np
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from imblearn.over_sampling import RandomOverSampler
from imblearn.pipeline import Pipeline
from xgboost import XGBClassifier


ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "datasets" / "unsw_nb15"
MODEL_DIR = ROOT / "artifacts" / "models"
REPORT_DIR = ROOT / "reports" / "evaluation"

FEATURES = [
    "proto",
    "dur",
    "spkts",
    "dpkts",
    "sinpkt",
    "dinpkt",
    "is_sm_ips_ports",
]

NUMERIC = [c for c in FEATURES if c != "proto"]

TRAIN_PATH = DATA / "UNSW_NB15_training-set.csv"
TEST_PATH = DATA / "UNSW_NB15_testing-set.csv"

MODEL_PATH = MODEL_DIR / "pcap_xgboost_7f.joblib"

MODEL_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def load_dataset(path):
    df = pd.read_csv(
        path,
        usecols=FEATURES + ["attack_cat"],
        low_memory=False,
    )

    df["proto"] = (
        df["proto"].astype(str).str.strip().str.lower()
    )

    df["attack_cat"] = (
        df["attack_cat"].astype(str).str.strip()
    )

    # The current PCAP extractor supports TCP and UDP.
    df = df[df["proto"].isin(["tcp", "udp"])].copy()

    for col in NUMERIC:
        df[col] = pd.to_numeric(
            df[col], errors="coerce"
        ).astype("float32")

    df[NUMERIC] = df[NUMERIC].replace(
        [np.inf, -np.inf], np.nan
    )

    if df.empty:
        raise ValueError(
            f"No TCP/UDP records found in {path}"
        )

    return df


print("\n=== AI-NIDS: PCAP-COMPATIBLE TRAINING ===")

train = load_dataset(TRAIN_PATH)
test = load_dataset(TEST_PATH)

print(f"Training records: {len(train):,}")
print(f"Testing records:  {len(test):,}")
print(f"Input features:   {len(FEATURES)}")

print("\nTraining class distribution:")
print(train["attack_cat"].value_counts().to_string())

X_train = train[FEATURES]
X_test = test[FEATURES]

label_encoder = LabelEncoder()

y_train = label_encoder.fit_transform(
    train["attack_cat"]
)

y_test = label_encoder.transform(
    test["attack_cat"]
)

classes = label_encoder.classes_

print("\nClass labels:")
for i, name in enumerate(classes):
    print(f"  {i}: {name}")

# Oversample minority categories in training only.
unique, counts = np.unique(
    y_train, return_counts=True
)

sampling_strategy = {
    int(cls): 2000
    for cls, count in zip(unique, counts)
    if count < 2000
}

print("\nOversampling strategy:")
print(sampling_strategy or "No oversampling required")

preprocessor = ColumnTransformer(
    transformers=[
        (
            "numeric",
            SimpleImputer(strategy="median"),
            NUMERIC,
        ),
        (
            "protocol",
            OneHotEncoder(handle_unknown="ignore"),
            ["proto"],
        ),
    ]
)

classifier = XGBClassifier(
    n_estimators=150,
    max_depth=5,
    learning_rate=0.08,
    subsample=0.8,
    colsample_bytree=0.8,
    objective="multi:softprob",
    eval_metric="mlogloss",
    tree_method="hist",
    n_jobs=2,
    random_state=42,
)

steps = [
    ("preprocessor", preprocessor),
]

if sampling_strategy:
    steps.append((
        "oversampler",
        RandomOverSampler(
            sampling_strategy=sampling_strategy,
            random_state=42,
        ),
    ))

steps.append(("classifier", classifier))

pipeline = Pipeline(steps=steps)

print("\nTraining XGBoost...")
start = time.perf_counter()

pipeline.fit(X_train, y_train)

training_time = time.perf_counter() - start

print(f"Training completed in {training_time:.2f}s")

print("\nEvaluating on the official held-out test split...")

start = time.perf_counter()
predictions = pipeline.predict(X_test)
inference_time = time.perf_counter() - start

accuracy = accuracy_score(y_test, predictions)
macro_f1 = f1_score(
    y_test, predictions, average="macro",
    zero_division=0,
)
weighted_f1 = f1_score(
    y_test, predictions, average="weighted",
    zero_division=0,
)

report = classification_report(
    y_test,
    predictions,
    labels=list(range(len(classes))),
    target_names=classes,
    zero_division=0,
)

matrix = confusion_matrix(
    y_test,
    predictions,
    labels=list(range(len(classes))),
)

# Operational binary evaluation derived from
# the multiclass model's predictions.
normal_id = int(
    label_encoder.transform(["Normal"])[0]
)

actual_attack = (y_test != normal_id).astype(int)
predicted_attack = (
    predictions != normal_id
).astype(int)

binary_precision = precision_score(
    actual_attack, predicted_attack,
    zero_division=0,
)

binary_recall = recall_score(
    actual_attack, predicted_attack,
    zero_division=0,
)

binary_f1 = f1_score(
    actual_attack, predicted_attack,
    zero_division=0,
)

print("\n=== MODEL RESULTS ===")
print(f"Accuracy:    {accuracy:.4f}")
print(f"Macro F1:    {macro_f1:.4f}")
print(f"Weighted F1: {weighted_f1:.4f}")
print(f"Attack precision: {binary_precision:.4f}")
print(f"Attack recall:    {binary_recall:.4f}")
print(f"Attack F1:        {binary_f1:.4f}")

print("\nClassification report:")
print(report)

# The pipeline contains the fitted preprocessor,
# training-only oversampler, and XGBoost model.
# During predict(), the oversampler is not applied.
artifact = {
    "pipeline": pipeline,
    "label_encoder": label_encoder,
    "features": FEATURES,
    "allowed_protocols": ["tcp", "udp"],
    "model_name": "XGBoost PCAP 7-Feature",
    "training_dataset": "UNSW-NB15",
    "feature_schema": "pcap_7f_v1",
}

joblib.dump(artifact, MODEL_PATH)

report_path = REPORT_DIR / "pcap_xgboost_7f_report.txt"

report_path.write_text(
    "AI-NIDS PCAP-Compatible XGBoost\n\n"
    f"Training records: {len(train)}\n"
    f"Testing records: {len(test)}\n"
    f"Training time: {training_time:.2f}s\n"
    f"Inference time: {inference_time:.2f}s\n"
    f"Accuracy: {accuracy:.6f}\n"
    f"Macro F1: {macro_f1:.6f}\n"
    f"Weighted F1: {weighted_f1:.6f}\n"
    f"Attack precision: {binary_precision:.6f}\n"
    f"Attack recall: {binary_recall:.6f}\n"
    f"Attack F1: {binary_f1:.6f}\n\n"
    + report,
    encoding="utf-8",
)

matrix_path = (
    REPORT_DIR / "pcap_xgboost_7f_confusion_matrix.csv"
)

pd.DataFrame(
    matrix,
    index=classes,
    columns=classes,
).to_csv(matrix_path)

metrics_path = REPORT_DIR / "pcap_xgboost_7f_metrics.json"

metrics_path.write_text(
    json.dumps(
        {
            "features": FEATURES,
            "classes": classes.tolist(),
            "train_rows": int(len(train)),
            "test_rows": int(len(test)),
            "accuracy": float(accuracy),
            "macro_f1": float(macro_f1),
            "weighted_f1": float(weighted_f1),
            "binary_attack_precision": float(binary_precision),
            "binary_attack_recall": float(binary_recall),
            "binary_attack_f1": float(binary_f1),
            "training_seconds": float(training_time),
        },
        indent=2,
    ),
    encoding="utf-8",
)

print("\n=== SAVED ARTIFACTS ===")
print(f"Model: {MODEL_PATH}")
print(f"Report: {report_path}")
print(f"Confusion matrix: {matrix_path}")
print(f"Metrics: {metrics_path}")

print("\nTraining and evaluation finished.")
