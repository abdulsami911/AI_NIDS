
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import f1_score, accuracy_score
from imblearn.over_sampling import RandomOverSampler
from imblearn.pipeline import Pipeline
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[2]

TRAIN = ROOT / "datasets/unsw_nb15/UNSW_NB15_training-set.csv"
MODEL_DIR = ROOT / "artifacts/models"
PCAP_DIR = ROOT / "reports/pcap_analysis"

F7 = [
    "proto", "dur", "spkts", "dpkts",
    "sinpkt", "dinpkt", "is_sm_ips_ports",
]
F8 = F7 + ["service"]

df = pd.read_csv(TRAIN, usecols=F8 + ["attack_cat"])

for col in ["proto", "service", "attack_cat"]:
    df[col] = df[col].fillna("-").astype(str).str.strip()

df["proto"] = df["proto"].str.lower()
df["service"] = df["service"].str.lower()
df = df[df["proto"].isin(["tcp", "udp"])].copy()

for col in F8:
    if col not in ["proto", "service"]:
        df[col] = pd.to_numeric(
            df[col], errors="coerce"
        ).replace([np.inf, -np.inf], np.nan)

encoder = LabelEncoder()
y = encoder.fit_transform(df["attack_cat"])

train_idx, val_idx = train_test_split(
    np.arange(len(df)),
    test_size=0.20,
    stratify=y,
    random_state=42,
)

print("\n=== AI-NIDS FEATURE COMPARISON ===")
print("Training rows:", len(train_idx))
print("Validation rows:", len(val_idx))

results = {}

for name, features in [
    ("Seven features", F7),
    ("Eight features", F8),
]:
    print(f"\nTraining {name}...")

    categorical = [
        col for col in features
        if col in ["proto", "service"]
    ]
    numeric = [
        col for col in features
        if col not in categorical
    ]

    preprocessor = ColumnTransformer([
        (
            "numeric",
            SimpleImputer(strategy="median"),
            numeric,
        ),
        (
            "categorical",
            OneHotEncoder(handle_unknown="ignore"),
            categorical,
        ),
    ])

    y_train = y[train_idx]
    y_val = y[val_idx]

    unique, counts = np.unique(
        y_train, return_counts=True
    )

    sampling = {
        int(cls): 2000
        for cls, count in zip(unique, counts)
        if count < 2000
    }

    pipeline = Pipeline([
        ("preprocessor", preprocessor),
        (
            "oversampler",
            RandomOverSampler(
                sampling_strategy=sampling,
                random_state=42,
            ),
        ),
        (
            "classifier",
            XGBClassifier(
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
            ),
        ),
    ])

    pipeline.fit(
        df.iloc[train_idx][features],
        y_train,
    )

    pred = pipeline.predict(
        df.iloc[val_idx][features]
    )

    normal_id = int(
        encoder.transform(["Normal"])[0]
    )

    normal = y_val == normal_id
    attacks = ~normal

    false_positives = (
        normal & (pred != normal_id)
    ).sum()

    false_negatives = (
        attacks & (pred == normal_id)
    ).sum()

    fpr = false_positives / normal.sum()
    fnr = false_negatives / attacks.sum()

    macro_f1 = f1_score(
        y_val, pred, average="macro",
        zero_division=0,
    )

    accuracy = accuracy_score(y_val, pred)

    results[name] = {
        "accuracy": accuracy,
        "macro_f1": macro_f1,
        "fpr": fpr,
        "fnr": fnr,
    }

    print(f"Accuracy: {accuracy:.2%}")
    print(f"Macro F1: {macro_f1:.4f}")
    print(f"False positive rate: {fpr:.2%}")
    print(f"False negative rate: {fnr:.2%}")

    if name == "Eight features":
        artifact = {
            "pipeline": pipeline,
            "label_encoder": encoder,
            "features": features,
            "allowed_protocols": ["tcp", "udp"],
            "model_name": "XGBoost 8F Experiment",
            "training_dataset": "UNSW-NB15",
            "feature_schema": "pcap_8f_experimental",
        }

        MODEL_DIR.mkdir(
            parents=True, exist_ok=True
        )

        joblib.dump(
            artifact,
            MODEL_DIR / "pcap_xgboost_8f_experiment.joblib",
        )

# Add only service labels supported by actual capture
# protocol evidence. Unknown services remain "-".
flows = pd.read_csv(
    PCAP_DIR / "flows.csv",
    dtype=str,
    keep_default_na=False,
)

pcap = pd.read_csv(
    PCAP_DIR / "pcap_ml_features.csv",
    dtype={"flow_id": str},
    keep_default_na=False,
)

service_map = {
    row["flow_id"]: (
        "dns"
        if row["protocol"].upper() == "DNS"
        else "-"
    )
    for _, row in flows.iterrows()
}

pcap["service"] = (
    pcap["flow_id"].map(service_map)
)

if pcap["service"].isna().any():
    raise ValueError("Unmatched flow IDs")

pcap.to_csv(
    PCAP_DIR / "pcap_ml_features_8f.csv",
    index=False,
)

print("\n=== FINAL COMPARISON ===")
print(pd.DataFrame(results).T.to_string())

print("\nExperimental model and PCAP features saved.")
print("Original seven-feature model is unchanged.")
print("Unknown service labels remain '-'.")
print("Eight-feature model is not automatically promoted.")

