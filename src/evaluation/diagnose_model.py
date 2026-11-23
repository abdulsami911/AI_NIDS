
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]

MODEL_FILE = ROOT / "artifacts/models/pcap_xgboost_7f.joblib"
TEST_FILE = ROOT / "datasets/unsw_nb15/UNSW_NB15_testing-set.csv"
PCAP_FILE = ROOT / "reports/pcap_analysis/pcap_ml_features.csv"

artifact = joblib.load(MODEL_FILE)

model = artifact["pipeline"]
encoder = artifact["label_encoder"]
features = artifact["features"]

print("\n========== AI-NIDS MODEL DIAGNOSTICS ==========")
print("Model:", artifact["model_name"])
print("Training dataset:", artifact["training_dataset"])
print("Features:", features)

# Load the official held-out test records.
test = pd.read_csv(TEST_FILE, usecols=features + ["attack_cat"])

test["proto"] = (
    test["proto"].astype(str).str.strip().str.lower()
)
test["attack_cat"] = test["attack_cat"].astype(str).str.strip()

test = test[
    test["proto"].isin(artifact["allowed_protocols"])
].copy()

for feature in features:
    if feature != "proto":
        test[feature] = pd.to_numeric(
            test[feature], errors="coerce"
        ).replace([np.inf, -np.inf], np.nan)

# Predict using the existing saved model.
predictions = model.predict(test[features])
predicted_names = encoder.inverse_transform(
    np.asarray(predictions).astype(int)
)

test["predicted"] = predicted_names

normal = test["attack_cat"] == "Normal"
attacks = ~normal

false_alarms = test[
    normal & (test["predicted"] != "Normal")
]

missed_attacks = test[
    attacks & (test["predicted"] == "Normal")
]

normal_count = int(normal.sum())
attack_count = int(attacks.sum())

false_positive_rate = len(false_alarms) / max(normal_count, 1)
false_negative_rate = len(missed_attacks) / max(attack_count, 1)

print("\n========== FALSE ALARM ANALYSIS ==========")
print("Actual normal flows:", normal_count)
print("Normal flows flagged as attacks:", len(false_alarms))
print(f"False positive rate: {false_positive_rate:.2%}")

print("\nWrong predictions on normal traffic:")
print(false_alarms["predicted"].value_counts().to_string())

print("\n========== MISSED ATTACK ANALYSIS ==========")
print("Actual attack flows:", attack_count)
print("Attacks predicted as Normal:", len(missed_attacks))
print(f"False negative rate: {false_negative_rate:.2%}")

# Compare Normal flow measurements with the
# real Wireshark capture feature distribution.
print("\n========== PCAP FEATURE COMPARISON ==========")

if PCAP_FILE.exists():
    pcap = pd.read_csv(PCAP_FILE)

    numeric_features = [
        f for f in features if f != "proto"
    ]

    for feature in numeric_features:
        pcap[feature] = pd.to_numeric(
            pcap[feature], errors="coerce"
        )

    normal_test = test.loc[normal]

    for feature in numeric_features:
        dataset_median = normal_test[feature].median()
        pcap_median = pcap[feature].median()

        print(
            f"{feature:20s} "
            f"UNSW Normal median={dataset_median:.4f} | "
            f"PCAP median={pcap_median:.4f}"
        )

    print("\nPCAP DNS flow measurements:")
    dns = pcap[
        (pcap["dst_port"].astype(str) == "53")
        | (pcap["src_port"].astype(str) == "53")
    ]

    columns = [
        "flow_id", "dur", "spkts",
        "dpkts", "sinpkt", "dinpkt"
    ]

    print(
        dns[columns].head(12).to_string(index=False)
        if not dns.empty else "No DNS-port flows found."
    )

print("\n========== DIAGNOSIS COMPLETE ==========")
