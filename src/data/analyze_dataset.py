
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path

base = Path(__file__).resolve().parents[2]

train_path = base / "datasets/unsw_nb15/UNSW_NB15_training-set.csv"
test_path = base / "datasets/unsw_nb15/UNSW_NB15_testing-set.csv"

output = base / "reports/figures"
output.mkdir(parents=True, exist_ok=True)

df = pd.read_csv(train_path)

sns.set_theme(style="whitegrid")

print("\nDATASET INFORMATION")
print(df.shape)
print(df.info())

print("\nATTACK DISTRIBUTION")
print(df["attack_cat"].value_counts())

print("\nATTACK PERCENTAGES")
print(df["attack_cat"].value_counts(normalize=True) * 100)

print("\nCATEGORICAL FEATURE DISTRIBUTION")

for col in ["proto", "service", "state"]:

    print("\n", col)
    print(df[col].value_counts().head(15))

    plt.figure(figsize=(12, 6))

    df[col].value_counts().head(15).plot(kind="bar")

    plt.title(col + " Distribution")
    plt.xlabel(col)
    plt.ylabel("Number of Records")
    plt.xticks(rotation=45)

    plt.tight_layout()
    plt.savefig(output / (col + "_distribution.png"))
    plt.close()

print("\nATTACK CATEGORY CHART")

plt.figure(figsize=(12, 6))

df["attack_cat"].value_counts().plot(kind="bar")

plt.title("UNSW-NB15 Attack Category Distribution")
plt.xlabel("Attack Category")
plt.ylabel("Number of Records")
plt.xticks(rotation=45)

plt.tight_layout()
plt.savefig(output / "attack_distribution.png")
plt.close()

print("\nNUMERICAL FEATURE DISTRIBUTIONS")

numeric = df.select_dtypes(include="number").drop(
    columns=["id", "label"],
    errors="ignore"
)

for col in numeric.columns:

    plt.figure(figsize=(8, 4))

    sns.histplot(df[col], bins=50, kde=True)

    plt.title(col + " Distribution")
    plt.xlabel(col)
    plt.ylabel("Frequency")

    plt.tight_layout()
    plt.savefig(output / (col + "_distribution.png"))
    plt.close()

print("\nCORRELATION ANALYSIS")

correlation = numeric.corr()

plt.figure(figsize=(18, 14))

sns.heatmap(
    correlation,
    cmap="coolwarm",
    center=0
)

plt.title("UNSW-NB15 Feature Correlation")

plt.tight_layout()
plt.savefig(output / "correlation_matrix.png")
plt.close()

print("\nEDA COMPLETED")
print("Charts saved in:", output)
