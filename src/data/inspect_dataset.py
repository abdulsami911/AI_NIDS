
import pandas as pd
from pathlib import Path

base = Path(__file__).resolve().parents[2]

train_path = base / "datasets/unsw_nb15/UNSW_NB15_training-set.csv"
test_path = base / "datasets/unsw_nb15/UNSW_NB15_testing-set.csv"

def inspect_dataset(path, name):

    print("\n" + "=" * 60)
    print(name)
    print("=" * 60)

    if not path.exists():
        print("File not found:", path)
        return

    df = pd.read_csv(path)

    print("\nDataset shape:")
    print(df.shape)

    print("\nColumn names:")
    print(df.columns.tolist())

    print("\nData types:")
    print(df.dtypes)

    print("\nMissing values:")
    print(df.isnull().sum().sort_values(ascending=False).head(15))

    print("\nDuplicate rows:")
    print(df.duplicated().sum())

    if "label" in df.columns:
        print("\nBinary class distribution:")
        print(df["label"].value_counts())

    if "attack_cat" in df.columns:
        print("\nAttack category distribution:")
        print(df["attack_cat"].value_counts(dropna=False))

    print("\nFirst five records:")
    print(df.head())

    print("\nStatistical summary:")
    print(df.describe(include="all").T)

inspect_dataset(train_path, "TRAINING DATASET")
inspect_dataset(test_path, "TESTING DATASET")
