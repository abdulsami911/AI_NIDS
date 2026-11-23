from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler, LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

if __package__:
    from .feature_config import CATEGORICAL_FEATURES, FULL, TARGET, DROP_COLUMNS, CATEGORIES
else:
    from feature_config import CATEGORICAL_FEATURES, FULL, TARGET, DROP_COLUMNS, CATEGORIES

ROOT = Path(__file__).resolve().parents[2]
UNSW = ROOT / "datasets/unsw_nb15"
PREP = ROOT / "artifacts/preprocessing"


def load_split(path):
    data = pd.read_csv(path)
    if set(data) != set(FULL + DROP_COLUMNS + [TARGET]):
        raise ValueError(f"Unexpected UNSW feature or target schema in {path.name}")
    y = data[TARGET]
    if y.isna().any() or not set(y) <= set(CATEGORIES):
        raise ValueError("Missing or unknown attack category")
    if not data["label"].eq(y.ne("Normal").astype(int)).all():
        raise ValueError("Binary label disagrees with attack category")
    return data[FULL], y


def load_data():
    train, y_train = load_split(UNSW / "UNSW_NB15_training-set.csv")
    test, y_test = load_split(UNSW / "UNSW_NB15_testing-set.csv")
    return train, test, y_train, y_test


def build_preprocessor(scaled=False, columns=FULL, categorical=CATEGORICAL_FEATURES):
    numeric_steps = [("imputer", SimpleImputer(strategy="median"))]
    if scaled:
        numeric_steps.append(("scaler", StandardScaler()))
    cats = [c for c in columns if c in categorical]
    return ColumnTransformer([
        ("numeric", Pipeline(numeric_steps), [c for c in columns if c not in cats]),
        ("categorical", Pipeline([
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("encoder", OneHotEncoder(handle_unknown="ignore"))
        ]), cats)
    ])


if __name__ == "__main__":
    train, test, labels, _ = load_data()
    PREP.mkdir(parents=True, exist_ok=True)
    for name, scaled in [("tree", False), ("scaled", True)]:
        model = build_preprocessor(scaled).fit(train)
        print(name, model.transform(test.iloc[:1]).shape)
        joblib.dump(model, PREP / f"{name}_preprocessor.pkl")
    joblib.dump(LabelEncoder().fit(labels), PREP / "label_encoder.pkl")
