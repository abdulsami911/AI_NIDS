
import sys
from pathlib import Path

import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score
)

sys.path.append(
    str(Path(__file__).resolve().parents[1] / "preprocessing")
)

from feature_config import TARGET, DROP_COLUMNS

from imblearn.over_sampling import RandomOverSampler

base = Path(__file__).resolve().parents[2]

train_path = base / "datasets/unsw_nb15/UNSW_NB15_training-set.csv"
test_path = base / "datasets/unsw_nb15/UNSW_NB15_testing-set.csv"

preprocessing_path = base / "artifacts/preprocessing"
model_path = base / "artifacts/models"
evaluation_path = base / "reports/evaluation"

model_path.mkdir(parents=True, exist_ok=True)
evaluation_path.mkdir(parents=True, exist_ok=True)

print("LOADING DATA")

train = pd.read_csv(train_path)
test = pd.read_csv(test_path)

X_train = train.drop(columns=DROP_COLUMNS + [TARGET])
X_test = test.drop(columns=DROP_COLUMNS + [TARGET])

y_train = train[TARGET]
y_test = test[TARGET]

print("Training:", X_train.shape)
print("Testing:", X_test.shape)

print("\nLOADING PREPROCESSORS")

preprocessor = joblib.load(
    preprocessing_path / "tree_preprocessor.pkl"
)

label_encoder = joblib.load(
    preprocessing_path / "label_encoder.pkl"
)

X_train = preprocessor.transform(X_train)
X_test = preprocessor.transform(X_test)

y_train = label_encoder.transform(y_train)
y_test = label_encoder.transform(y_test)

print("Transformed training:", X_train.shape)
print("Transformed testing:", X_test.shape)

print("\nCLASS DISTRIBUTION BEFORE BALANCING")

class_names = label_encoder.classes_

before_counts = pd.Series(y_train).value_counts().sort_index()

for index, count in before_counts.items():
    print(class_names[index], ":", count)

print("\nAPPLYING RANDOM OVERSAMPLING")

sampling_strategy = {
    index: 2000
    for index, count in before_counts.items()
    if count < 2000
}

oversampler = RandomOverSampler(
    sampling_strategy=sampling_strategy,
    random_state=42
)

X_train_balanced, y_train_balanced = oversampler.fit_resample(
    X_train,
    y_train
)

after_counts = pd.Series(y_train_balanced).value_counts().sort_index()

print("\nCLASS DISTRIBUTION AFTER BALANCING")

for index, count in after_counts.items():
    print(class_names[index], ":", count)

print("\nBUILDING RANDOM FOREST")

model = RandomForestClassifier(
    n_estimators=100,
    max_depth=25,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=2
)

print("\nTRAINING MODEL")

model.fit(X_train_balanced, y_train_balanced)

print("\nMAKING PREDICTIONS")

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)
macro_f1 = f1_score(y_test, predictions, average="macro")
weighted_f1 = f1_score(y_test, predictions, average="weighted")

print("\nMODEL RESULTS")
print("Accuracy:", accuracy)
print("Macro F1:", macro_f1)
print("Weighted F1:", weighted_f1)

report = classification_report(
    y_test,
    predictions,
    labels=list(range(len(class_names))),
    target_names=class_names,
    zero_division=0
)

print("\nCLASSIFICATION REPORT")
print(report)

matrix = confusion_matrix(
    y_test,
    predictions,
    labels=list(range(len(class_names)))
)

matrix_df = pd.DataFrame(
    matrix,
    index=class_names,
    columns=class_names
)

matrix_df.to_csv(
    evaluation_path / "random_forest_confusion_matrix.csv"
)

with open(
    evaluation_path / "random_forest_report.txt",
    "w"
) as file:
    file.write("Accuracy: " + str(accuracy) + "\n")
    file.write("Macro F1: " + str(macro_f1) + "\n")
    file.write("Weighted F1: " + str(weighted_f1) + "\n\n")
    file.write(report)

print("\nSAVING MODEL")

joblib.dump(
    model,
    model_path / "random_forest.pkl"
)

print("\nRANDOM FOREST TRAINING COMPLETED")
