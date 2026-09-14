import warnings

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from risk_engine import calculate_final_risk


DATASET_PATH = "synthetic_login_data_final_audited.csv"
POSITIVE_LABELS = {"HIGH", "CRITICAL"}


def print_score_statistics(df):
    score = df["final_risk_score"]

    print("--- Final Risk Score Statistics ---")
    print(f"Min: {score.min():.2f}")
    print(f"Max: {score.max():.2f}")
    print(f"Mean: {score.mean():.2f}")
    print(f"Median: {score.median():.2f}")
    print(f"Standard deviation: {score.std():.2f}")

    for percentile in [50, 75, 90, 95, 99]:
        print(f"P{percentile}: {np.percentile(score, percentile):.2f}")


def print_distribution(df, column, title, ordered_values=None):
    total = len(df)
    counts = df[column].value_counts()

    print(f"\n--- {title} ---")
    values = ordered_values if ordered_values is not None else counts.index.tolist()
    for value in values:
        count = int(counts.get(value, 0))
        percentage = (count / total) * 100 if total else 0
        print(f"{value}: {count} ({percentage:.2f}%)")


def get_binary_labels(df):
    if "risk_level" not in df.columns:
        raise ValueError("The dataset must contain 'risk_level' for label evaluation.")

    return df["risk_level"].astype(str).str.upper().isin(POSITIVE_LABELS).astype(int)


def print_metrics(name, y_true, y_pred, y_score):
    print(f"\n--- {name} Metrics ---")
    print(f"Accuracy: {accuracy_score(y_true, y_pred):.4f}")
    print(f"Precision: {precision_score(y_true, y_pred, zero_division=0):.4f}")
    print(f"Recall: {recall_score(y_true, y_pred, zero_division=0):.4f}")
    print(f"F1-score: {f1_score(y_true, y_pred, zero_division=0):.4f}")
    print("Confusion Matrix:")
    print(confusion_matrix(y_true, y_pred, labels=[0, 1]))

    if y_true.nunique() == 2:
        print(f"ROC-AUC: {roc_auc_score(y_true, y_score):.4f}")
    else:
        print("ROC-AUC: not valid because only one label class is present")


def build_metric_inputs(df):
    y_true = get_binary_labels(df)

    return {
        "RBS-only": {
            "y_true": y_true,
            "y_pred": (df["rbs_level"] == "HIGH").astype(int),
            "y_score": df["rbs_score"],
        },
        "IF-only": {
            "y_true": y_true,
            "y_pred": df["if_anomaly_flag"].astype(int),
            "y_score": df["if_score"],
        },
        "Final weighted-engine": {
            "y_true": y_true,
            "y_pred": (df["final_risk_level"] == "HIGH").astype(int),
            "y_score": df["final_risk_score"],
        },
    }


def print_representative_examples(df):
    columns = [
        "rbs_score",
        "rbs_level",
        "risk_reasons",
        "if_score",
        "if_anomaly_flag",
        "final_risk_score",
        "final_risk_level",
        "required_action",
    ]

    samples = []
    for level in ["LOW", "MEDIUM", "HIGH"]:
        level_rows = df[df["final_risk_level"] == level]
        if not level_rows.empty:
            samples.append(level_rows.sort_values("final_risk_score").head(2))

    examples = pd.concat(samples, ignore_index=True).head(6) if samples else df.head(5)

    print("\n--- Representative Examples ---")
    for index, row in examples.iterrows():
        print(f"\nExample {index + 1}")
        for column in columns:
            print(f"{column}: {row[column]}")


def print_recommendation(df, metric_inputs):
    rbs_f1 = f1_score(
        metric_inputs["RBS-only"]["y_true"],
        metric_inputs["RBS-only"]["y_pred"],
        zero_division=0,
    )
    if_f1 = f1_score(
        metric_inputs["IF-only"]["y_true"],
        metric_inputs["IF-only"]["y_pred"],
        zero_division=0,
    )
    final_f1 = f1_score(
        metric_inputs["Final weighted-engine"]["y_true"],
        metric_inputs["Final weighted-engine"]["y_pred"],
        zero_division=0,
    )
    high_pct = (df["final_risk_level"].eq("HIGH").mean() * 100)
    medium_pct = (df["final_risk_level"].eq("MEDIUM").mean() * 100)

    print("\n--- Summary Recommendation ---")
    print("The 60/40 weighted engine ran without retraining or threshold tuning.")
    print(f"Final F1-score: {final_f1:.4f}")
    print(f"RBS-only F1-score: {rbs_f1:.4f}")
    print(f"IF-only F1-score: {if_f1:.4f}")
    print(f"Final HIGH distribution: {high_pct:.2f}%")
    print(f"Final MEDIUM distribution: {medium_pct:.2f}%")

    if final_f1 >= max(rbs_f1, if_f1):
        print("Recommendation: keep the explicit 60/40 setup for the prototype baseline.")
    else:
        print(
            "Recommendation: evaluate alternate weights or thresholds in a separate "
            "tuning task; do not silently change the 60/40 baseline."
        )


def main():
    warnings.filterwarnings("ignore")

    df = pd.read_csv(DATASET_PATH)
    result = calculate_final_risk(df)

    print(f"Rows evaluated: {len(result)}")
    print_score_statistics(result)
    print_distribution(
        result,
        "final_risk_level",
        "Final Risk Distribution",
        ordered_values=["LOW", "MEDIUM", "HIGH"],
    )
    print_distribution(result, "required_action", "Authentication Action Distribution")

    print("\n--- Evaluation Against Synthetic Labels ---")
    print("Positive/suspicious class: existing risk_level in {High, Critical}")
    metric_inputs = build_metric_inputs(result)
    for name, inputs in metric_inputs.items():
        print_metrics(name, inputs["y_true"], inputs["y_pred"], inputs["y_score"])

    print_representative_examples(result)
    print_recommendation(result, metric_inputs)


if __name__ == "__main__":
    main()
