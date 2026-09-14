import numpy as np

from if_engine import calculate_if_score
from rbs_engine import calculate_rbs


RBS_WEIGHT = 0.60
IF_WEIGHT = 0.40

LOW_ACTION = "ALLOW / PASSWORD"
MEDIUM_ACTION = "PASSWORD + OTP"
HIGH_ACTION = "STRONG STEP-UP / BLOCK"

LEAKAGE_COLUMNS = {
    "risk_score",
    "risk_level",
    "required_action",
    "final_risk_score",
    "final_risk_level",
    "rbs_score",
    "rbs_level",
    "if_score",
    "if_anomaly_flag",
    "if_raw_score",
}

OUTPUT_COLUMNS = [
    "rbs_score",
    "rbs_level",
    "risk_reasons",
    "if_score",
    "if_anomaly_flag",
    "final_risk_score",
    "final_risk_level",
    "required_action",
]


def _level_from_score(score):
    if score < 30:
        return "LOW"
    if score < 60:
        return "MEDIUM"
    return "HIGH"


def _action_from_level(level):
    if level == "LOW":
        return LOW_ACTION
    if level == "MEDIUM":
        return MEDIUM_ACTION
    return HIGH_ACTION


def _remove_leakage_columns(df):
    columns_to_drop = [col for col in LEAKAGE_COLUMNS if col in df.columns]
    return df.drop(columns=columns_to_drop)


def _preserve_output_collisions(df):
    result = df.copy()
    for column in OUTPUT_COLUMNS:
        if column in result.columns:
            preserved_name = f"original_{column}"
            suffix = 2
            while preserved_name in result.columns:
                preserved_name = f"original_{column}_{suffix}"
                suffix += 1
            result[preserved_name] = result[column]
    return result


def calculate_final_risk(df):
    """
    Calculate final 60/40 weighted risk scores for login attempts.

    The function reuses the existing rule-based scoring engine and trained
    Isolation Forest engine. Prior risk outputs are excluded before those
    engines run, preventing data leakage while preserving the caller's original
    non-derived input columns in the returned DataFrame.
    """
    original_df = df.copy()
    engine_input = _remove_leakage_columns(original_df)

    rbs_result = calculate_rbs(engine_input)
    if_result = calculate_if_score(engine_input)

    result = _preserve_output_collisions(original_df)
    result["rbs_score"] = rbs_result["rbs_score"]
    result["rbs_level"] = rbs_result["rbs_level"]
    result["risk_reasons"] = rbs_result["risk_reasons"]
    result["if_score"] = if_result["if_score"]
    result["if_anomaly_flag"] = if_result["if_anomaly_flag"]

    weighted_scores = (
        (RBS_WEIGHT * result["rbs_score"].astype(float))
        + (IF_WEIGHT * result["if_score"].astype(float))
    )
    result["final_risk_score"] = np.clip(weighted_scores, 0, 100).round(2)
    result["final_risk_level"] = result["final_risk_score"].apply(_level_from_score)
    result["required_action"] = result["final_risk_level"].apply(_action_from_level)

    return result
