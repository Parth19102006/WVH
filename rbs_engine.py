import pandas as pd
import numpy as np

def calculate_rbs(df):
    """
    Calculates the Rule-Based Selection (RBS) score and level for login attempts.
    
    The score is based on explicitly defined explicit security signals:
    - New Country (+25)
    - New Device (+20)
    - Location Change (+20)
    - High IP Risk Score > 0.70 (+20)
    - Failed Login Attempts (>=5 is +25, >=3 is +15)

    Args:
        df: Pandas DataFrame containing login attempt data.

    Returns:
        Pandas DataFrame: A copy of the input DataFrame with 'rbs_score', 'rbs_level', 
                          and 'risk_reasons' columns added.
    """
    df_out = df.copy()

    # Required columns check
    required_cols = [
        'is_new_country', 'is_new_device', 'location_change', 
        'ip_risk_score', 'failed_login_attempts'
    ]
    for col in required_cols:
        if col not in df_out.columns:
            raise ValueError(f"Required column '{col}' is missing from the dataset.")

    # Fill nulls to prevent errors during evaluation
    df_out['is_new_country'] = df_out['is_new_country'].fillna(0)
    df_out['is_new_device'] = df_out['is_new_device'].fillna(0)
    df_out['location_change'] = df_out['location_change'].fillna(0)
    df_out['ip_risk_score'] = df_out['ip_risk_score'].fillna(0.0)
    df_out['failed_login_attempts'] = df_out['failed_login_attempts'].fillna(0)

    # Calculate raw scores and reasons
    rbs_raw_scores = []
    all_risk_reasons = []

    for index, row in df_out.iterrows():
        points = 0
        reasons = []

        # Rule 1: New Country (+25 points)
        if row['is_new_country'] == 1:
            points += 25
            reasons.append("New Country")

        # Rule 2: New Device (+20 points)
        if row['is_new_device'] == 1:
            points += 20
            reasons.append("New Device")

        # Rule 3: Location Change (+20 points)
        if row['location_change'] == 1:
            points += 20
            reasons.append("Location Change")

        # Rule 4: IP Risk (+20 points if > 0.70)
        if row['ip_risk_score'] > 0.70:
            points += 20
            reasons.append("High-Risk IP")

        # Rule 5: Failed Login Attempts
        if row['failed_login_attempts'] >= 5:
            points += 25
            reasons.append("Multiple Failed Attempts")
        elif row['failed_login_attempts'] >= 3:
            points += 15
            reasons.append("Multiple Failed Attempts")

        # Cap points at 100
        final_points = min(points, 100)
        rbs_raw_scores.append(final_points)

        # Formatting risk reasons
        if not reasons:
            all_risk_reasons.append("Normal")
        else:
            all_risk_reasons.append(", ".join(reasons))

    df_out['rbs_score'] = rbs_raw_scores
    df_out['risk_reasons'] = all_risk_reasons

    # Calculate rbs_level based on rbs_score
    def get_level(score):
        if score < 30:
            return "LOW"
        elif score < 60:
            return "MEDIUM"
        else:
            return "HIGH"
            
    df_out['rbs_level'] = df_out['rbs_score'].apply(get_level)

    return df_out
