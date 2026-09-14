import pandas as pd
import numpy as np
from if_engine import calculate_if_score
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score
import warnings

def main():
    warnings.filterwarnings('ignore')
    dataset_path = 'synthetic_login_data_final_audited.csv'
    df = pd.read_csv(dataset_path)
    
    # 1. Calculate IF scores
    df_result = calculate_if_score(df)
    
    # 2. Basic Statistics
    print("--- IF Score Statistics ---")
    print(f"Minimum IF score: {df_result['if_score'].min()}")
    print(f"Maximum IF score: {df_result['if_score'].max()}")
    print(f"Mean IF score: {df_result['if_score'].mean():.2f}")
    print(f"Median IF score: {df_result['if_score'].median():.2f}")
    print(f"Standard deviation: {df_result['if_score'].std():.2f}")
    
    percentiles = [50, 75, 90, 95, 99]
    for p in percentiles:
        print(f"P{p}: {np.percentile(df_result['if_score'], p):.2f}")
        
    print("\n--- Binary Anomaly Statistics ---")
    num_anomalies = df_result['if_anomaly_flag'].sum()
    pct_anomalies = (num_anomalies / len(df_result)) * 100
    print(f"Number of anomalies: {num_anomalies}")
    print(f"Percentage of anomalies: {pct_anomalies:.2f}%")
    
    print("\n--- IF Score Distribution ---")
    d0_29 = len(df_result[(df_result['if_score'] >= 0) & (df_result['if_score'] < 30)])
    d30_59 = len(df_result[(df_result['if_score'] >= 30) & (df_result['if_score'] < 60)])
    d60_100 = len(df_result[(df_result['if_score'] >= 60) & (df_result['if_score'] <= 100)])
    
    print(f"IF score 0-29: {d0_29} ({(d0_29 / len(df_result))*100:.2f}%)")
    print(f"IF score 30-59: {d30_59} ({(d30_59 / len(df_result))*100:.2f}%)")
    print(f"IF score 60-100: {d60_100} ({(d60_100 / len(df_result))*100:.2f}%)")
    
    # 3. Evaluation against synthetic labels
    print("\n--- Evaluation Against Synthetic Labels (risk_level) ---")
    print("Note: Isolation Forest is an unsupervised model. These metrics are evaluated against synthetic labels.")
    
    if 'risk_level' in df_result.columns:
        # Ground truth: 1 if High or Critical, else 0
        y_true = df_result['risk_level'].isin(['High', 'Critical']).astype(int)
        y_pred = df_result['if_anomaly_flag']
        
        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        cm = confusion_matrix(y_true, y_pred)
        
        try:
            auc = roc_auc_score(y_true, df_result['if_score'])
        except Exception as e:
            auc = None
            
        print(f"Accuracy: {acc:.4f}")
        print(f"Precision: {prec:.4f}")
        print(f"Recall: {rec:.4f}")
        print(f"F1-score: {f1:.4f}")
        if auc:
            print(f"ROC-AUC: {auc:.4f}")
        print("Confusion Matrix:")
        print(cm)
    
    print("\n--- Demonstration ---")
    # Sample a normal
    normal_sample = df_result[df_result['if_anomaly_flag'] == 0].head(1)
    # Sample a moderately unusual
    mod_sample = df_result[(df_result['if_score'] >= 40) & (df_result['if_score'] <= 60)].head(1)
    if mod_sample.empty:
        mod_sample = df_result[(df_result['if_score'] >= 30) & (df_result['if_score'] <= 70)].head(1)
    # Sample a highly anomalous
    anom_sample = df_result[df_result['if_anomaly_flag'] == 1].sort_values(by='if_score', ascending=False).head(1)
    
    if not normal_sample.empty:
        print("\nNormal example")
        print(f"IF Score: {normal_sample['if_score'].values[0]}")
        print(f"IF Flag: {'Anomaly' if normal_sample['if_anomaly_flag'].values[0] == 1 else 'Normal'}")
        
    if not mod_sample.empty:
        print("\nModerately unusual example")
        print(f"IF Score: {mod_sample['if_score'].values[0]}")
        print(f"IF Flag: {'Anomaly' if mod_sample['if_anomaly_flag'].values[0] == 1 else 'Normal'}")
        
    if not anom_sample.empty:
        print("\nHighly anomalous example")
        print(f"IF Score: {anom_sample['if_score'].values[0]}")
        print(f"IF Flag: {'Anomaly' if anom_sample['if_anomaly_flag'].values[0] == 1 else 'Normal'}")

if __name__ == "__main__":
    main()
