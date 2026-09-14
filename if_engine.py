import pandas as pd
import numpy as np
import pickle

def calculate_if_score(df, model_path="isolation_forest_pipeline.pkl", features_path="features.pkl"):
    """
    Calculates the Isolation Forest (IF) anomaly score and flag.
    
    - uses decision_function() to get the raw score.
    - IsolationForest decision_function outputs lower values for more anomalous instances.
    - We invert the decision_function output so that higher values = more anomalous.
    - We normalize the inverted score to a 0-100 range using Min-Max scaling on the dataset.
    - The if_anomaly_flag is derived from pipeline.predict(): -1 becomes 1 (anomaly), 1 becomes 0 (normal).
    """
    df_out = df.copy()

    with open(model_path, 'rb') as f:
        # Patch for loading sklearn 1.6.1 model in 1.9.0
        import sklearn.compose._column_transformer
        if not hasattr(sklearn.compose._column_transformer, '_RemainderColsList'):
            sklearn.compose._column_transformer._RemainderColsList = type('_RemainderColsList', (object,), {})
        from sklearn.impute import SimpleImputer
        if not hasattr(SimpleImputer, '_fill_dtype'):
            SimpleImputer._fill_dtype = property(lambda self: self.statistics_.dtype)
        pipeline = pickle.load(f)
        
    with open(features_path, 'rb') as f:
        features = pickle.load(f)
        
    for col in features:
        if col not in df_out.columns:
            raise ValueError(f"Missing feature: {col}")
            
    X = df_out[features]
    
    preds = pipeline.predict(X)
    df_out['if_anomaly_flag'] = np.where(preds == -1, 1, 0)
    
    raw_scores = pipeline.decision_function(X)
    df_out['if_raw_score'] = raw_scores
    
    inverted_scores = -raw_scores
    
    min_val = np.min(inverted_scores)
    max_val = np.max(inverted_scores)
    
    if max_val > min_val:
        normalized_scores = (inverted_scores - min_val) / (max_val - min_val) * 100.0
    else:
        normalized_scores = np.zeros_like(inverted_scores)
        
    df_out['if_score'] = np.round(normalized_scores, 2)
    
    return df_out
