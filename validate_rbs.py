import pandas as pd
from rbs_engine import calculate_rbs

def main():
    dataset_path = 'synthetic_login_data_final_audited.csv'
    
    # 1. Load dataset
    df = pd.read_csv(dataset_path)
    
    # 2. Check for missing values in required columns
    required_cols = [
        'is_new_country', 'is_new_device', 'location_change', 
        'ip_risk_score', 'failed_login_attempts'
    ]
    missing_info = df[required_cols].isnull().sum()
    print("--- Missing Values in Required Columns ---")
    print(missing_info)
    print("\n")

    # 3. Calculate RBS
    df_result = calculate_rbs(df)
    
    # 4. Reporting
    total_rows = len(df_result)
    print(f"--- General Report ---")
    print(f"Number of rows processed: {total_rows}")
    
    print("\n--- RBS Score Distribution ---")
    print(df_result['rbs_score'].describe())
    
    print("\n--- RBS Level Classifications ---")
    level_counts = df_result['rbs_level'].value_counts()
    for level, count in level_counts.items():
        percentage = (count / total_rows) * 100
        print(f"{level}: {count} ({percentage:.2f}%)")
        
    print("\n--- Triggered Rules Frequency ---")
    # To get individual rule triggers we split 'risk_reasons'
    rule_counts = {}
    for reasons in df_result['risk_reasons']:
        if reasons == "Normal":
            continue
        rules = [r.strip() for r in reasons.split(",")]
        for r in rules:
            rule_counts[r] = rule_counts.get(r, 0) + 1
            
    for rule, count in sorted(rule_counts.items(), key=lambda item: item[1], reverse=True):
        print(f"{rule}: {count} ({(count / total_rows) * 100:.2f}%)")
        
    print("\n--- Top 5 Combinations of Triggered Rules ---")
    combo_counts = df_result['risk_reasons'].value_counts().head(5)
    for combo, count in combo_counts.items():
        if combo != "Normal":
            print(f"{combo}: {count} ({(count / total_rows) * 100:.2f}%)")
            
    print("\n--- Representative Examples ---")
    # Take a few samples for each level
    for level in ['LOW', 'MEDIUM', 'HIGH']:
        sample = df_result[df_result['rbs_level'] == level].head(2)
        for _, row in sample.iterrows():
            print(f"Level: {level}")
            print(f"  Inputs: New Country={row['is_new_country']}, New Device={row['is_new_device']}, "
                  f"Location Change={row['location_change']}, IP Risk={row['ip_risk_score']:.2f}, "
                  f"Failed Attempts={row['failed_login_attempts']}")
            print(f"  RBS Score: {row['rbs_score']}")
            print(f"  Reasons: {row['risk_reasons']}")
            print("-" * 30)

if __name__ == "__main__":
    main()
