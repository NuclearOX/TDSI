import pandas as pd
import statsmodels.api as sm
from statsmodels.stats.outliers_influence import variance_inflation_factor
import os
import sys
import numpy as np

# --- CONFIGURATION ---
INPUT_CSV = os.path.join('data', 'output', 'dataset_final.csv')
OUTPUT_DIR = os.path.join('data', 'output', 'figures')

# Create output directory if it doesn't exist
os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_data():
    """
    Loads the CSV dataset handling potential missing files or parsing errors.
    """
    if not os.path.exists(INPUT_CSV):
        print(f"ERROR: File {INPUT_CSV} not found.")
        sys.exit(1)
    try:
        df = pd.read_csv(INPUT_CSV)
    except:
        # Fallback engine for files with inconsistent formatting
        df = pd.read_csv(INPUT_CSV, sep=',', on_bad_lines='skip', engine='python')
    return df

def analyze_advanced_rq1():
    print("--- RQ1: Advanced Multivariate Analysis (OLS Regression & VIF) ---")
    
    df = load_data()
    print(f"Raw rows loaded: {len(df)}")
    
    # 1. Cleaning and Preparation
    # Include ALL structural metrics extracted by the miner
    numeric_cols = [
        'loc', 'num_resources', 'num_modules', 'num_providers', 
        'iac_mccabe_complexity', 'hard_coded_values', 'comment_lines',
        'internal_references', 'num_variables', 'num_outputs',
        'security_debt_score'
    ]
    
    # Filter existing columns and convert them to numeric types
    cols = [c for c in numeric_cols if c in df.columns]
    for c in cols: 
        df[c] = pd.to_numeric(df[c], errors='coerce')
    
    # Remove infinities and NaNs
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df = df.dropna(subset=['loc', 'security_debt_score'])
    df = df[df['loc'] > 0].fillna(0)
    
    # Unique States Only (Strict methodology standard)
    # Remove exact duplicates to avoid inflating statistical significance
    df_unique = df.drop_duplicates(subset=['repo_name'] + cols).copy()
    
    print(f"Unique datapoints analyzed: {len(df_unique)}")

    if len(df_unique) < 10:
        print("Error: Too little data for regression analysis.")
        return

    # 2. Predictor Selection
    # Exclude the target variable (security_debt_score)
    predictors = [c for c in cols if c != 'security_debt_score']
    
    # --- ZERO VARIANCE CHECK ---
    # If a column has identical values (e.g., all 0s), it breaks the regression.
    X_temp = df_unique[predictors]
    variance = X_temp.var()
    cols_to_drop = variance[variance == 0].index
    if not cols_to_drop.empty:
        print(f"WARNING: Removed columns with zero variance: {list(cols_to_drop)}")
        predictors = [p for p in predictors if p not in cols_to_drop]

    X = df_unique[predictors]
    X = sm.add_constant(X) # Adds the intercept (beta0)

    # 3. Variance Inflation Factor (VIF) Analysis
    print("\n--- Multicollinearity Analysis (VIF) ---")
    try:
        vif_data = pd.DataFrame()
        vif_data["Feature"] = X.columns
        vif_data["VIF"] = [variance_inflation_factor(X.values, i) for i in range(X.shape[1])]
        
        print("Variables with VIF > 5 are considered redundant (explained by others).")
        print(vif_data.sort_values(by="VIF", ascending=False).to_string(index=False))
        vif_data.to_csv(os.path.join(OUTPUT_DIR, 'rq1_vif_analysis.csv'), index=False)
    except Exception as e:
        print(f"Unable to calculate VIF (possible perfect collinearity): {e}")

    # 4. Multiple Linear Regression (OLS)
    y = df_unique['security_debt_score']
    
    try:
        model = sm.OLS(y, X).fit()
        
        print("\n--- Multiple Regression Results (OLS) ---")
        print(model.summary())
        
        # Save summary to file
        summary_path = os.path.join(OUTPUT_DIR, 'rq1_ols_regression_summary.txt')
        with open(summary_path, 'w') as f:
            f.write(model.summary().as_text())

        # 5. Automated Interpretation
        print("\n--- QUICK INTERPRETATION ---")
        print("Statistically significant variables (P < 0.05):")
        significant = model.pvalues[model.pvalues < 0.05].index.tolist()
        for var in significant:
            coef = model.params[var]
            impact = "INCREASES" if coef > 0 else "DECREASES"
            print(f"  - {var}: {impact} debt (Coef: {coef:.4f})")
            
    except Exception as e:
        print(f"Error calculating OLS model: {e}")

    # 5. VALIDATION WITH ROBUST LINEAR MODEL (RLM)
    # This model is less sensitive to outliers and confirms OLS results.
    try:
        print("\n--- Validation with Robust Linear Model (RLM) ---")
        rlm_model = sm.RLM(y, X, M=sm.robust.norms.HuberT()).fit()
        
        print(rlm_model.summary())
        
        # Save RLM summary to file
        rlm_summary_path = os.path.join(OUTPUT_DIR, 'rq1_rlm_regression_summary.txt')
        with open(rlm_summary_path, 'w') as f:
            f.write(rlm_model.summary().as_text())
            
        print("\nCOEFFICIENT COMPARISON (OLS vs RLM):")
        comparison_df = pd.DataFrame({
            'OLS_coef': model.params,
            'RLM_coef': rlm_model.params,
            'OLS_pvalue': model.pvalues,
            'RLM_pvalue': rlm_model.pvalues
        })
        print(comparison_df.round(4))

    except Exception as e:
        print(f"Error calculating RLM model: {e}")

if __name__ == "__main__":
    analyze_advanced_rq1()