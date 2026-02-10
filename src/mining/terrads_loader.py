import sqlite3
import pandas as pd
import os
import logging

# Standard logging configuration for the module
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def load_repositories(
    db_path: str = '/app/data/input/TerraDS.sqlite', 
    min_stars: int = 5, 
    limit: int = 400,
    random_seed: int = 42  # Static seed for deterministic sampling
) -> pd.DataFrame:
    """
    Extracts a stratified random sample of Terraform repositories from the TerraDS database.
    
    Sampling Strategy:
    1.  Stratification: Filters repositories to include only those with a minimum star count, 
        defining the "relevant population" and excluding inactive or toy projects.
    2.  Random Sampling: Selects a random subset to ensure statistical representativeness.
    3.  Reproducibility: Uses a fixed random seed so that the same sample is generated on every run.
    """
    
    if not os.path.exists(db_path):
        logger.error(f"Database file not found at: {db_path}")
        return pd.DataFrame()

    try:
        logger.info(f"Connecting to TerraDS database: {db_path}")
        conn = sqlite3.connect(db_path)
        
        # SQL query to fetch the entire relevant population first
        query = f"""
        SELECT 
            GitUrl, 
            Name, 
            StarCount
        FROM 
            Repositories 
        WHERE 
            StarCount >= {min_stars}
        """
        
        logger.info(f"Fetching all candidate repositories with stars >= {min_stars}...")
        df = pd.read_sql_query(query, conn)
        conn.close()
        
        if df.empty:
            logger.warning("The query returned no results. Consider lowering the min_stars threshold.")
            return df
            
        logger.info(f"Found {len(df)} total candidate repositories.")

        # Protocol Conversion: git:// is deprecated and often blocked by firewalls.
        df['GitUrl'] = df['GitUrl'].str.replace('git://', 'https://', regex=False)
        df = df.dropna(subset=['GitUrl']).drop_duplicates(subset=['GitUrl'])

        # Deterministic Sampling using Pandas' .sample() method
        if len(df) > limit:
            logger.info(f"Sampling {limit} repositories with random_seed={random_seed}...")
            df = df.sample(n=limit, random_state=random_seed)
        else:
            logger.warning(f"Found fewer repositories ({len(df)}) than the limit ({limit}). Using all available.")

        logger.info(f"Final target list contains {len(df)} repositories.")
        return df

    except Exception as e:
        logger.error(f"An error occurred in terrads_loader: {e}")
        return pd.DataFrame()

if __name__ == "__main__":
    # Internal self-test block
    print("--- Testing TerraDS Loader ---")
    local_db_path = os.path.join('data', 'input', 'TerraDS.sqlite')
    if os.path.exists(local_db_path):
        test_df = load_repositories(db_path=local_db_path, limit=5)
        print("Sampled repositories:")
        print(test_df)