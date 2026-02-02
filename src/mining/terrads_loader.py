import sqlite3
import pandas as pd
import os
import logging

# Basic logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def load_repositories(
    db_path: str = '/app/data/input/TerraDS.sqlite', 
    min_stars: int = 30, 
    limit: int = 50
) -> pd.DataFrame:
    """
    Extracts a list of Terraform repositories from the TerraDS SQLite database.
    
    Sampling Strategy:
    - We use 'StarCount' as a proxy for project maturity and community relevance.
    - Filtering by stars ensures we analyze real-world, maintained infrastructure 
      rather than empty or strictly personal test repositories.
    """
    
    if not os.path.exists(db_path):
        logger.error(f"Database file not found at: {db_path}")
        return pd.DataFrame()

    try:
        logger.info(f"Connecting to TerraDS database: {db_path}")
        conn = sqlite3.connect(db_path)
        
        # SQL Query execution
        # We select Name and GitUrl to uniquely identify and clone the target repos.
        query = f"""
        SELECT 
            GitUrl, 
            Name, 
            StarCount
        FROM 
            Repositories 
        WHERE 
            StarCount >= {min_stars} 
        ORDER BY 
            StarCount DESC 
        LIMIT {limit};
        """
        
        logger.info(f"Executing sampling query (Min stars: {min_stars}, Limit: {limit})...")
        
        df = pd.read_sql_query(query, conn)
        conn.close()
        
        if df.empty:
            logger.warning("The query returned no results. Consider lowering the min_stars threshold.")
        else:
            logger.info(f"Found {len(df)} candidate repositories.")
            
            # --- CRITICAL FIX: Protocol Conversion ---
            # Modern GitHub security policies have disabled the unauthenticated git:// protocol.
            # We convert all URLs to the secure https:// protocol to ensure successful cloning.
            df['GitUrl'] = df['GitUrl'].str.replace('git://', 'https://', regex=False)
            
            # Data Cleaning: remove duplicates or malformed entries
            df = df.dropna(subset=['GitUrl']).drop_duplicates(subset=['GitUrl'])
            
            logger.info(f"Final target list ready: {len(df)} repositories.")
            
        return df

    except sqlite3.Error as e:
        logger.error(f"SQLite error during extraction: {e}")
        return pd.DataFrame()
    except Exception as e:
        logger.error(f"Unexpected error in terrads_loader: {e}")
        return pd.DataFrame()

if __name__ == "__main__":
    # Internal test block
    print("--- Running TerraDS Loader Test ---")
    
    # Path adjustment for local execution outside Docker
    local_path = os.path.join("data", "input", "TerraDS.sqlite")
    
    if os.path.exists(local_path):
        df_test = load_repositories(db_path=local_path, limit=5)
        if not df_test.empty:
            print(df_test[['Name', 'GitUrl', 'StarCount']].head())
    else:
        print(f"Local database file not found at {local_path}. Test skipped.")