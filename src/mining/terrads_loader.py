import sqlite3
import pandas as pd
import os
import logging

# Configurazione del Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def load_repositories(
    db_path: str = '/app/data/input/TerraDS.sqlite', 
    min_stars: int = 10, 
    limit: int = 50
) -> pd.DataFrame:
    """
    Estrae una lista di repository Terraform dal dataset TerraDS (SQLite).
    """
    
    if not os.path.exists(db_path):
        logger.error(f"Database non trovato al percorso: {db_path}")
        return pd.DataFrame()

    try:
        logger.info(f"Connessione al database TerraDS: {db_path}")
        conn = sqlite3.connect(db_path)
        
        # Usiamo CloneUrl se disponibile, altrimenti GitUrl
        # Ma per sicurezza prendiamo GitUrl e lo convertiamo in HTTPS
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
        
        logger.info(f"Esecuzione query: SELECT TOP {limit} repos WITH stars >= {min_stars}...")
        
        df = pd.read_sql_query(query, conn)
        conn.close()
        
        if df.empty:
            logger.warning("La query non ha restituito risultati.")
        else:
            logger.info(f"Trovati {len(df)} repository validi.")
            
            # --- FIX CRUCIALE: Conversione protocollo git:// -> https:// ---
            # GitHub blocca git://, dobbiamo usare https://
            df['GitUrl'] = df['GitUrl'].str.replace('git://', 'https://')
            
            # Pulizia
            df = df.dropna(subset=['GitUrl']).drop_duplicates(subset=['GitUrl'])
            
        return df

    except sqlite3.Error as e:
        logger.error(f"Errore SQLite: {e}")
        return pd.DataFrame()
    except Exception as e:
        logger.error(f"Errore generico: {e}")
        return pd.DataFrame()

if __name__ == "__main__":
    print("--- Test TerraDS Loader ---")
    test_path = "data/input/TerraDS.sqlite" 
    if os.path.exists(test_path):
        df_test = load_repositories(db_path=test_path, limit=5)
        print(df_test['GitUrl'].head()) # Stampiamo gli URL per verificare che siano HTTPS
    else:
        print(f"File {test_path} non trovato.")