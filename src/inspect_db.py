import sqlite3
import os
import sys

# Database path inside the container (aligned with config.py and Dockerfile)
DB_PATH = '/app/data/input/TerraDS.sqlite'

def inspect_database():
    """
    Analyzes the TerraDS SQLite database to verify table structures, 
    column names, and record counts. This is essential for ensuring 
    the construct validity of the repository sampling logic.
    """
    print(f"============================================================")
    print(f"DATABASE INSPECTION UTILITY")
    print(f"============================================================")
    print(f"Target Path: {DB_PATH}")

    # Check if the database file exists at the expected location
    if not os.path.exists(DB_PATH):
        print(f"ERROR: Database file not found at {DB_PATH}.")
        print("Debugging: Current directory contents:")
        try:
            print(os.listdir('.'))
            print("Contents of /app/data/input/:")
            print(os.listdir('/app/data/input/'))
        except Exception:
            pass
        return

    try:
        # Establishing connection to the SQLite database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # 1. Fetching all table names from the master schema
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        if not tables:
            print("WARNING: The database contains no tables.")
            return

        print(f"Tables found in database: {[t[0] for t in tables]}")
        
        # 2. Detailed inspection for each table
        for table in tables:
            table_name = table[0]
            print(f"\n--- Table: {table_name} ---")
            
            # Print Column Information (PRAGMA table_info returns: cid, name, type, notnull, dflt_value, pk)
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns = cursor.fetchall()
            print(f"  Schema:")
            for col in columns:
                pk_marker = "[PK]" if col[5] == 1 else ""
                print(f"    - {col[1]:<20} {col[2]:<10} {pk_marker}")
            
            # Print Record Count (to verify data availability)
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            row_count = cursor.fetchone()[0]
            print(f"  Total records: {row_count}")
            
            # Sample data (First row)
            if row_count > 0:
                cursor.execute(f"SELECT * FROM {table_name} LIMIT 1")
                sample = cursor.fetchone()
                print(f"  Data Sample (1st row): {sample}")

        conn.close()
        print(f"\n============================================================")
        print(f"INSPECTION COMPLETED SUCCESSFULLY")
        print(f"============================================================")

    except sqlite3.Error as e:
        print(f"CRITICAL ERROR: SQLite encountered a problem: {e}")
    except Exception as e:
        print(f"CRITICAL ERROR: An unexpected error occurred: {e}")

if __name__ == "__main__":
    inspect_database()