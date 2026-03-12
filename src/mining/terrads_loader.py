import sqlite3
import pandas as pd
import os
import logging
from typing import Optional, Set
from src import config

logger = logging.getLogger(__name__)


def load_repositories(
    db_path: str = config.DB_PATH,
    min_stars: int = config.MIN_STARS,
    limit: int = config.REPO_LIMIT,
    random_seed: int = 42,
    exclude_repos: Optional[Set[str]] = None,
) -> pd.DataFrame:
    """
    Extracts a random sample of Terraform repositories from the TerraDS database.

    Sampling strategy
    -----------------
    1. Stratification: retains only repositories with StarCount >= min_stars,
       defining the "relevant population" and excluding toy/abandoned projects.
    2. Exclusion: removes repositories whose Name is in exclude_repos (i.e.
       already present in the output CSV from a prior mining run). This enables
       supplementary sampling without re-processing already-completed repos.
    3. Random sampling: draws up to `limit` repositories with a fixed random
       seed for full reproducibility.

    Parameters
    ----------
    db_path : str
        Path to the TerraDS SQLite database.
    min_stars : int
        Minimum star count for a repository to be included in the population.
    limit : int
        Maximum number of repositories to return.
    random_seed : int
        Seed for the random sampler (default 42, matching the original run).
    exclude_repos : set of str, optional
        Repository names (Name column in TerraDS) to exclude from sampling.
        Pass the set of names already present in the output CSV to avoid
        re-mining completed repositories during a supplementary run.

    Returns
    -------
    pd.DataFrame
        Columns: GitUrl, Name, StarCount.
        Empty DataFrame on any error.
    """
    if exclude_repos is None:
        exclude_repos = set()

    if not os.path.exists(db_path):
        logger.error(f"Database file not found at: {db_path}")
        return pd.DataFrame()

    try:
        logger.info(f"Connecting to TerraDS database: {db_path}")
        conn = sqlite3.connect(db_path)

        query = f"""
            SELECT GitUrl, Name, StarCount
            FROM   Repositories
            WHERE  StarCount >= {min_stars}
        """

        logger.info(f"Fetching all candidate repositories with stars >= {min_stars}...")
        df = pd.read_sql_query(query, conn)
        conn.close()

        if df.empty:
            logger.warning("Query returned no results. Consider lowering min_stars.")
            return df

        logger.info(f"Found {len(df)} total candidate repositories in population.")

        # Protocol conversion: git:// is deprecated and blocked by most firewalls.
        df['GitUrl'] = df['GitUrl'].str.replace('git://', 'https://', regex=False)
        df = df.dropna(subset=['GitUrl']).drop_duplicates(subset=['GitUrl'])

        # Exclusion of already-processed repositories.
        if exclude_repos:
            before = len(df)
            df = df[~df['Name'].isin(exclude_repos)]
            excluded_count = before - len(df)
            logger.info(
                f"Excluded {excluded_count} already-processed repositories. "
                f"Remaining candidate pool: {len(df)}."
            )

        if df.empty:
            logger.warning("All candidates are already processed. Nothing left to sample.")
            return df

        # Deterministic random sampling.
        if len(df) > limit:
            logger.info(f"Sampling {limit} repositories (random_seed={random_seed})...")
            df = df.sample(n=limit, random_state=random_seed)
        else:
            logger.warning(
                f"Candidate pool ({len(df)}) is smaller than the requested "
                f"limit ({limit}). Using all available candidates."
            )

        logger.info(f"Final target list: {len(df)} repositories.")
        return df

    except Exception as e:
        logger.error(f"An error occurred in terrads_loader: {e}")
        return pd.DataFrame()


if __name__ == "__main__":
    print("--- Testing TerraDS Loader ---")
    local_db_path = os.path.join('data', 'input', 'TerraDS.sqlite')
    if os.path.exists(local_db_path):
        test_df = load_repositories(db_path=local_db_path, limit=5)
        print("Sampled repositories:")
        print(test_df)