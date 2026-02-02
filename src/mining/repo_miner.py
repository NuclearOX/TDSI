from pydriller import Repository
from src.metrics.quality_model import QualityAnalyzer
from src.metrics.security_model import SecurityAnalyzer
from src import config
import logging
import os
import shutil
import tempfile
import subprocess
import numpy as np
import hashlib
import re

logger = logging.getLogger(__name__)

class RepoMiner:
    """
    Handles the mining of Git repositories. Implements an adaptive and 
    optimized strategy to capture evolution data.
    """
    def __init__(self, repo_url: str, repo_name: str):
        self.repo_url = repo_url
        self.repo_name = repo_name

    def mine_history(self):
        """
        Main mining workflow:
        1. Clones a repository once into a temporary directory.
        2. Intelligently samples snapshots (Tags or Commits) across the project's timeline.
        3. Analyzes each snapshot, using a content-based cache to skip redundant calculations.
        4. Cleans up all temporary files.
        """
        logger.info(f"Starting SMART mining for: {self.repo_name}")
        
        temp_dir = tempfile.mkdtemp()
        clone_path = os.path.join(temp_dir, self.repo_name)
        
        try:
            # 1. CLONE REPOSITORY
            logger.info(f"Cloning {self.repo_url}...")
            subprocess.run(
                ["git", "clone", "--no-filter", self.repo_url, clone_path], 
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=300
            )

            # 2. SELECT SNAPSHOTS TO ANALYZE
            commits_to_analyze = self._select_smart_snapshots(clone_path)
            
            if not commits_to_analyze:
                logger.warning(f"No valid snapshots found for {self.repo_name}")
                return

            logger.info(f"Selected {len(commits_to_analyze)} representative snapshots for analysis.")

            # 3. ANALYZE SELECTED SNAPSHOTS WITH CACHING
            repo_mining = Repository(path_to_repo=clone_path, only_commits=commits_to_analyze)

            last_tf_hash = None
            last_metrics = None

            for commit in repo_mining.traverse_commits():
                yield from self._analyze_commit(commit, last_tf_hash, last_metrics)

        except subprocess.TimeoutExpired:
            logger.error(f"Git clone timed out for {self.repo_url}")
        except subprocess.CalledProcessError:
            logger.error(f"Git clone failed for {self.repo_url}")
        except Exception as e:
            logger.error(f"Critical mining error for {self.repo_name}: {e}")
        finally:
            # 4. CLEANUP
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    def _select_smart_snapshots(self, path: str):
        """
        Selects a uniform sample of snapshots (either Tags or Commits) that
        modified .tf files, covering the entire project history.
        """
        cwd = os.getcwd()
        os.chdir(path)
        try:
            # First, try to get chronological tags
            tags = subprocess.check_output(["git", "tag", "--sort=creatordate"], text=True).splitlines()
            tags = [t.strip() for t in tags if t.strip()]
            
            # If we have enough tags, they are our primary source
            if len(tags) >= 5:
                logger.info(f"Found {len(tags)} tags. Sampling from official releases.")
                hashes = [subprocess.check_output(["git", "rev-list", "-n", "1", tag], text=True).strip() for tag in tags]
                return self._sample_list(hashes, config.MAX_SNAPSHOTS)
            
            # Fallback: not enough tags, so we use commits that changed .tf files
            logger.info("Few tags found. Analyzing chronological commit history (.tf files only).")
            cmd = ["git", "log", "--pretty=format:%H", "--reverse", "--", "*.tf", "*.tfvars"]
            commits = subprocess.check_output(cmd, text=True).splitlines()
            commits = [c.strip() for c in commits if c.strip()]
            
            return self._sample_list(commits, config.MAX_SNAPSHOTS)
        except Exception as e:
            logger.error(f"Could not select snapshots: {e}")
            return []
        finally:
            os.chdir(cwd)

    def _sample_list(self, full_list: list, limit: int) -> list:
        """
        Takes a long list and returns a uniformly sampled sub-list, 
        always including the first and last elements.
        """
        if len(full_list) <= limit:
            return full_list
        indices = np.linspace(0, len(full_list) - 1, limit, dtype=int)
        return [full_list[i] for i in sorted(list(set(indices)))]

    def _calculate_tf_content_hash(self, path: str) -> str:
        """
        Creates a single MD5 hash from the content of all .tf files in a directory.
        This is used as a fast cache key to detect structural changes.
        """
        hasher = hashlib.md5()
        for root, _, files in os.walk(path):
            for file in sorted(files): # sorted() for deterministic order
                if file.endswith(('.tf', '.tfvars')):
                    try:
                        with open(os.path.join(root, file), 'rb') as f:
                            hasher.update(f.read())
                    except FileNotFoundError:
                        continue # File might be a broken symlink
        return hasher.hexdigest()

    def _analyze_commit(self, commit, last_tf_hash, last_metrics):
        """
        Analyzes a single commit, applying caching logic.
        """
        try:
            current_path = commit.project_path
            current_tf_hash = self._calculate_tf_content_hash(current_path)
            
            # CACHING LOGIC: If .tf content is identical, reuse old results
            if last_tf_hash and current_tf_hash == last_tf_hash and last_metrics:
                yield self._create_data_point(commit, last_metrics, "SKIPPED_DUPLICATE")
                return

            # Perform full analysis if content has changed
            q_analyzer = QualityAnalyzer(current_path)
            q_metrics = q_analyzer.analyze()

            if q_metrics['loc'] == 0: return

            s_analyzer = SecurityAnalyzer(current_path)
            s_metrics = s_analyzer.analyze()

            # HANDLE TRIVY FAILURE: If s_metrics is None, discard this snapshot
            if s_metrics is None:
                logger.warning(f"Security analysis failed for {commit.hash[:7]}. Discarding snapshot.")
                return
            
            # --- DETAILED LOGGING FOR SUCCESSFUL ANALYSIS ---
            log_msg = (
                f"  [{commit.hash[:7]}] {commit.author_date.date()} | "
                f"LOC: {q_metrics['loc']} | "
                f"Complexity: {q_metrics['iac_mccabe_complexity']} | "
                f"Hard-coded: {q_metrics['hard_coded_values']} | "
                f"SecDebt: {s_metrics['security_debt_score']}"
            )
            logger.info(log_msg)

            full_metrics = {**q_metrics, **s_metrics}
            
            # Update cache for the next iteration
            last_tf_hash = current_tf_hash
            last_metrics = full_metrics

            yield self._create_data_point(commit, full_metrics, "ANALYZED")

        except Exception as e:
            logger.error(f"Failed to process commit {commit.hash[:7]}: {e}")
            
    def _create_data_point(self, commit, metrics, mode):
        """
        Creates the final data dictionary and sanitizes the commit/tag message for CSV.
        """
        # Sanitize message to prevent CSV corruption
        raw_msg = str(commit.msg)
        clean_msg = re.sub(r'[\n\r\t,"]', ' ', raw_msg) # Replace newlines, commas, quotes
        clean_msg = (clean_msg[:150] + '...') if len(clean_msg) > 150 else clean_msg
        
        return {
            'repo_name': self.repo_name,
            'git_url': self.repo_url,
            'commit_hash': commit.hash,
            'tag': clean_msg,
            'analysis_mode': mode,
            'author_date': commit.author_date,
            **metrics
        }