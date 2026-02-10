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
import stat

logger = logging.getLogger(__name__)

def remove_readonly(func, path, exc_info):
    """Error handler for shutil.rmtree to handle read-only files on Windows."""
    os.chmod(path, stat.S_IWRITE)
    func(path)

class RepoMiner:
    """
    Handles the mining of Git repositories with a smart sampling strategy
    and forced state synchronization for accurate IaC analysis.
    """
    def __init__(self, repo_url: str, repo_name: str):
        self.repo_url = repo_url
        self.repo_name = repo_name

    def mine_history(self):
        """
        Main mining workflow with forced checkout and structural caching.
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

            # 2. SELECT REPRESENTATIVE SNAPSHOTS
            commits_to_analyze = self._select_smart_snapshots(clone_path)
            
            if not commits_to_analyze:
                logger.warning(f"No valid snapshots found for {self.repo_name}")
                return

            logger.info(f"Selected {len(commits_to_analyze)} snapshots for analysis.")

            # 3. ANALYZE SELECTED SNAPSHOTS
            repo_mining = Repository(path_to_repo=clone_path, only_commits=commits_to_analyze)

            last_tf_hash = None
            last_metrics = None

            for commit in repo_mining.traverse_commits():
                try:
                    # FORCED CHECKOUT: Crucial to ensure disk matches the commit hash
                    subprocess.run(
                        ["git", "checkout", "-f", commit.hash],
                        cwd=clone_path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True
                    )

                    # SMART CACHING: Calculate hash of production TF files only
                    current_tf_hash = self._calculate_tf_content_hash(clone_path)
                    
                    if last_tf_hash and current_tf_hash == last_tf_hash and last_metrics:
                        yield self._create_data_point(commit, last_metrics, "SKIPPED_DUPLICATE")
                        continue 

                    # QUALITY ANALYSIS
                    q_analyzer = QualityAnalyzer(clone_path)
                    q_metrics = q_analyzer.analyze()

                    if q_metrics['loc'] == 0:
                        continue

                    # SECURITY ANALYSIS
                    s_analyzer = SecurityAnalyzer(clone_path)
                    s_metrics = s_analyzer.analyze()

                    if s_metrics is None:
                        logger.warning(f"Security analysis failed for {commit.hash[:7]}. Discarding snapshot.")
                        continue
                    
                    # ENHANCED LOGGING: Show more quality attributes for real-time monitoring
                    log_msg = (
                        f"  [{commit.hash[:7]}] {commit.author_date.date()} | "
                        f"LOC: {q_metrics['loc']} | "
                        f"Complexity: {q_metrics['iac_mccabe_complexity']} | "
                        f"Refs: {q_metrics['internal_references']} | "
                        f"Debt: {s_metrics['security_debt_score']}"
                    )
                    logger.info(log_msg)

                    full_metrics = {**q_metrics, **s_metrics}
                    
                    # Update cache
                    last_tf_hash = current_tf_hash
                    last_metrics = full_metrics

                    yield self._create_data_point(commit, full_metrics, "ANALYZED")

                except Exception as e:
                    logger.error(f"Failed to process commit {commit.hash[:7]}: {e}")
                    try:
                        subprocess.run(["git", "reset", "--hard"], cwd=clone_path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    except: pass

        except Exception as e:
            logger.error(f"Critical mining error for {self.repo_name}: {e}")
        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, onerror=remove_readonly)

    def _calculate_tf_content_hash(self, path: str) -> str:
        """
        Calculates an MD5 hash of production .tf files.
        Synchronized with QualityAnalyzer's directory blacklist.
        """
        hasher = hashlib.md5()
        # SYNC: Same blacklist as QualityAnalyzer
        dirs_to_exclude = [
            '.git', '.terraform', '.idea', '.vscode', 'vendor', 'node_modules',
            'examples', 'example', 'tests', 'test', 'fixtures', 'spec'
        ]
        
        for root, dirs, files in os.walk(path):
            # Prune directories in-place to avoid hashing non-production code
            dirs[:] = [d for d in dirs if d not in dirs_to_exclude]
            
            for file in sorted(files):
                if file.endswith(('.tf', '.tfvars')):
                    try:
                        with open(os.path.join(root, file), 'rb') as f:
                            hasher.update(f.read())
                    except: continue
        return hasher.hexdigest()

    def _select_smart_snapshots(self, path: str):
        """Uniform sampling of project history."""
        cwd = os.getcwd()
        os.chdir(path)
        try:
            tags = subprocess.check_output(["git", "tag", "--sort=creatordate"], text=True).splitlines()
            tags = [t.strip() for t in tags if t.strip()]
            
            if len(tags) >= 5:
                hashes = [subprocess.check_output(["git", "rev-list", "-n", "1", tag], text=True).strip() for tag in tags]
                return self._sample_list(hashes, config.MAX_SNAPSHOTS)
            
            cmd = ["git", "log", "--pretty=format:%H", "--reverse", "--", "*.tf", "*.tfvars"]
            commits = subprocess.check_output(cmd, text=True).splitlines()
            return self._sample_list([c.strip() for c in commits if c.strip()], config.MAX_SNAPSHOTS)
        except: return []
        finally: os.chdir(cwd)

    def _sample_list(self, full_list: list, limit: int) -> list:
        if len(full_list) <= limit: return full_list
        indices = np.linspace(0, len(full_list) - 1, limit, dtype=int)
        return [full_list[i] for i in sorted(list(set(indices)))]
            
    def _create_data_point(self, commit, metrics, mode):
        raw_msg = str(commit.msg)
        clean_msg = re.sub(r'[\n\r\t,"]', ' ', raw_msg)
        clean_msg = (clean_msg[:150] + '...') if len(clean_msg) > 150 else clean_msg
        return {
            'repo_name': self.repo_name, 'git_url': self.repo_url, 'commit_hash': commit.hash,
            'tag': clean_msg, 'analysis_mode': mode, 'author_date': commit.author_date,
            **metrics
        }