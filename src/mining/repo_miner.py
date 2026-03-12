import hashlib
import logging
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time

import numpy as np
from pydriller import Repository

from src import config
from src.metrics.quality_model import DIRS_TO_EXCLUDE
from src.metrics.security_model import SecurityAnalyzer
from src.metrics.quality_model import QualityAnalyzer

logger = logging.getLogger(__name__)


# Sentinel returned by _process_commit when SecurityAnalyzer returns None
# (Trivy hard failure or timeout). Distinct from None (other errors) so
# that mine_history() can count consecutive Trivy failures and abort the
# repo early when the repository has grown too large for Trivy to handle.
_TRIVY_FAILURE = object()

# Maximum number of consecutive Trivy failures before the repo is
# considered unanalysable and mining stops early.
MAX_CONSECUTIVE_TRIVY_FAILURES = 2

# Fraction of REPO_ANALYSIS_TIMEOUT after which mine_history() stops
# voluntarily and returns partial results. Must be < 1.0 so that the
# child process has time to put() results before the parent's get()
# timeout fires and kills the process.
_INTERNAL_TIMEOUT_FRACTION = 0.90


def _remove_readonly(func, path, exc_info):
    """
    Error handler for shutil.rmtree on Windows.
    Clears the read-only bit and retries the failed operation.
    """
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass  # Best-effort cleanup; do not propagate inside rmtree


class RepoMiner:
    """
    Mines the longitudinal history of a single Terraform repository.

    Workflow
    --------
    1. Clone the repository into a temporary directory.
    2. Select a representative set of snapshots via uniform sampling
       (tag-based when available, commit-based otherwise).
    3. For each snapshot: force-checkout, hash production .tf files,
       skip if the content is identical to the previous snapshot
       (deduplication), then run quality and security analysis.
    4. Yield one data-point dict per snapshot.
    5. Delete the temporary directory unconditionally in the finally block.

    Design notes
    ------------
    * os.chdir() is never used. All subprocess calls receive an explicit
      cwd= argument so that concurrent or re-entrant usage cannot corrupt
      the process working directory.
    * The directory blacklist for content hashing is imported from
      quality_model.DIRS_TO_EXCLUDE to guarantee synchronisation between
      the two subsystems.
    * SKIPPED_DUPLICATE snapshots reuse the last valid metrics but still
      produce a data-point so that the timeline has no gaps.
    * All git subprocess calls are bounded by GIT_OP_TIMEOUT seconds.
      A subprocess.TimeoutExpired exception is treated as a skippable
      error — the snapshot is discarded and mining continues with the
      next one. This prevents a single stuck git operation from blocking
      the entire run indefinitely.
    * If Trivy fails on MAX_CONSECUTIVE_TRIVY_FAILURES snapshots in a row,
      mining stops early for that repository. This handles the common case
      where a repo grows beyond Trivy's capacity: once it starts timing out
      it will keep timing out on all subsequent (larger) snapshots, wasting
      time proportional to n_remaining * TRIVY_CLI_TIMEOUT.
    * An internal wall-clock timeout (_INTERNAL_TIMEOUT_FRACTION of
      REPO_ANALYSIS_TIMEOUT) causes mine_history() to stop voluntarily
      and return partial results before the parent process kills the child.
      This guarantees that data collected so far is never lost to a hard
      kill from the parent's multiprocessing timeout.
    """

    # Timeout in seconds for individual git operations (checkout, clean,
    # tag listing, log). Distinct from REPO_ANALYSIS_TIMEOUT in config.py
    # which bounds the entire repo processing in the parent process.
    # 120s is generous for any single git operation on a local clone.
    GIT_OP_TIMEOUT = 120

    def __init__(self, repo_url: str, repo_name: str) -> None:
        self.repo_url = repo_url
        self.repo_name = repo_name

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def mine_history(self):
        """
        Generator: yields one data-point dictionary per selected snapshot.

        Yields nothing if the repository cannot be cloned or contains no
        Terraform files.

        Early exits
        -----------
        1. Consecutive Trivy failures: if Trivy fails on
           MAX_CONSECUTIVE_TRIVY_FAILURES snapshots in a row, the repo
           is considered too large for Trivy and mining stops.
        2. Internal timeout: if _INTERNAL_TIMEOUT_FRACTION of
           REPO_ANALYSIS_TIMEOUT has elapsed, mining stops voluntarily
           so that partial results can be returned to the parent process
           before it fires its hard kill.

        In both cases, data collected up to that point is yielded and saved.
        """
        logger.info(f"Starting mining for: {self.repo_name}")

        temp_dir = tempfile.mkdtemp()
        clone_path = os.path.join(temp_dir, self.repo_name)

        # Internal wall-clock deadline — 80% of the global repo timeout.
        internal_timeout = config.REPO_ANALYSIS_TIMEOUT * _INTERNAL_TIMEOUT_FRACTION
        mining_start = time.time()

        try:
            # ---------------------------------------------------------
            # Step 1 — Clone
            # ---------------------------------------------------------
            self._clone(clone_path)

            # ---------------------------------------------------------
            # Step 2 — Select snapshots
            # ---------------------------------------------------------
            commits_to_analyze = self._select_smart_snapshots(clone_path)

            if not commits_to_analyze:
                logger.warning(f"No valid snapshots found for {self.repo_name}.")
                return

            logger.info(
                f"Selected {len(commits_to_analyze)} snapshots "
                f"for {self.repo_name}."
            )

            # ---------------------------------------------------------
            # Step 3 — Iterate and analyse
            # ---------------------------------------------------------
            repo_handle = Repository(
                path_to_repo=clone_path,
                only_commits=commits_to_analyze,
            )

            last_tf_hash: str | None = None
            last_metrics: dict | None = None
            consecutive_trivy_failures = 0

            for commit in repo_handle.traverse_commits():

                # --- Internal timeout check (checked before each snapshot) ---
                elapsed = time.time() - mining_start
                if elapsed >= internal_timeout:
                    logger.warning(
                        f"Internal timeout reached for {self.repo_name} "
                        f"({elapsed:.0f}s >= {internal_timeout:.0f}s). "
                        f"Stopping early — partial results will be saved."
                    )
                    break

                result = self._process_commit(
                    commit, clone_path, last_tf_hash, last_metrics
                )

                # --- Trivy consecutive failure check ---
                if result is _TRIVY_FAILURE:
                    consecutive_trivy_failures += 1
                    if consecutive_trivy_failures >= MAX_CONSECUTIVE_TRIVY_FAILURES:
                        logger.warning(
                            f"Trivy failed on {consecutive_trivy_failures} consecutive "
                            f"snapshots for {self.repo_name}. Repository likely too large "
                            f"for Trivy — stopping early to avoid wasting time."
                        )
                        break
                    continue

                if result is None:
                    # Other errors (git, LOC=0, etc.) — reset Trivy counter
                    # because the failure is not Trivy-related.
                    consecutive_trivy_failures = 0
                    continue

                # Successful snapshot — reset Trivy failure counter.
                consecutive_trivy_failures = 0

                data_point, current_tf_hash, current_metrics = result

                # Update deduplication cache only for freshly analysed
                # snapshots, not for SKIPPED_DUPLICATE ones (whose metrics
                # are already identical to the cached ones).
                if data_point['analysis_mode'] == 'ANALYZED':
                    last_tf_hash = current_tf_hash
                    last_metrics = current_metrics

                yield data_point

        except subprocess.CalledProcessError as e:
            logger.error(f"Git error while mining {self.repo_name}: {e}")
        except Exception as e:
            logger.error(f"Critical mining error for {self.repo_name}: {e}")
        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, onerror=_remove_readonly)

    # ------------------------------------------------------------------
    # Private — git helpers
    # ------------------------------------------------------------------

    def _clone(self, clone_path: str) -> None:
        """Clones the repository into clone_path with a 5-minute timeout."""
        logger.info(f"Cloning {self.repo_url} ...")
        subprocess.run(
            ["git", "clone", "--no-filter", self.repo_url, clone_path],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=300,
        )

    def _checkout(self, clone_path: str, commit_hash: str) -> None:
        """
        Forces the working tree to exactly match commit_hash.

        Two-step approach:
        * git checkout -f  — restores tracked files.
        * git clean -fdx   — removes untracked files and ignored artefacts
                             (e.g. .terraform directories from previous runs).

        Both operations are bounded by GIT_OP_TIMEOUT seconds. If either
        exceeds the timeout a subprocess.TimeoutExpired is raised, which
        _process_commit catches and converts into a skipped snapshot.
        """
        subprocess.run(
            ["git", "checkout", "-f", commit_hash],
            cwd=clone_path,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=self.GIT_OP_TIMEOUT,
        )
        subprocess.run(
            ["git", "clean", "-fdx"],
            cwd=clone_path,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=self.GIT_OP_TIMEOUT,
        )

    def _select_smart_snapshots(self, clone_path: str) -> list:
        """
        Returns a list of commit hashes to analyse, using uniform sampling.

        Strategy
        --------
        * If the repository has 5 or more annotated/lightweight tags sorted
          by creation date, resolve each tag to its commit hash and sample
          from that list. Tags provide semantically meaningful checkpoints.
        * Otherwise fall back to all commits that touched .tf or .tfvars
          files, listed in chronological order.

        In both cases the list is capped at config.MAX_SNAPSHOTS using
        equidistant index sampling (numpy.linspace).

        All git operations are bounded by GIT_OP_TIMEOUT seconds.
        """
        try:
            tags = subprocess.check_output(
                ["git", "tag", "--sort=creatordate"],
                text=True,
                cwd=clone_path,
                timeout=self.GIT_OP_TIMEOUT,
            ).splitlines()
            tags = [t.strip() for t in tags if t.strip()]

            if len(tags) >= 5:
                hashes = []
                seen_hashes = set()  # guard against tags pointing to the same commit
                for tag in tags:
                    try:
                        h = subprocess.check_output(
                            ["git", "rev-list", "-n", "1", tag],
                            text=True,
                            cwd=clone_path,
                            timeout=self.GIT_OP_TIMEOUT,
                        ).strip()
                        if h and h not in seen_hashes:
                            seen_hashes.add(h)
                            hashes.append(h)
                    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                        logger.warning(
                            f"Skipping tag '{tag}' for {self.repo_name}: {e}"
                        )
                        continue
                if hashes:
                    return self._sample_list(hashes, config.MAX_SNAPSHOTS)

            # Fallback: commits touching IaC files, oldest first
            raw = subprocess.check_output(
                ["git", "log", "--pretty=format:%H", "--reverse",
                 "--", "*.tf", "*.tfvars"],
                text=True,
                cwd=clone_path,
                timeout=self.GIT_OP_TIMEOUT,
            ).splitlines()
            commits = [c.strip() for c in raw if c.strip()]
            return self._sample_list(commits, config.MAX_SNAPSHOTS)

        except subprocess.TimeoutExpired:
            logger.error(
                f"Timeout ({self.GIT_OP_TIMEOUT}s) exceeded during snapshot "
                f"selection for {self.repo_name}. Returning empty list."
            )
            return []
        except subprocess.CalledProcessError as e:
            logger.error(
                f"Failed to select snapshots for {self.repo_name}: {e}"
            )
            return []

    # ------------------------------------------------------------------
    # Private — per-commit analysis
    # ------------------------------------------------------------------

    def _process_commit(
        self,
        commit,
        clone_path: str,
        last_tf_hash: str | None,
        last_metrics: dict | None,
    ):
        """
        Analyses a single commit snapshot.

        Returns
        -------
        (data_point, tf_hash, metrics)
            Successful analysis (ANALYZED or SKIPPED_DUPLICATE).
        _TRIVY_FAILURE
            SecurityAnalyzer returned None — Trivy timed out or crashed.
            The caller uses this sentinel to count consecutive failures.
        None
            Other discardable errors (git timeout, LOC=0, unexpected
            exception). Does NOT increment the Trivy failure counter.
        """
        try:
            self._checkout(clone_path, commit.hash)

            current_tf_hash = self._calculate_tf_content_hash(clone_path)

            # --- Deduplication ---
            if last_tf_hash and current_tf_hash == last_tf_hash and last_metrics:
                data_point = self._create_data_point(
                    commit, last_metrics, "SKIPPED_DUPLICATE"
                )
                return data_point, current_tf_hash, last_metrics

            # --- Quality analysis ---
            q_metrics = QualityAnalyzer(clone_path).analyze()
            if q_metrics['loc'] == 0:
                return None

            # --- Security analysis ---
            s_metrics = SecurityAnalyzer(clone_path).analyze()
            if s_metrics is None:
                logger.warning(
                    f"Security analysis failed for {commit.hash[:7]} "
                    f"in {self.repo_name}. Discarding snapshot."
                )
                return _TRIVY_FAILURE  # distinct sentinel for caller

            full_metrics = {**q_metrics, **s_metrics}

            zero_debt_flag = (
                " [ZERO_DEBT]" if s_metrics['security_debt_score'] == 0 else ""
            )
            logger.info(
                f"  [{commit.hash[:7]}] {commit.author_date.date()} | "
                f"LOC: {q_metrics['loc']} | "
                f"Complexity: {q_metrics['iac_mccabe_complexity']} | "
                f"Refs: {q_metrics['internal_references']} | "
                f"Debt: {s_metrics['security_debt_score']}{zero_debt_flag}"
            )

            data_point = self._create_data_point(commit, full_metrics, "ANALYZED")
            return data_point, current_tf_hash, full_metrics

        except subprocess.TimeoutExpired:
            logger.warning(
                f"Git operation timed out at commit {commit.hash[:7]} "
                f"in {self.repo_name} (limit={self.GIT_OP_TIMEOUT}s). "
                f"Skipping snapshot."
            )
            try:
                subprocess.run(
                    ["git", "reset", "--hard"],
                    cwd=clone_path,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=self.GIT_OP_TIMEOUT,
                )
            except Exception:
                pass
            return None  # git timeout, not Trivy — do not increment counter

        except subprocess.CalledProcessError as e:
            logger.error(
                f"Git error at commit {commit.hash[:7]} in {self.repo_name}: {e}"
            )
            try:
                subprocess.run(
                    ["git", "reset", "--hard"],
                    cwd=clone_path,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=self.GIT_OP_TIMEOUT,
                )
            except Exception:
                pass
            return None  # git error, not Trivy — do not increment counter

        except Exception as e:
            logger.error(
                f"Unexpected error at commit {commit.hash[:7]} "
                f"in {self.repo_name}: {e}"
            )
            return None  # unknown error, not Trivy — do not increment counter

    # ------------------------------------------------------------------
    # Private — utilities
    # ------------------------------------------------------------------

    def _calculate_tf_content_hash(self, path: str) -> str:
        """
        Returns an MD5 digest of the concatenated content of all production
        .tf and .tfvars files found under path.

        Uses the same directory blacklist as QualityAnalyzer (imported from
        quality_model.DIRS_TO_EXCLUDE) to guarantee that the deduplication
        logic and the quality metrics operate on exactly the same file set.

        Files are processed in deterministic sorted order so that the hash
        is stable across different OS directory-traversal orderings.
        """
        hasher = hashlib.md5()

        for root, dirs, files in os.walk(path):
            dirs[:] = sorted(d for d in dirs if d not in DIRS_TO_EXCLUDE)

            for file in sorted(files):
                if file.endswith(('.tf', '.tfvars')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'rb') as fh:
                            hasher.update(fh.read())
                    except OSError:
                        continue

        return hasher.hexdigest()

    @staticmethod
    def _sample_list(full_list: list, limit: int) -> list:
        """
        Returns a uniformly sampled subset of full_list of at most `limit`
        elements, preserving chronological order.

        Uses numpy.linspace to compute equidistant indices so that the
        first and last elements are always included.
        """
        if len(full_list) <= limit:
            return full_list
        indices = np.linspace(0, len(full_list) - 1, limit, dtype=int)
        seen = set()
        result = []
        for i in indices:
            if i not in seen:
                seen.add(i)
                result.append(full_list[i])
        return result

    def _create_data_point(self, commit, metrics: dict, mode: str) -> dict:
        """
        Assembles the flat dictionary that will become one CSV row.

        The commit message is sanitised (newlines, tabs, and CSV-unsafe
        characters replaced with spaces) and truncated to 150 characters
        to keep the output file readable.
        """
        raw_msg = str(commit.msg)
        clean_msg = re.sub(r'[\n\r\t,"]', ' ', raw_msg)
        clean_msg = (clean_msg[:150] + '...') if len(clean_msg) > 150 else clean_msg

        return {
            'repo_name': self.repo_name,
            'git_url': self.repo_url,
            'commit_hash': commit.hash,
            'tag': clean_msg,
            'analysis_mode': mode,
            'author_date': commit.author_date,
            **metrics,
        }