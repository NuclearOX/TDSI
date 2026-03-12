import subprocess
import json
import logging
import os
from typing import Dict, Any, Optional
from src import config

logger = logging.getLogger(__name__)


class SecurityAnalyzer:
    """
    Analyzes a directory using Trivy to identify security vulnerabilities,
    misconfigurations, and hard-coded secrets.

    Diagnostic fields
    -----------------
    trivy_scanned_files : int
        Total number of Result entries returned by Trivy.
        0 means Trivy ran but found absolutely nothing to scan (e.g. the
        repository path was empty or unrecognized entirely).

    trivy_terraform_targets : int
        Number of Result entries whose Type or Target indicates a Terraform
        file specifically (type == 'terraform' / 'terraform-plan', or target
        ending in '.tf').
        0 with trivy_scanned_files > 0 means Trivy scanned something (e.g. a
        package manifest) but did not recognize any Terraform file — the most
        common cause of systematic false negatives in this study.

    Downstream filtering rule (applied in pre-processing before RQ analysis)
    -------------------------------------------------------------------------
    Exclude repositories where trivy_terraform_targets == 0 across their
    entire ANALYZED history. These repositories cannot be meaningfully
    assessed by Trivy and would introduce systematic false negatives if
    retained. The number of excluded repositories must be reported in the
    paper under Threats to Validity (Internal Validity).
    """

    # Trivy Result types that unambiguously identify Terraform content.
    _TERRAFORM_TYPES = frozenset(['terraform', 'terraform-plan'])

    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.severity_weights = config.SEVERITY_WEIGHTS

        self.metrics: Dict[str, Any] = {
            # --- Severity counts ---
            'critical_count': 0.0,
            'high_count': 0.0,
            'medium_count': 0.0,
            'low_count': 0.0,
            # --- Aggregate debt scores ---
            'security_debt_score': 0.0,
            'infrastructure_debt': 0.0,
            'dependency_debt': 0.0,
            'secret_debt': 0.0,
            # --- Diagnostic fields ---
            # Total Result entries Trivy returned (0 = nothing scanned at all).
            'trivy_scanned_files': 0,
            # Result entries that Trivy identified as Terraform targets.
            # 0 (with trivy_scanned_files > 0) = Trivy ran but missed all .tf files.
            'trivy_terraform_targets': 0,
        }

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def analyze(self) -> Optional[Dict[str, Any]]:
        """
        Executes the security scan.

        Returns
        -------
        Dict
            On success — Trivy ran without a hard failure.
            trivy_terraform_targets == 0 signals a likely false negative;
            the snapshot is retained in the CSV for downstream filtering.
        None
            On hard failure (timeout, crash, missing binary).
            The caller (RepoMiner._process_commit) will discard this snapshot.
        """
        # Reset all counters before each scan so the instance can be reused.
        for k in self.metrics:
            self.metrics[k] = 0.0

        raw = self._run_trivy()

        if raw is None:
            # Hard failure: Trivy timed out or crashed.
            logger.error(
                f"Security analysis hard failure for: {self.repo_path}. "
                f"Snapshot will be discarded by the caller."
            )
            return None

        return self._calculate_debt(raw)

    # ------------------------------------------------------------------
    # Private — Trivy execution
    # ------------------------------------------------------------------

    def _run_trivy(self) -> Optional[Dict]:
        """
        Executes the Trivy CLI and returns parsed JSON output.

        Return values
        -------------
        Dict (possibly empty)
            Trivy ran without a fatal error. An empty dict means stdout was
            empty but stderr contained no fatal keyword — interpreted as
            "no scannable targets found at all".
        None
            Hard failure: timeout, process crash, JSON parse error, or a
            fatal keyword in stderr. The caller discards this snapshot.
        """
        if not os.path.exists(self.repo_path):
            logger.error(f"Repo path does not exist: {self.repo_path}")
            return None

        dirs_to_skip = (
            ".terraform,.git,.github,.idea,.vscode,"
            "node_modules,examples,example,tests,test,"
            "fixtures,modules_override,vendor,spec"
        )

        trivy_minutes = int(config.TRIVY_CLI_TIMEOUT.replace('m', ''))
        python_timeout = (trivy_minutes * 60) + 60  # 1-minute buffer over Trivy's own timeout

        cmd = [
            "trivy", "fs",
            "--scanners", "vuln,misconfig,secret",
            "--format", "json",
            "--quiet",
            "--skip-db-update",
            "--offline-scan",
            "--timeout", config.TRIVY_CLI_TIMEOUT,
            "--skip-dirs", dirs_to_skip,
            self.repo_path,
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=python_timeout,
            )

            if not result.stdout:
                stderr_lower = (result.stderr or "").lower()
                if "fatal" in stderr_lower or "error" in stderr_lower:
                    # Hard failure: Trivy reported a fatal condition.
                    logger.warning(
                        f"Trivy fatal error (empty stdout + error in stderr) "
                        f"for {self.repo_path}: {result.stderr[:300]}"
                    )
                    return None

                # Empty stdout with no fatal error: no targets found at all.
                # Return empty dict so _calculate_debt sets both diagnostic
                # fields to 0, correctly signalling a complete scan miss.
                logger.debug(
                    f"Trivy returned empty stdout with no fatal error "
                    f"for {self.repo_path}. Likely no scannable targets."
                )
                return {}

            return json.loads(result.stdout)

        except subprocess.TimeoutExpired:
            logger.error(
                f"Trivy TIMEOUT (Python killed after {python_timeout}s) "
                f"on: {self.repo_path}"
            )
            return None

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Trivy JSON output: {e}")
            return None

        except Exception as e:
            logger.error(f"Critical error during Trivy execution: {e}")
            return None

    # ------------------------------------------------------------------
    # Private — debt calculation
    # ------------------------------------------------------------------

    def _calculate_debt(self, data: Dict) -> Dict[str, Any]:
        """
        Aggregates Trivy findings into weighted debt scores and populates
        the two diagnostic fields.

        trivy_scanned_files     = total number of Result entries.
        trivy_terraform_targets = subset of Results that Trivy identified
                                  as Terraform content specifically.
        """
        results = data.get('Results', [])

        # Diagnostic field 1: did Trivy find anything to scan at all?
        self.metrics['trivy_scanned_files'] = len(results)

        # Diagnostic field 2: did Trivy specifically recognize Terraform files?
        terraform_results = [
            r for r in results
            if r.get('Type', '').lower() in self._TERRAFORM_TYPES
            or str(r.get('Target', '')).endswith('.tf')
        ]
        self.metrics['trivy_terraform_targets'] = len(terraform_results)

        if self.metrics['trivy_terraform_targets'] == 0 and len(results) > 0:
            logger.warning(
                f"Trivy scanned {len(results)} target(s) but found zero "
                f"Terraform-specific results in {self.repo_path}. "
                f"Possible false negative — repo will be flagged for filtering."
            )

        # Aggregate findings across all result types.
        for res in results:
            misconfs = res.get('Misconfigurations') or []
            vulns    = res.get('Vulnerabilities')   or []
            secrets  = res.get('Secrets')           or []

            for issue in misconfs:
                if issue.get('Status') == 'FAIL':
                    self._add_issue(issue, category='infrastructure')

            for issue in vulns:
                self._add_issue(issue, category='dependency')

            for issue in secrets:
                self._add_issue(issue, category='secret')

        return self.metrics

    def _add_issue(self, issue: Dict, category: str) -> None:
        severity = issue.get('Severity', 'UNKNOWN').upper()
        weight   = self.severity_weights.get(severity, 0.0)

        if severity == 'CRITICAL':
            self.metrics['critical_count'] += 1
        elif severity == 'HIGH':
            self.metrics['high_count'] += 1
        elif severity == 'MEDIUM':
            self.metrics['medium_count'] += 1
        elif severity == 'LOW':
            self.metrics['low_count'] += 1

        self.metrics['security_debt_score'] += weight

        if category == 'infrastructure':
            self.metrics['infrastructure_debt'] += weight
        elif category == 'dependency':
            self.metrics['dependency_debt'] += weight
        elif category == 'secret':
            self.metrics['secret_debt'] += weight