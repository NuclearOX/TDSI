import hcl2
import os
import logging
import re
from typing import Dict, Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Directory blacklist: synchronized with RepoMiner._calculate_tf_content_hash
# to ensure that quality analysis and deduplication operate on the same set
# of production files.
# ---------------------------------------------------------------------------
DIRS_TO_EXCLUDE = frozenset([
    '.git', '.github', '.terraform', '.idea', '.vscode',
    'vendor', 'node_modules', 'examples', 'example',
    'tests', 'test', 'fixtures', 'modules_override', 'spec'
])

# ---------------------------------------------------------------------------
# HCL keys whose values are structurally required to be static strings and
# therefore do NOT constitute a parameterization smell.
# 'name' is intentionally excluded from this list: in Terraform, resource
# names (e.g. S3 bucket names, IAM role names) are a primary location for
# hard-coded production values and must be tracked as structural debt.
# ---------------------------------------------------------------------------
IGNORED_HARDCODE_KEYS = frozenset([
    'description', 'type', 'source', 'version', 'required_version',
    'backend', 'alias', 'provider', 'key', 'format', 'region',
])

# Prefixes that identify HCL interpolation references (internal connectivity).
REFERENCE_PREFIXES = (
    'var.', 'local.', 'module.', 'data.', 'each.', 'self.',
    'aws_', 'google_', 'azurerm_', 'kubernetes_', 'helm_',
)

# Meta-arguments that represent conditional branching / iteration and
# contribute one decision point each to the approximated McCabe complexity.
COMPLEXITY_KEYS = frozenset(['count', 'for_each', 'dynamic'])


class QualityAnalyzer:
    """
    Advanced structural analyzer for Terraform HCL code.

    Computes a suite of metrics aligned with ISO/IEC 25010 quality
    characteristics, following the catalogs of Dalla Palma et al. (2020),
    Konala et al. (2025), and the AST-based approach of TerraMetrics
    (Begoug et al., 2024).

    Metric overview
    ---------------
    Size / Structure     : loc, num_resources, files_analyzed
    Complexity           : iac_mccabe_complexity  (approximated McCabe index)
    Coupling             : num_modules, num_providers, internal_references
    Interface            : num_variables, num_outputs
    Maintainability      : hard_coded_values, comment_lines

    Design notes
    ------------
    * Ternary detection is performed exclusively on the parsed AST string
      values, not with a raw-text regex, to avoid false positives caused by
      map literals, label colons, and URL schemes.
    * Meta-argument loops (count / for_each / dynamic) are counted once per
      AST node so that duplicates introduced by the recursive walk are avoided.
    * 'name' is treated as a hard-coded value candidate because resource and
      bucket names are a primary location for environment-specific literals.
    """

    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.metrics: Dict[str, Any] = {
            # --- SIZE & STRUCTURE (ISO: Functional Suitability) ---
            'loc': 0,                   # Non-blank, non-comment source lines
            'num_resources': 0,         # resource + data blocks
            'files_analyzed': 0,        # .tf files successfully processed

            # --- COMPLEXITY (ISO: Maintainability / Analysability) ---
            # Approximated McCabe: +1 base, +1 per loop meta-argument
            # (count / for_each / dynamic), +1 per ternary expression.
            'iac_mccabe_complexity': 0,

            # --- COUPLING & INTEGRATION (ISO: Modularity / Compatibility) ---
            'num_modules': 0,           # External module calls
            'num_providers': 0,         # Distinct provider types
            'internal_references': 0,   # Cross-resource / variable references

            # --- INTERFACE (ISO: Reusability) ---
            'num_variables': 0,         # Input variable declarations
            'num_outputs': 0,           # Output value declarations

            # --- MAINTAINABILITY (ISO: Modifiability / Documentation) ---
            'hard_coded_values': 0,     # Lack-of-parameterization smell
            'comment_lines': 0,         # Inline documentation lines
        }
        self._unique_providers: set = set()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def analyze(self) -> Dict[str, Any]:
        """
        Recursively walks the repository, skips non-production directories,
        and aggregates structural metrics across all .tf files.

        Returns the populated metrics dictionary.
        """
        self._reset()

        for root, dirs, files in os.walk(self.repo_path):
            # Prune non-production directories in-place so os.walk does not
            # descend into them (examples, tests, vendor, etc.).
            dirs[:] = [d for d in dirs if d not in DIRS_TO_EXCLUDE]

            for file in sorted(files):
                if file.endswith('.tf'):
                    self._analyze_file(os.path.join(root, file))

        # Finalize derived metrics
        self.metrics['num_providers'] = len(self._unique_providers)

        # Base complexity is 1 when the module contains any executable code,
        # representing the single default execution path (McCabe baseline).
        if self.metrics['loc'] > 0:
            self.metrics['iac_mccabe_complexity'] += 1

        return self.metrics

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _reset(self) -> None:
        """Resets all counters so the instance can be reused safely."""
        for k in self.metrics:
            self.metrics[k] = 0
        self._unique_providers = set()

    def _analyze_file(self, file_path: str) -> None:
        """
        Performs a two-pass analysis of a single .tf file:

        Pass 1 (text level) — line counting only.
            Counts LOC and comment lines from raw text because these metrics
            are meaningful even when HCL parsing fails.

        Pass 2 (AST level) — structural and semantic analysis.
            Uses the python-hcl2 parser to obtain a structured representation
            of the file. Ternary detection and meta-argument counting are done
            here to eliminate regex false positives.
            Falls back to a conservative regex estimate if parsing fails.
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            self.metrics['files_analyzed'] += 1

            # ----------------------------------------------------------
            # Pass 1: Text-level line counting
            # ----------------------------------------------------------
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped.startswith(('#', '//')):
                    self.metrics['comment_lines'] += 1
                else:
                    self.metrics['loc'] += 1

            # ----------------------------------------------------------
            # Pass 2: AST-level structural analysis
            # ----------------------------------------------------------
            try:
                data = hcl2.loads(content)
            except Exception:
                # Parsing failed: keep text-level metrics already collected
                # and fall back to a conservative regex estimate for loops so
                # that iac_mccabe_complexity is not silently zeroed out.
                self._fallback_complexity(content)
                return

            # High-level block counts
            self.metrics['num_resources'] += len(data.get('resource', []))
            self.metrics['num_resources'] += len(data.get('data', []))
            self.metrics['num_modules']   += len(data.get('module', []))
            self.metrics['num_variables'] += len(data.get('variable', []))
            self.metrics['num_outputs']   += len(data.get('output', []))

            # Unique provider types
            for provider_block in data.get('provider', []):
                if isinstance(provider_block, dict):
                    for p_name in provider_block.keys():
                        self._unique_providers.add(p_name)

            # Recursive deep scan for complexity, connectivity, and debt
            self._scan_ast(data)

        except Exception as e:
            logger.debug(f"Error analyzing {file_path}: {e}")

    def _fallback_complexity(self, content: str) -> None:
        """
        Conservative text-based fallback used when HCL2 parsing fails.

        Counts explicit loop meta-argument assignments only. Ternary
        detection is intentionally skipped in fallback mode to avoid
        the false-positive problem inherent in raw-text regex matching
        against HCL map literals and URL colons.
        """
        loops = len(re.findall(r'^\s*(count|for_each|dynamic)\s*=', content, re.MULTILINE))
        self.metrics['iac_mccabe_complexity'] += loops

    def _scan_ast(self, node: Any) -> None:
        """
        Recursively walks the parsed HCL AST to collect:

        * Complexity points — one per loop meta-argument node
          (count / for_each / dynamic) and one per ternary expression
          found inside string values.
        * Internal references — string values that reference other
          Terraform objects (var., local., module., resource types, etc.).
        * Hard-coded values — string values that are static literals
          in semantically significant attribute positions.
        """
        if isinstance(node, dict):
            for key, value in node.items():
                # --- Complexity: loop and dynamic meta-arguments ---
                if key in COMPLEXITY_KEYS:
                    self.metrics['iac_mccabe_complexity'] += 1

                # --- String value analysis ---
                if isinstance(value, str):
                    # Ternary detection on AST string values only.
                    # The pattern matches a '?' followed by a ':' with at least
                    # one non-special character in between, using a non-greedy
                    # quantifier to avoid spanning across unrelated tokens.
                    ternaries = len(re.findall(r'\?\s*\S[^?:\n]*?\s*:', value))
                    self.metrics['iac_mccabe_complexity'] += ternaries

                    # Classify the string as a reference or a hard-coded value
                    self._classify_string(key, value)

                # Recurse into nested structures
                self._scan_ast(value)

        elif isinstance(node, list):
            for item in node:
                self._scan_ast(item)

    def _classify_string(self, key: str, value: str) -> None:
        """
        Classifies a string attribute value as either:

        (a) An internal reference — the value contains a Terraform
            interpolation reference to another object in the graph
            (e.g. var.*, local.*, aws_*). These increase internal
            connectivity, a positive quality signal.

        (b) A hard-coded literal — the value is a static string in
            an attribute position that should ideally be parameterized.
            Keys in IGNORED_HARDCODE_KEYS are exempt because they are
            structurally required to be static (source, version, etc.).
            'name' is NOT exempt: resource/bucket names are a primary
            location for hard-coded environment-specific values.
        """
        inner = value.strip()

        # (a) Internal reference check
        if any(inner.startswith(prefix) or f'${{{prefix}' in inner
               for prefix in REFERENCE_PREFIXES):
            self.metrics['internal_references'] += 1
            return

        # (b) Hard-coded value check
        # Skip keys whose values are legitimately static.
        if key in IGNORED_HARDCODE_KEYS:
            return

        # Skip trivially short strings (single chars, empty after strip).
        if len(inner) <= 1:
            return

        # Skip pure numeric strings — they are not parameterization smells
        # in the same sense as environment-specific identifiers.
        if inner.lstrip('-').isdigit():
            return

        # At this point the value is a non-trivial static literal in a
        # semantically significant attribute: count it as structural debt.
        self.metrics['hard_coded_values'] += 1