# TerraPulse: Bridging the Gap Between Code Quality and Security in IaC Ecosystems

> A longitudinal empirical study of the co-evolution of structural quality 
> and security debt in Terraform repositories.  
> Replication package for the empirical study presented in *TerraPulse: 
> Bridging the Gap Between Code Quality and Security in IaC Ecosystems*.  
> Conducted as part of the "Software Evolution and Quality" [39939] course —
> University of Sannio, Benevento, Italy.

---

## What is TerraPulse?

TerraPulse is an automated research framework that mines the Git history of 
Terraform repositories, extracts structural quality metrics aligned with 
ISO/IEC 25010, and correlates them with security vulnerabilities detected by 
Trivy. The goal is to empirically investigate whether the *way* IaC code is 
written serves as an associative signal for security risk over time.

The study analyzes **500 repositories**, **10,054 historical snapshots** 
(filtered to **9,259 unique code states**), and answers four research questions:

| RQ | Question |
|---|---|
| **RQ1 (Association)** | Are structural metrics statistically correlated with the Security Debt Index? |
| **RQ2 (Prediction)** | Which structural attributes best predict security debt magnitude? |
| **RQ3 (Evolution)** | How do structural and security debt co-evolve over a project's lifecycle? |
| **RQ4 (Characterization)** | Do distinct project archetypes exist based on debt intensity profiles? |

---

## Key Findings

- **Complexity Paradox:** Higher IaC-McCabe complexity is negatively associated 
  with security debt density (ρ = −0.319) and carries a strong protective 
  coefficient in multivariate regression (RLM: −251.29). This suggests that logical 
  abstraction (`for_each`, `count`, dynamic blocks) reduces misconfiguration 
  surface area relative to flat, repetitive code.
- **Dominant predictor:** `num_resources` accounts for 38% of feature importance 
  in the Random Forest model (CV R² = 0.397, log-space; held-out R² = 0.133 on 
  original scale), confirming that infrastructure footprint is the primary 
  driver of security debt accumulation. Raw lines of code (LOC) are largely irrelevant.
- **Structural decay is the norm:** 74.4% of mature repositories exhibit 
  continuously increasing structural debt. Joint remediation of both structural 
  and security debt occurs in only 0.6% of projects, confirming that IaC debt is highly "sticky".
- **Three archetypes:** K-Means clustering identifies *Low-to-Moderate-Debt* 
  (28.4%, structurally complex and secure), *High-Debt* (64.6%, driven by infrastructure misconfigurations), 
  and *Very-High-Debt* (7.0%, systemic liabilities driven by vulnerable external dependencies).

---

## Repository Structure
```text
TerraPulse/
├── data/
│   ├── input/              # TerraDS.sqlite (downloaded separately)
│   └── output/             # Generated datasets, logs, and figures
├── src/
│   ├── main.py             # Mining pipeline orchestrator
│   ├── config.py           # Global settings and thresholds
│   ├── mining/             # Adaptive history mining (PyDriller)
│   ├── metrics/            # Structural (HCL2) and security (Trivy) extractors
│   └── analysis/
│       ├── validate_sample.py      # Three-stage K-S representativeness test
│       ├── rq1_correlation.py      # Spearman correlation and heatmap
│       ├── rq1_advanced_stats.py   # OLS vs RLM regression and VIF analysis
│       ├── rq2_prediction.py       # Random Forest and feature importance
│       ├── rq2_surrogate_tree.py   # Global surrogate decision tree
│       ├── rq3_statistics.py       # Mann-Kendall trends and StDI computation
│       ├── rq3_visualizer.py       # Co-evolution and debt composition plots
│       └── rq4_clustering.py       # K-Means archetype discovery
├── TerraPulse_Paper.pdf    # Full paper (published version)
├── Dockerfile              # Reproducible containerized environment
└── requirements.txt        # Python dependencies
```

---

## Customizing the Analysis

TerraPulse is designed to be extensible. You can modify the scale and scope of the research by simply editing the `src/config.py` file before running the mining pipeline. Key configurable parameters include:

- `REPO_LIMIT`: Number of repositories to mine (default: `500`).
- `MIN_STARS`: GitHub star threshold to filter out toy projects (default: `10`).
- `MAX_SNAPSHOTS`: Maximum number of historical commits to analyze per repository (default: `50`).
- `REPO_ANALYSIS_TIMEOUT`: Hard-timeout in seconds to prevent the pipeline from hanging on giant repositories (default: `7200`).

---

## Replication Guide

### Prerequisites

1. Install [Docker](https://www.docker.com/).
2. Create `data/input/` and `data/output/` in the project root.
3. Download `TerraDS.sqlite` from 
   [Zenodo](https://zenodo.org/records/14217386) and place it in `data/input/`.

### Build the Environment
```bash
docker build -t terrapulse .
```

### Step 1 — Mine repositories
```bash
docker run --rm -v ${PWD}/data:/app/data terrapulse
```
> **Note:** The pipeline resumes automatically from `dataset_final.csv` on subsequent runs. If the process is interrupted, simply run the command again.

### Step 2 — Run analyses

Execute the following commands in order. All generated figures and CSV reports will be saved to `data/output/figures/`.

```bash
# Sample validation (must be run first to generate the Trivy filter list)
docker run --rm --entrypoint "" -v ${PWD}/data:/app/data terrapulse \
    python src/analysis/validate_sample.py

# RQ1 — Association
docker run --rm --entrypoint "" -v ${PWD}/data:/app/data terrapulse \
    python src/analysis/rq1_correlation.py
docker run --rm --entrypoint "" -v ${PWD}/data:/app/data terrapulse \
    python src/analysis/rq1_advanced_stats.py

# RQ2 — Prediction
docker run --rm --entrypoint "" -v ${PWD}/data:/app/data terrapulse \
    python src/analysis/rq2_prediction.py
docker run --rm --entrypoint "" -v ${PWD}/data:/app/data terrapulse \
    python src/analysis/rq2_surrogate_tree.py

# RQ3 — Evolution (requires the RQ2 feature importance CSV)
docker run --rm --entrypoint "" -v ${PWD}/data:/app/data terrapulse \
    python src/analysis/rq3_statistics.py
docker run --rm --entrypoint "" -v ${PWD}/data:/app/data terrapulse \
    python src/analysis/rq3_visualizer.py

# RQ4 — Clustering
docker run --rm --entrypoint "" -v ${PWD}/data:/app/data terrapulse \
    python src/analysis/rq4_clustering.py
```

---

## Academic Context

| | |
|---|---|
| **Course** | Evoluzione e Qualità del Software \[39939\] |
| **Institution** | Università degli Studi del Sannio, Benevento, Italy |
| **Supervisor** | Prof. Damian Andrew Tamburri |
| **Authors** | Francis Mascia & Alfonso Maria Turco |

---

## References

Key works underpinning TerraPulse's methodology:

- **Lehman (1980)** — Laws of software evolution (theoretical basis for RQ3).
- **Dalla Palma et al. (2020)** — Structural metrics mapping for IaC.
- **Rahman et al. (2019)** — Security smells in IaC (Security Debt).
- **Bühler et al. (2024)** — TerraDS dataset (Source Population).
- **Breiman (2001)** — Random Forests (Algorithmic foundation).
- **Benjamini & Hochberg (1995)** — Controlling the False Discovery Rate.

*For the full bibliography, please refer to `TerraPulse_Paper.pdf`.*
