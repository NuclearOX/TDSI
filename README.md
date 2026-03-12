
# TerraPulse: Bridging the Gap Between Code Quality and Security in IaC Ecosystems

**TerraPulse** is a robust, automated research framework designed to conduct large-scale, longitudinal empirical studies on the co-evolution of **Structural Quality** and **Security Debt** in Terraform-based Infrastructure as Code (IaC).

This repository serves as the complete replication package for the empirical study conducted for the "Software Evolution and Quality" [39939] course at the University of Sannio (Benevento, Italy).

---

## Research Overview

While the impact of code quality on maintainability is well-studied, its longitudinal relationship with security vulnerabilities in IaC remains largely unexplored. This project investigates whether the structural way code is written (complexity, coupling, resource density) serves as a **leading indicator** for security vulnerabilities over time.

We answer four fundamental Research Questions (RQs):

- **RQ1 (Association):** Is there a statistically significant correlation between structural code metrics and the Security Debt Index (SDI)?
- **RQ2 (Prediction):** Which structural attributes are the most reliable predictors for the emergence of security vulnerabilities?
- **RQ3 (Evolution):** How do structural and security debt co-evolve over the lifecycle of an IaC project, and what joint trend patterns can be identified across the population?
- **RQ4 (Characterization):** Is it possible to identify distinct clusters of Terraform projects with homogeneous structural and security debt intensity profiles?

### Key Findings
* **The Complexity Paradox:** Higher cyclomatic complexity in IaC acts as a protective factor, proving that abstraction (e.g., dynamic blocks, loops) prevents misconfigurations compared to flat, repetitive "copy-paste" code.
* **Predictive Power:** Using a rigorous `GroupKFold` cross-validation to prevent data leakage, structural metrics alone can explain **39% of the variance** in security debt across unseen repositories. 
* **The Inevitability of Decay:** 74.4% of the analyzed mature projects exhibit continuously increasing structural debt. Joint remediation (improving both structure and security) occurs in only 0.6% of cases.
* **Three Ecosystem Archetypes:** Risk is not uniform. The ecosystem divides into *Low-to-Moderate-Debt* (highly abstracted modules), *High-Debt* (the norm, driven by infra misconfigurations), and *Very-High-Debt* (systemic liabilities driven by vulnerable external dependencies).

---

## Key Methodological Features

- **Adaptive History Mining:** Uses `PyDriller` to extract up to 50 equidistant commits, employing a robust `git clean -fdx` logic for state consistency.
- **Three-Stage Statistical Validation:** Includes Theoretical, Empirical (post-dropout), and Post-Trivy filtering validations verified via Kolmogorov-Smirnov tests to ensure **0% selection bias and 0% systematic false negatives**.
- **Content-Hashing Deduplication:** Hashes raw `.tf` contents to skip redundant commits and completely prevent temporal autocorrelation.
- **Hybrid Quality & Security Parsing:** Merges ISO/IEC 25010 structural metrics extracted via `python-hcl2` (with regex fallback) with offline vulnerability scanning via **AquaSecurity Trivy**.
- **Advanced Statistical Modeling:** Features Benjamini-Hochberg FDR corrections, Robust Linear Models (RLM) with Huber's T norm to handle outliers, and 95th-percentile feature winsorization for K-Means clustering.

---

## Project Structure

```text
TerraPulse/
├── data/
│   ├── input/              # Source database (TerraDS.sqlite)
│   └── output/             # CSV datasets, logs, and generated figures
├── src/
│   ├── main.py             # Orchestrates the mining and analysis
│   ├── config.py           # Global settings, weights, and thresholds
│   ├── inspect_db.py       # TerraDS database inspection utility
│   ├── mining/             # Repository mining and adaptive sampling logic
│   ├── metrics/            # Quality (HCL2) and Security (Trivy) models
│   └── analysis/           # Statistical analysis modules
│       ├── validate_sample.py      # 3-Stage K-S Test Validation
│       ├── rq1_correlation.py      # Spearman Correlation & Heatmap
│       ├── rq1_advanced_stats.py   # OLS vs RLM Regression & VIF
│       ├── rq2_prediction.py       # Random Forest & Feature Importance
│       ├── rq3_statistics.py       # Mann-Kendall Trends & StDI Calc
│       ├── rq3_visualizer.py       # Covariance & Stacked Evolution Plots
│       └── rq4_clustering.py       # K-Means Archetype Discovery (Silhouette)
├── Dockerfile              # Reproducible containerized environment
└── requirements.txt        # Python dependencies
```

---

## Usage Guide & Replication

### 0. Primary Setup
1. Create the `data/` folder in the project root.
2. Inside `data/`, create the `input/` and `output/` subfolders.
3. Download the **TerraDS.sqlite** file from [Zenodo](https://zenodo.org/records/14217386) and place it inside `data/input/`.

### 1. Build the Environment
Ensure Docker is installed. This builds the isolated research image, installing Python dependencies and pre-fetching Trivy vulnerability databases:
```bash
docker build -t terrapulse .
```

### 2. Data Collection (Mining)
Run the main mining pipeline to clone repositories, extract history, and generate the raw dataset:
```bash
docker run --rm -v ${PWD}/data:/app/data terrapulse
```
*Note: The tool features a 90-minute hard-timeout per repository and a resume logic. It will automatically skip already-processed repositories found in `dataset_final.csv`.*

### 3. Statistical Analysis & Results Generation
Run the following commands sequentially to replicate the statistical tests, train the models, and generate the figures described in the paper. Results are saved in `data/output/figures/`.

**Step 3.0: Sample Validation (Crucial before RQs)**
```bash
docker run --rm --entrypoint "" -v ${PWD}/data:/app/data terrapulse python src/analysis/validate_sample.py
```

**Step 3.1: RQ1 - Association & Regression**
```bash
docker run --rm --entrypoint "" -v ${PWD}/data:/app/data terrapulse python src/analysis/rq1_correlation.py
docker run --rm --entrypoint "" -v ${PWD}/data:/app/data terrapulse python src/analysis/rq1_advanced_stats.py
```

**Step 3.2: RQ2 - Prediction & Feature Importance**
```bash
docker run --rm --entrypoint "" -v ${PWD}/data:/app/data terrapulse python src/analysis/rq2_prediction.py
```

**Step 3.3: RQ3 - Evolutionary Analysis**
*(Requires the Feature Importance CSV generated in RQ2 to calculate the Structural Debt Index)*
```bash
docker run --rm --entrypoint "" -v ${PWD}/data:/app/data terrapulse python src/analysis/rq3_statistics.py
docker run --rm --entrypoint "" -v ${PWD}/data:/app/data terrapulse python src/analysis/rq3_visualizer.py
```

**Step 3.4: RQ4 - Archetype Clustering**
```bash
docker run --rm --entrypoint "" -v ${PWD}/data:/app/data terrapulse python src/analysis/rq4_clustering.py
```

---

## Main References

The metrics and methodologies implemented in TerraPulse are grounded in the following academic works:

1. **Lehman (1980)** - *Programs, life cycles, and laws of software evolution.* (Theoretical foundation for RQ3).
2. **Dalla Palma et al. (2020)** - *Toward a catalog of software quality metrics for infrastructure code.* (Structural Metrics mapping).
3. **Rahman et al. (2019)** - *The Seven Sins: Security Smells in Infrastructure as Code Scripts.* (Security Debt concepts).
4. **Bühler et al. (2024)** - *TerraDS: A Dataset for Terraform HCL Programs.* (Source Population).

---

## Academic Context
- **Course:** Evoluzione e Qualità del Software [39939]
- **Institution:** Università degli Studi del Sannio, Benevento (Italy)
- **Professor:** Damian Andrew Tamburri
- **Authors:** Francis Mascia, Alfonso Maria Turco
