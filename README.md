# TerraPulse

**TerraPulse** is an automated research framework designed to analyze the co-evolution of **Structural Quality Debt** and **Security Debt** in Terraform-based Infrastructure as Code (IaC).

This project serves as the replication package for the empirical study conducted for the "Software Evolution and Quality" course at the University of Sannio (Benevento, Italy).

---

## Research Overview

The goal of this study is to determine if the structural way code is written (Complexity, Coupling, and Code Smells) serves as a leading indicator for security vulnerabilities. We answer four key Research Questions:

- **RQ1 - Association:** Is there a statistically significant correlation between Structural Quality Debt and Security Debt?
- **RQ2 - Prediction:** Which structural attributes (e.g., Hard-coded values, Complexity) serve as the best predictors for Security Debt?
- **RQ3 - Evolution:** How do Quality and Security Debt change reciprocally as a Terraform module matures over time?
- **RQ4 - Characterization:** Can we identify distinct project archetypes (e.g., *Critical Risk* vs. *Managed Monoliths*) based on their technical debt profiles?

## Key Features

- **Adaptive History Mining:** Uses `PyDriller` and a custom "Smart Sampling" strategy to extract snapshots from either official Git Tags (Releases) or significant commits across the entire project history.
- **Forced State Analysis:** Implements a robust `git checkout -f` logic to ensure every analysis is performed on the exact historical state of the files.
- **Multi-vocal Quality Model:** Integrates metrics from **Dalla Palma et al. (2020)** and **Konala et al. (2025)**, mapping Terraform attributes to the ISO/IEC 25010 standard.
- **Deep Security Scanning:** Wraps **AquaSecurity Trivy** to categorize debt into Infrastructure Misconfigurations, Dependency Vulnerabilities (CVEs), and Hard-coded Secrets.
- **Unsupervised Learning:** Implements K-Means clustering to identify project archetypes based on debt density and scale.
- **Resilient Execution:** Features a multiprocessing-based hard-timeout (90 mins per repo) and incremental resume logic to survive system crashes.

---

## Project Structure

```text
TerraPulse/
├── data/
│   ├── input/              # Source database (TerraDS.sqlite)
│   └── output/             # CSV datasets and generated figures
├── src/
│   ├── main.py             # Orchestrates the mining and analysis
│   ├── config.py           # Global settings, weights, and thresholds
│   ├── mining/             # Repository mining and sampling logic
│   ├── metrics/            # Quality (HCL2) and Security (Trivy) models
│   └── analysis/           # Statistical analysis modules
│       ├── rq1_correlation.py      # Spearman Correlation & Heatmap
│       ├── rq1_advanced_stats.py   # OLS/RLM Regression & VIF
│       ├── rq2_prediction.py       # Random Forest & Feature Importance
│       ├── rq3_statistics.py       # Evolutionary Trends & StDI Calc
│       ├── rq3_visualizer.py       # Covariance & Stacked Plots
│       └── rq4_clustering.py       # K-Means Archetype Discovery
├── Dockerfile              # Reproducible containerized environment
└── requirements.txt        # Python dependencies
```

---

## Usage Guide

### 0. Primary Setup
1. Create the `data/` folder in the project root.
2. Inside `data/`, create the `input/` and `output/` subfolders.
3. Download the **TerraDS.sqlite** file from [Zenodo](https://zenodo.org/records/14217386) and place it inside `data/input/`.

### 1. Build the Environment
Ensure Docker is installed, then build the research image:
```bash
docker build -t terrapulse .
```

### 2. Data Collection (Mining)
Run the main mining pipeline. This will clone repositories, travel through history, and generate the dataset:
```bash
docker run --rm -v ${PWD}:/app terrapulse
```
*The tool will automatically skip already processed repositories found in `dataset_final.csv`.*

### 3. Statistical Analysis & Replication
Once mining is complete, run the following commands to generate the results and figures described in the paper:

**RQ1: Association & Regression**
```bash
docker run --rm --entrypoint "" -v ${PWD}:/app terrapulse python src/analysis/rq1_correlation.py
docker run --rm --entrypoint "" -v ${PWD}:/app terrapulse python src/analysis/rq1_advanced_stats.py
```

**RQ2: Prediction & Feature Importance**
```bash
docker run --rm --entrypoint "" -v ${PWD}:/app terrapulse python src/analysis/rq2_prediction.py
```

**RQ3: Evolutionary Analysis**
```bash
docker run --rm --entrypoint "" -v ${PWD}:/app terrapulse python src/analysis/rq3_statistics.py
docker run --rm --entrypoint "" -v ${PWD}:/app terrapulse python src/analysis/rq3_visualizer.py
```

**RQ4: Archetype Clustering**
```bash
docker run --rm --entrypoint "" -v ${PWD}:/app terrapulse python src/analysis/rq4_clustering.py
```

---

## Methodology & Main References

The metrics and methodologies used in this tool are mainly grounded in the following academic works:

1.  **Konala et al. (2025)** - *A Framework for Measuring the Quality of Infrastructure-as-Code Scripts.* (Quality Mapping Framework).
2.  **Dalla Palma et al. (2020)** - *Toward a catalogue of software quality metrics for infrastructure code.* (Structural Metrics).
3.  **Rahman et al. (2019)** - *The Seven Sins: Security Smells in Infrastructure as Code Scripts.* (Security Debt Weights).
4.  **Spadini et al. (2018)** - *PyDriller: Python framework for mining software repositories.* (Mining Engine).

---

## Academic Context
- **Course:** Software Evolution and Quality [39939]
- **Institution:** University of Sannio, Benevento
- **Professor:** Damian Andrew Tamburri
- **Authors:** Francis Mascia, Alfonso Maria Turco
