import os
import pandas as pd
import base64
from datetime import datetime
from jinja2 import Template
import sys

# Configurazioni Path
BASE_DIR = "/app" if os.path.exists("/.dockerenv") else os.getcwd()
DATA_DIR = os.path.join(BASE_DIR, "data", "output")
FIG_DIR = os.path.join(DATA_DIR, "figures")
REPORT_PATH = os.path.join(DATA_DIR, "TerraPulse_Report.html")

# --- HTML TEMPLATE (Jinja2) ---
# Uno stile pulito, accademico e moderno
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TerraPulse Research Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f8f9fa; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 3rem 0; margin-bottom: 2rem; }
        .card { border: none; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 2rem; }
        .card-header { background-color: white; border-bottom: 2px solid #f0f0f0; font-weight: bold; color: #555; }
        .metric-box { text-align: center; padding: 1.5rem; }
        .metric-value { font-size: 2.5rem; font-weight: bold; color: #2c3e50; }
        .metric-label { color: #7f8c8d; text-transform: uppercase; font-size: 0.85rem; letter-spacing: 1px; }
        .img-fluid { border-radius: 8px; border: 1px solid #eee; }
        table { font-size: 0.9rem; }
        .footer { text-align: center; padding: 2rem; color: #aaa; font-size: 0.9rem; }
    </style>
</head>
<body>

    <!-- HEADER -->
    <div class="header text-center">
        <div class="container">
            <h1 class="display-4 fw-bold">🌍 TerraPulse</h1>
            <p class="lead">Longitudinal Empirical Study on Terraform Evolution</p>
            <p class="mt-3"><small>Generated on: {{ date }}</small></p>
        </div>
    </div>

    <div class="container">
        
        <!-- EXECUTIVE SUMMARY -->
        <div class="card">
            <div class="card-header">📊 Executive Summary</div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-3 metric-box">
                        <div class="metric-value">{{ total_repos }}</div>
                        <div class="metric-label">Repositories Mined</div>
                    </div>
                    <div class="col-md-3 metric-box">
                        <div class="metric-value">{{ total_snapshots }}</div>
                        <div class="metric-label">Total Snapshots</div>
                    </div>
                    <div class="col-md-3 metric-box">
                        <div class="metric-value">{{ avg_debt|round(1) }}</div>
                        <div class="metric-label">Avg Security Debt</div>
                    </div>
                    <div class="col-md-3 metric-box">
                        <div class="metric-value">{{ avg_loc|round(0)|int }}</div>
                        <div class="metric-label">Avg LOC per Module</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- RQ1: CORRELATION -->
        <div class="card">
            <div class="card-header">RQ1: Structural Quality vs Security Correlation</div>
            <div class="card-body">
                <div class="row align-items-center">
                    <div class="col-lg-6">
                        <p>This section analyzes the correlation between structural metrics and security debt using Spearman's rank correlation coefficient on unique code states.</p>
                        <table class="table table-striped table-hover">
                            <thead class="table-dark">
                                <tr>
                                    <th>Quality Metric</th>
                                    <th>Spearman Coeff</th>
                                    <th>Significance</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for row in rq1_data %}
                                <tr>
                                    <td>{{ row['Quality Metric'] }}</td>
                                    <td><strong>{{ row['Spearman Coeff'] }}</strong></td>
                                    <td>
                                        {% if row['Significant'] == 'YES' %}
                                            <span class="badge bg-success">Significant</span>
                                        {% else %}
                                            <span class="badge bg-secondary">Not Significant</span>
                                        {% endif %}
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                    <div class="col-lg-6 text-center">
                        {% if rq1_img %}
                        <img src="data:image/png;base64,{{ rq1_img }}" class="img-fluid" alt="Correlation Heatmap">
                        {% else %}
                        <div class="alert alert-warning">Heatmap image not found.</div>
                        {% endif %}
                    </div>
                </div>
            </div>
        </div>

        <!-- RQ2: PREDICTION -->
        <div class="card">
            <div class="card-header">RQ2: Predictors of Security Debt (Random Forest)</div>
            <div class="card-body">
                <p>Feature importance analysis derived from the Random Forest Regressor model (R² Score: <strong>{{ r2_score }}</strong>).</p>
                <div class="text-center">
                     {% if rq2_img %}
                        <img src="data:image/png;base64,{{ rq2_img }}" class="img-fluid" style="max-height: 500px;" alt="Feature Importance">
                    {% else %}
                        <div class="alert alert-warning">Feature Importance image not found.</div>
                    {% endif %}
                </div>
            </div>
        </div>

        <!-- RQ3: EVOLUTION -->
        <div class="card">
            <div class="card-header">RQ3: Evolutionary Dynamics</div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-4">
                        <h5>Trend Distribution</h5>
                        <p>Distribution of security debt trends across the analyzed ecosystem (Mann-Kendall Test).</p>
                        {% if rq3_pie %}
                            <img src="data:image/png;base64,{{ rq3_pie }}" class="img-fluid" alt="Trend Pie Chart">
                        {% endif %}
                    </div>
                    <div class="col-md-8">
                        <h5>Case Studies</h5>
                        <p>Selected examples of evolutionary patterns found in the dataset.</p>
                        <div class="row">
                            {% for img in rq3_examples %}
                            <div class="col-12 mb-3">
                                <img src="data:image/png;base64,{{ img }}" class="img-fluid" alt="Evolution Plot">
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                </div>
            </div>
        </div>

    </div>

    <div class="footer">
        Generated by <strong>TerraPulse</strong> | Software Evolution & Quality Course | Università degli Studi del Sannio
    </div>

</body>
</html>
"""

def img_to_base64(path):
    """Converte un'immagine su disco in stringa Base64 per l'embedding HTML."""
    if not os.path.exists(path):
        return None
    with open(path, "rb") as img_file:
        return base64.b64encode(img_file.read()).decode('utf-8')

def generate_report():
    print("--- Generazione Report HTML TerraPulse ---")
    
    # 1. Caricamento Dati Sommario
    try:
        df_main = pd.read_csv(os.path.join(DATA_DIR, "dataset_final.csv"))
        total_repos = df_main['repo_name'].nunique()
        total_snapshots = len(df_main)
        avg_debt = df_main['security_debt_score'].mean()
        avg_loc = df_main['loc'].mean()
    except Exception as e:
        print(f"Errore caricamento dataset principale: {e}")
        return

    # 2. Caricamento Dati RQ1
    rq1_data = []
    try:
        df_rq1 = pd.read_csv(os.path.join(DATA_DIR, "figures", "rq1_statistics_clean.csv"))
        # Prendiamo solo le top 8 correlazioni per la tabella
        rq1_data = df_rq1.head(8).to_dict(orient='records')
    except:
        pass
    
    # 3. Caricamento Dati RQ2 (Performance)
    r2_score = "N/A"
    try:
        with open(os.path.join(DATA_DIR, "figures", "rq2_model_performance.txt"), 'r') as f:
            for line in f:
                if "R2 Score" in line:
                    r2_score = str(round(float(line.split(":")[1].strip()), 3))
    except:
        pass

    # 4. Caricamento Immagini
    rq1_img = img_to_base64(os.path.join(FIG_DIR, "rq1_heatmap_unique.png"))
    rq2_img = img_to_base64(os.path.join(FIG_DIR, "rq2_importance.png"))
    rq3_pie = img_to_base64(os.path.join(FIG_DIR, "rq3_trend_distribution_pie.png"))

    # Cerchiamo 2-3 immagini di esempio per la RQ3 (quelle rigurous)
    rq3_examples = []
    for f in sorted(os.listdir(FIG_DIR)):
        if f.startswith("rq3_rigorous_") and f.endswith(".png"):
            encoded = img_to_base64(os.path.join(FIG_DIR, f))
            if encoded: rq3_examples.append(encoded)
            if len(rq3_examples) >= 2: break # Ne mostriamo solo 2 per non intasare

    # 5. Rendering Template
    template = Template(HTML_TEMPLATE)
    html_output = template.render(
        date=datetime.now().strftime("%Y-%m-%d %H:%M"),
        total_repos=total_repos,
        total_snapshots=total_snapshots,
        avg_debt=avg_debt,
        avg_loc=avg_loc,
        rq1_data=rq1_data,
        rq1_img=rq1_img,
        r2_score=r2_score,
        rq2_img=rq2_img,
        rq3_pie=rq3_pie,
        rq3_examples=rq3_examples
    )

    # 6. Salvataggio
    with open(REPORT_PATH, "w", encoding='utf-8') as f:
        f.write(html_output)
    
    print(f"✅ Report generato con successo: {REPORT_PATH}")

if __name__ == "__main__":
    generate_report()