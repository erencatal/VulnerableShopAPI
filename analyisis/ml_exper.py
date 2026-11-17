import json
import os
import re
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score
from scipy.stats import wilcoxon

# 1. PARSE ALL THREE SECURITY LAYERS (SAST + SCA + DAST)
def load_all_findings():
    records = []

    # --- Layer 1: Semgrep (SAST) ---
    if os.path.exists("semgrep-report.json"):
        with open("semgrep-report.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        for res in data.get("results", []):
            meta = res.get("extra", {}).get("metadata", {})
            cwe = meta.get("cwe", ["CWE-0"])[0].split(":")[0]
            sev = res.get("extra", {}).get("severity", "WARNING")
            base_score = 85.0 if sev == "ERROR" else 50.0
            records.append({
                "tool": "SAST",
                "title": res.get("check_id", "").split(".")[-1],
                "cwe": cwe,
                "location": res.get("path", ""),
                "description": res.get("extra", {}).get("message", ""),
                "raw_severity": sev,
                "baseline_score": base_score
            })

    # --- Layer 2: Trivy (SCA) ---
    if os.path.exists("trivy-report.json"):
        with open("trivy-report.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        for res in data.get("Results", []):
            for vuln in res.get("Vulnerabilities", []):
                sev = vuln.get("Severity", "MEDIUM")
                base_score = {"CRITICAL": 95.0, "HIGH": 80.0, "MEDIUM": 55.0, "LOW": 30.0}.get(sev, 40.0)
                cwe_ids = vuln.get("CweIDs", ["CWE-0"])
                records.append({
                    "tool": "SCA",
                    "title": f"{vuln.get('PkgName')} ({vuln.get('VulnerabilityID')})",
                    "cwe": cwe_ids[0] if cwe_ids else "CWE-0",
                    "location": res.get("Target", ""),
                    "description": vuln.get("Title", "") + " " + vuln.get("Description", ""),
                    "raw_severity": sev,
                    "baseline_score": base_score
                })

    # --- Layer 3: OWASP ZAP (DAST) ---
    if os.path.exists("zap-report.json"):
        with open("zap-report.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                rc = int(alert.get("riskcode", 0))
                sev = {3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFO"}.get(rc, "INFO")
                base_score = {3: 80.0, 2: 55.0, 1: 30.0, 0: 10.0}.get(rc, 10.0)
                cwe = f"CWE-{alert.get('cweid', '0')}"
                for inst in alert.get("instances", []):
                    records.append({
                        "tool": "DAST",
                        "title": alert.get("alert", ""),
                        "cwe": cwe,
                        "location": inst.get("uri", ""),
                        "description": alert.get("desc", ""),
                        "raw_severity": sev,
                        "baseline_score": base_score
                    })

    return pd.DataFrame(records)

# 2. GROUND TRUTH LABELING (1 = Actionable Real Vulnerability, 0 = False Positive / Low-Impact Noise)
def assign_ground_truth(df):
    critical_cwes = {"CWE-89", "CWE-79", "CWE-78", "CWE-284", "CWE-639", "CWE-400", "CWE-1333"}
    noise_patterns = r"(\.png|\.css|\.js|/swagger|/robots\.txt|/sitemap\.xml)"

    labels = []
    for _, row in df.iterrows():
        is_noise_path = bool(re.search(noise_patterns, row["location"], re.IGNORECASE))
        if is_noise_path:
            labels.append(0)
        elif row["cwe"] in critical_cwes or row["tool"] == "SCA":
            labels.append(1)
        elif row["raw_severity"] in ["HIGH", "CRITICAL", "ERROR"]:
            labels.append(1)
        else:
            labels.append(0)
    df["ground_truth"] = labels
    return df

# 3. FEATURE ENGINEERING FOR ML PRIORITIZATION
def build_features(df, include_context=True, include_text=True):
    feat = pd.DataFrame()
    feat["baseline_score"] = df["baseline_score"] / 100.0
    feat["is_sast"] = (df["tool"] == "SAST").astype(int)
    feat["is_sca"] = (df["tool"] == "SCA").astype(int)
    feat["is_dast"] = (df["tool"] == "DAST").astype(int)

    if include_context:
        feat["is_api_route"] = df["location"].str.contains("/api/", case=False, regex=False).astype(int)
        feat["is_static_asset"] = df["location"].str.contains(r"\.(?:png|css|js)|/swagger|/robots", case=False, regex=True).astype(int)
        feat["is_high_impact_cwe"] = df["cwe"].isin(["CWE-89", "CWE-79", "CWE-284", "CWE-639", "CWE-400", "CWE-1333"]).astype(int)

    if include_text:
        tfidf = TfidfVectorizer(max_features=25, stop_words="english")
        text_data = (df["title"] + " " + df["description"]).fillna("")
        tfidf_mat = tfidf.fit_transform(text_data).toarray()
        tfidf_df = pd.DataFrame(tfidf_mat, columns=[f"tfidf_{i}" for i in range(tfidf_mat.shape[1])])
        feat = pd.concat([feat.reset_index(drop=True), tfidf_df], axis=1)

    return feat

def evaluate_experiments():
    df = load_all_findings()
    df = assign_ground_truth(df)

    y_true = df["ground_truth"].values
    print(f"Total Aggregated Findings: {len(df)} | True Vulnerabilities: {y_true.sum()} | Noise/FP: {len(df) - y_true.sum()}\n")

    # --- BASELINE 1: Raw Tool Severity Threshold (>= 55 means Medium/High/Critical) ---
    y_pred_base1 = (df["baseline_score"] >= 55.0).astype(int)
    prob_base1 = df["baseline_score"] / 100.0

    # --- ABLATION 1: ML without Context Features (Only Tool + TF-IDF) ---
    X_no_ctx = build_features(df, include_context=False, include_text=True)
    clf_no_ctx = RandomForestClassifier(n_estimators=100, random_state=42)
    cv = StratifiedKFold(n_splits=min(5, max(2, y_true.sum())), shuffle=True, random_state=42)
    prob_no_ctx = cross_val_predict(clf_no_ctx, X_no_ctx, y_true, cv=cv, method="predict_proba")[:, 1]
    y_pred_no_ctx = (prob_no_ctx >= 0.5).astype(int)

    # --- PROPOSED METHOD: Full Context-Aware ML Prioritizer ---
    X_full = build_features(df, include_context=True, include_text=True)
    clf_full = RandomForestClassifier(n_estimators=100, random_state=42)
    prob_full = cross_val_predict(clf_full, X_full, y_true, cv=cv, method="predict_proba")[:, 1]
    y_pred_full = (prob_full >= 0.5).astype(int)

    # Save prioritized output
    df["ml_risk_score"] = np.round(prob_full * 100, 2)
    df_sorted = df.sort_values(by="ml_risk_score", ascending=False)
    df_sorted.to_csv("experiment_results.csv", index=False)

    # Print Comparison Table for Research Paper
    methods = [
        ("Baseline (Raw Tool Severity)", y_pred_base1, prob_base1),
        ("Ablation (ML w/o Endpoint Context)", y_pred_no_ctx, prob_no_ctx),
        ("Proposed (Full Context-Aware ML)", y_pred_full, prob_full),
    ]

    print(f"{'Method':<36} | {'Precision':<9} | {'Recall':<8} | {'F1-Score':<8} | {'FP Rate':<8} | {'ROC-AUC':<8}")
    print("-" * 92)
    for name, y_p, y_prob in methods:
        prec = precision_score(y_true, y_p, zero_division=0)
        rec = recall_score(y_true, y_p, zero_division=0)
        f1 = f1_score(y_true, y_p, zero_division=0)
        fp = np.sum((y_p == 1) & (y_true == 0))
        tn = np.sum((y_p == 0) & (y_true == 0))
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        auc = roc_auc_score(y_true, y_prob) if len(np.unique(y_true)) > 1 else 0.0
        print(f"{name:<36} | {prec:<9.3f} | {rec:<8.3f} | {f1:<8.3f} | {fpr:<8.3f} | {auc:<8.3f}")

    # Statistical Significance Test (Wilcoxon Signed-Rank Test on Risk Scores)
    stat, p_val = wilcoxon(prob_base1, prob_full)
    print(f"\nStatistical Significance (Wilcoxon Test Baseline vs Proposed): statistic={stat:.2f}, p-value={p_val:.6f}")

if __name__ == "__main__":
    evaluate_experiments()