import json
import os
import re
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score, roc_curve
from scipy.stats import wilcoxon

def parse_dataset(dataset_name, semgrep_file, trivy_file, zap_file):
    records = []

    # 1. SAST (Semgrep)
    if os.path.exists(semgrep_file):
        with open(semgrep_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        for res in data.get("results", []):
            meta = res.get("extra", {}).get("metadata", {})
            cwe = meta.get("cwe", ["CWE-0"])[0].split(":")[0]
            sev = res.get("extra", {}).get("severity", "WARNING")
            base_score = 85.0 if sev == "ERROR" else 50.0
            records.append({
                "dataset": dataset_name,
                "tool": "SAST",
                "title": res.get("check_id", "").split(".")[-1],
                "cwe": cwe,
                "location": res.get("path", ""),
                "description": res.get("extra", {}).get("message", ""),
                "raw_severity": sev,
                "baseline_score": base_score
            })

    # 2. SCA (Trivy)
    if os.path.exists(trivy_file):
        with open(trivy_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        for res in data.get("Results", []):
            for vuln in res.get("Vulnerabilities", []):
                sev = vuln.get("Severity", "MEDIUM")
                base_score = {"CRITICAL": 95.0, "HIGH": 80.0, "MEDIUM": 55.0, "LOW": 30.0}.get(sev, 40.0)
                cwe_ids = vuln.get("CweIDs", ["CWE-0"])
                records.append({
                    "dataset": dataset_name,
                    "tool": "SCA",
                    "title": f"{vuln.get('PkgName')} ({vuln.get('VulnerabilityID')})",
                    "cwe": cwe_ids[0] if cwe_ids else "CWE-0",
                    "location": res.get("Target", ""),
                    "description": vuln.get("Title", "") + " " + vuln.get("Description", ""),
                    "raw_severity": sev,
                    "baseline_score": base_score
                })

    # 3. DAST (OWASP ZAP)
    if os.path.exists(zap_file):
        with open(zap_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                rc = int(alert.get("riskcode", 0))
                sev = {3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFO"}.get(rc, "INFO")
                base_score = {3: 80.0, 2: 55.0, 1: 30.0, 0: 10.0}.get(rc, 10.0)
                cwe = f"CWE-{alert.get('cweid', '0')}"
                for inst in alert.get("instances", []):
                    records.append({
                        "dataset": dataset_name,
                        "tool": "DAST",
                        "title": alert.get("alert", ""),
                        "cwe": cwe,
                        "location": inst.get("uri", ""),
                        "description": alert.get("desc", ""),
                        "raw_severity": sev,
                        "baseline_score": base_score
                    })

    return pd.DataFrame(records)

def assign_ground_truth(df):
    critical_cwes = {"CWE-89", "CWE-79", "CWE-78", "CWE-284", "CWE-639", "CWE-400", "CWE-1333", "CWE-22", "CWE-94"}
    noise_patterns = r"(\.png|\.css|\.js|\.ico|\.woff|/swagger|/robots\.txt|/sitemap\.xml|/assets/)"

    labels = []
    for _, row in df.iterrows():
        is_noise_path = bool(re.search(noise_patterns, row["location"], re.IGNORECASE)) and row["tool"] == "DAST"
        if is_noise_path:
            labels.append(0)
        elif row["cwe"] in critical_cwes or (row["tool"] == "SCA" and row["raw_severity"] in ["CRITICAL", "HIGH"]):
            labels.append(1)
        elif row["raw_severity"] in ["HIGH", "CRITICAL", "ERROR"]:
            labels.append(1)
        else:
            labels.append(0)
    df["ground_truth"] = labels
    return df

def build_features(df, include_context=True, include_text=True, vectorizer=None):
    feat = pd.DataFrame()
    feat["baseline_score"] = df["baseline_score"] / 100.0
    feat["is_sast"] = (df["tool"] == "SAST").astype(int)
    feat["is_sca"] = (df["tool"] == "SCA").astype(int)
    feat["is_dast"] = (df["tool"] == "DAST").astype(int)

    if include_context:
        feat["is_api_or_route"] = df["location"].str.contains(r"/api/|/rest/|routes/", case=False, regex=True).astype(int)
        feat["is_static_asset"] = df["location"].str.contains(r"\.(?:png|css|js|ico)|/swagger|/robots|/assets/", case=False, regex=True).astype(int)
        feat["is_high_impact_cwe"] = df["cwe"].isin(["CWE-89", "CWE-79", "CWE-78", "CWE-284", "CWE-639", "CWE-22", "CWE-94"]).astype(int)

    if include_text:
        text_data = (df["title"] + " " + df["description"]).fillna("")
        if vectorizer is None:
            vectorizer = TfidfVectorizer(max_features=30, stop_words="english")
            tfidf_mat = vectorizer.fit_transform(text_data).toarray()
        else:
            tfidf_mat = vectorizer.transform(text_data).toarray()
        tfidf_df = pd.DataFrame(tfidf_mat, columns=[f"tfidf_{i}" for i in range(tfidf_mat.shape[1])])
        feat = pd.concat([feat.reset_index(drop=True), tfidf_df], axis=1)

    return feat, vectorizer

def main():
    df_custom = parse_dataset("VulnerableShopAPI", "semgrep-report.json", "trivy-report.json", "zap-report.json")
    df_juice = parse_dataset("OWASP_JuiceShop", "juiceshop-semgrep.json", "juiceshop-trivy.json", "juiceshop-zap.json")
    
    df = pd.concat([df_custom, df_juice], ignore_index=True)
    # Deduplicate identical alerts on same location
    df = df.drop_duplicates(subset=["dataset", "tool", "title", "location"]).reset_index(drop=True)
    df = assign_ground_truth(df)

    y_true = df["ground_truth"].values
    print(f"=== COMBINED BENCHMARK SUMMARY ===")
    print(f"Total Deduplicated Findings : {len(df)}")
    print(f" - VulnerableShopAPI (.NET) : {len(df[df['dataset']=='VulnerableShopAPI'])}")
    print(f" - OWASP Juice Shop (Node)  : {len(df[df['dataset']=='OWASP_JuiceShop'])}")
    print(f"Actionable Vulnerabilities  : {y_true.sum()} | False Positive Noise: {len(df) - y_true.sum()}\n")

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    # 1. Baseline 1: Raw Tool Severity (>= 55)
    prob_base1 = df["baseline_score"].values / 100.0
    pred_base1 = (df["baseline_score"].values >= 55.0).astype(int)

    # 2. Baseline 2: Logistic Regression (Linear Model)
    X_full, vec = build_features(df, include_context=True, include_text=True)
    prob_lr = cross_val_predict(LogisticRegression(max_iter=500), X_full, y_true, cv=cv, method="predict_proba")[:, 1]
    pred_lr = (prob_lr >= 0.5).astype(int)

    # 3. Ablation: Random Forest WITHOUT Endpoint Context
    X_no_ctx, _ = build_features(df, include_context=False, include_text=True)
    prob_ablation = cross_val_predict(RandomForestClassifier(n_estimators=100, random_state=42), X_no_ctx, y_true, cv=cv, method="predict_proba")[:, 1]
    pred_ablation = (prob_ablation >= 0.5).astype(int)

    # 4. Proposed Method: Full Context-Aware Random Forest
    prob_prop = cross_val_predict(RandomForestClassifier(n_estimators=100, random_state=42), X_full, y_true, cv=cv, method="predict_proba")[:, 1]
    pred_prop = (prob_prop >= 0.5).astype(int)

    methods = [
        ("Baseline 1 (Raw Severity)", pred_base1, prob_base1),
        ("Baseline 2 (Logistic Regression)", pred_lr, prob_lr),
        ("Ablation (RF w/o Context)", pred_ablation, prob_ablation),
        ("Proposed (Context-Aware RF)", pred_prop, prob_prop),
    ]

    print(f"{'Method':<34} | {'Precision':<9} | {'Recall':<8} | {'F1-Score':<8} | {'FP Rate':<8} | {'ROC-AUC':<8}")
    print("-" * 90)
    f1_scores, fpr_scores, names = [], [], []
    for name, y_p, y_prob in methods:
        prec = precision_score(y_true, y_p, zero_division=0)
        rec = recall_score(y_true, y_p, zero_division=0)
        f1 = f1_score(y_true, y_p, zero_division=0)
        fp = np.sum((y_p == 1) & (y_true == 0))
        tn = np.sum((y_p == 0) & (y_true == 0))
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        auc = roc_auc_score(y_true, y_prob)
        f1_scores.append(f1)
        fpr_scores.append(fpr)
        names.append(name.split(" (")[0])
        print(f"{name:<34} | {prec:<9.3f} | {rec:<8.3f} | {f1:<8.3f} | {fpr:<8.3f} | {auc:<8.3f}")

    stat, p_val = wilcoxon(prob_base1, prob_prop)
    print(f"\nWilcoxon Signed-Rank Test (Baseline 1 vs Proposed): W={stat:.2f}, p-value={p_val:.6e}")

    # 5. RQ4 Cross-Project Generalization (Train on Juice Shop -> Test on VulnerableShopAPI)
    train_idx = df["dataset"] == "OWASP_JuiceShop"
    test_idx = df["dataset"] == "VulnerableShopAPI"
    if train_idx.sum() > 0 and test_idx.sum() > 0:
        clf_gen = RandomForestClassifier(n_estimators=100, random_state=42)
        clf_gen.fit(X_full[train_idx], y_true[train_idx])
        gen_probs = clf_gen.predict_proba(X_full[test_idx])[:, 1]
        gen_preds = (gen_probs >= 0.5).astype(int)
        print(f"\n=== RQ4: UNSEEN APP GENERALIZATION (Train: JuiceShop -> Test: ASP.NET App) ===")
        print(f"F1-Score: {f1_score(y_true[test_idx], gen_preds, zero_division=0):.3f} | ROC-AUC: {roc_auc_score(y_true[test_idx], gen_probs):.3f}")

    # Generate Paper Figures
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.8))
    
    # Plot 1: ROC Curves
    for name, _, y_prob in methods:
        fpr_c, tpr_c, _ = roc_curve(y_true, y_prob)
        auc_val = roc_auc_score(y_true, y_prob)
        ax1.plot(fpr_c, tpr_c, label=f"{name} (AUC={auc_val:.2f})", linewidth=2)
    ax1.plot([0, 1], [0, 1], "k--", alpha=0.5)
    ax1.set_title("ROC Curve Comparison Across Prioritization Models")
    ax1.set_xlabel("False Positive Rate")
    ax1.set_ylabel("True Positive Rate (Recall)")
    ax1.legend(loc="lower right", fontsize=8)
    ax1.grid(True, alpha=0.3)

    # Plot 2: F1-Score vs False Positive Rate
    x = np.arange(len(names))
    width = 0.35
    ax2.bar(x - width/2, f1_scores, width, label="F1-Score (Higher is Better)", color="#2b5c8f")
    ax2.bar(x + width/2, fpr_scores, width, label="False Positive Rate (Lower is Better)", color="#d9534f")
    ax2.set_title("F1-Score & False Positive Reduction")
    ax2.set_xticks(x)
    ax2.set_xticklabels(names, rotation=15)
    ax2.set_ylim(0, 1.1)
    ax2.legend(fontsize=8)
    ax2.grid(True, axis="y", alpha=0.3)

    plt.tight_layout()
    plt.savefig("paper_figures.png", dpi=300)
    print("\nSaved high-resolution charts to 'paper_figures.png'.")

if __name__ == "__main__":
    main()