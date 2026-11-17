import json
import os
import re
from dataclasses import dataclass, asdict
from typing import List

@dataclass
class UnifiedVulnerability:
    id: str
    tool: str           # SAST (Semgrep), SCA (Trivy), DAST (OWASP ZAP)
    title: str
    cwe: str
    location: str
    raw_severity: str   # Tool's original severity
    baseline_score: float
    intelligent_score: float
    is_false_positive_noise: bool
    reasoning: str

class SecurityAggregatorAndPrioritizer:
    def __init__(self):
        self.findings: List[UnifiedVulnerability] = []

    def parse_semgrep(self, filepath: str):
        if not os.path.exists(filepath):
            return
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        for idx, res in enumerate(data.get("results", []), 1):
            meta = res.get("extra", {}).get("metadata", {})
            cwe_list = meta.get("cwe", ["Unknown"])
            cwe = cwe_list[0].split(":")[0] if cwe_list else "Unknown"
            sev = res.get("extra", {}).get("severity", "WARNING")
            
            # Baseline mapping
            base_score = 85.0 if sev == "ERROR" else 50.0
            
            self.findings.append(UnifiedVulnerability(
                id=f"SAST-{idx}",
                tool="Semgrep (SAST)",
                title=res.get("check_id", "").split(".")[-1],
                cwe=cwe,
                location=f"{res.get('path')}:{res.get('start', {}).get('line')}",
                raw_severity=sev,
                baseline_score=base_score,
                intelligent_score=0.0,
                is_false_positive_noise=False,
                reasoning=""
            ))

    def parse_zap(self, filepath: str):
        if not os.path.exists(filepath):
            return
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        counter = 1
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                risk_code = int(alert.get("riskcode", 0))
                sev_map = {3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFO"}
                raw_sev = sev_map.get(risk_code, "INFO")
                base_score = {3: 80.0, 2: 55.0, 1: 30.0, 0: 10.0}.get(risk_code, 10.0)
                cwe = f"CWE-{alert.get('cweid', 'Unknown')}"

                for inst in alert.get("instances", []):
                    self.findings.append(UnifiedVulnerability(
                        id=f"DAST-{counter}",
                        tool="OWASP ZAP (DAST)",
                        title=alert.get("alert", "Unknown Alert"),
                        cwe=cwe,
                        location=inst.get("uri", ""),
                        raw_severity=raw_sev,
                        baseline_score=base_score,
                        intelligent_score=0.0,
                        is_false_positive_noise=False,
                        reasoning=""
                    ))
                    counter += 1

    def apply_intelligent_prioritization(self):
        """
        Proposed Method: Context-aware risk scoring & False-Positive suppression.
        Evaluates exploitability, endpoint sensitivity, and static asset noise.
        """
        high_impact_cwes = {"CWE-89", "CWE-79", "CWE-78", "CWE-284", "CWE-639"}
        static_noise_patterns = [r"\.png$", r"\.css$", r"\.js$", r"/swagger/", r"/robots\.txt", r"/sitemap\.xml"]

        for item in self.findings:
            score = item.baseline_score
            reasons = []

            # Rule 1: Suppress static asset / documentation UI noise (False Positives in API context)
            if any(re.search(pat, item.location, re.IGNORECASE) for pat in static_noise_patterns):
                score *= 0.15
                item.is_false_positive_noise = True
                reasons.append("Static/Swagger UI asset; non-exploitable API noise (-85%)")

            # Rule 2: Boost critical injection / access control vulnerabilities in active API routes
            if item.cwe in high_impact_cwes:
                score = min(100.0, score + 13.0)
                reasons.append(f"Critical exploitability class ({item.cwe}) (+13)")

            # Rule 3: Context check on API endpoints
            if "/api/" in item.location and not item.is_false_positive_noise:
                score = min(100.0, score + 10.0)
                reasons.append("Exposed production API route (+10)")

            # Rule 4: Informational / Missing security headers on JSON APIs
            if item.raw_severity in ["INFO", "LOW"] and not item.is_false_positive_noise:
                score *= 0.5
                item.is_false_positive_noise = True
                reasons.append("Low-impact header/informational alert (-50%)")

            item.intelligent_score = round(score, 2)
            item.reasoning = "; ".join(reasons) if reasons else "Standard baseline risk"

    def run(self):
        self.parse_semgrep("semgrep-report.json")
        self.parse_zap("zap-report.json")
        self.apply_intelligent_prioritization()

        # Sort by Intelligent Score descending
        ranked = sorted(self.findings, key=lambda x: x.intelligent_score, reverse=True)

        total = len(ranked)
        suppressed = sum(1 for x in ranked if x.is_false_positive_noise)
        actionable = total - suppressed

        print(f"=== CONTINUOUS SECURITY PRIORITIZATION REPORT ===")
        print(f"Total Raw Findings (Baseline) : {total}")
        print(f"Suppressed Noise / FP         : {suppressed} ({(suppressed/total)*100:.1f}% reduction)")
        print(f"Actionable Critical Findings  : {actionable}\n")

        print("--- TOP PRIORITIZED VULNERABILITIES ---")
        for item in ranked[:5]:
            print(f"[{item.intelligent_score:5.1f} pts | Base: {item.baseline_score:4.1f}] {item.tool} -> {item.title} ({item.cwe})")
            print(f"    Location : {item.location}")
            print(f"    Analysis : {item.reasoning}\n")

        with open("prioritized-results.json", "w", encoding="utf-8") as out:
            json.dump([asdict(x) for x in ranked], out, indent=2)

if __name__ == "__main__":
    engine = SecurityAggregatorAndPrioritizer()
    engine.run()