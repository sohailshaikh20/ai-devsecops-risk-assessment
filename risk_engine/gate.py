import json
import sys
from pathlib import Path

FINDINGS_DIR = Path("findings")

# =====================================================
# RISK THRESHOLDS
# =====================================================

THRESHOLD_FINDING = 0.75
THRESHOLD_ASSET = 0.80
THRESHOLD_IAC = 0.70

# =====================================================
# MAIN SECURITY GATE
# =====================================================

def main():

    report_path = FINDINGS_DIR / "risk_report.json"

    if not report_path.exists():
        print("❌ risk_report.json not found")
        sys.exit(1)

    report = json.load(open(report_path))

    findings = report.get("all_findings", [])
    assets = report.get("assets", [])

    print("\n🔍 Running DevSecOps Risk Gate...\n")

    high_findings = []
    high_iac = []
    high_assets = []

    # =====================================================
    # CHECK INDIVIDUAL FINDINGS
    # =====================================================

    for f in findings:

        score = f.get("risk_score", 0)
        stage = f.get("stage")

        if stage == "IaC" and score >= THRESHOLD_IAC:
            high_iac.append(f)

        if score >= THRESHOLD_FINDING:
            high_findings.append(f)

    # =====================================================
    # CHECK ASSET LEVEL RISK
    # =====================================================

    for a in assets:

        if a.get("max_risk", 0) >= THRESHOLD_ASSET:
            high_assets.append(a)

    # =====================================================
    # DECISION LOGIC
    # =====================================================

    if high_iac:
        print("❌ High Infrastructure Risk Detected\n")

        for f in high_iac[:5]:
            print(
                f"IaC Risk → {f.get('id')} "
                f"| score={f.get('risk_score')} "
                f"| asset={f.get('asset')}"
            )

        sys.exit(1)

    if high_findings:
        print("❌ High Security Risk Findings Detected\n")

        for f in high_findings[:5]:
            print(
                f"Finding → {f.get('id')} "
                f"| score={f.get('risk_score')} "
                f"| tool={f.get('tool')}"
            )

        sys.exit(1)

    if high_assets:
        print("❌ High Risk Asset Detected\n")

        for a in high_assets[:5]:
            print(
                f"Asset → {a.get('asset')} "
                f"| max_risk={a.get('max_risk')}"
            )

        sys.exit(1)

    # =====================================================
    # PASS
    # =====================================================

    print("✅ Risk within acceptable threshold")
    sys.exit(0)


if __name__ == "__main__":
    main()