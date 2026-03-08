import json
from datetime import datetime, timezone
from pathlib import Path

FINDINGS_DIR = Path("findings")


# ==============================
# SEVERITY NORMALIZATION
# ==============================

def severity_to_score(severity):
    mapping = {
        "CRITICAL": 9,
        "HIGH": 7,
        "MEDIUM": 5,
        "LOW": 3,
        "INFO": 1
    }

    if not severity:
        return 1

    return mapping.get(str(severity).upper(), 1)


# ==============================
# SEMGREP NORMALIZATION
# ==============================

def normalize_semgrep():

    path = FINDINGS_DIR / "semgrep.json"
    if not path.exists():
        return []

    with open(path) as f:
        data = json.load(f)

    results = []

    for item in data.get("results", []):

        results.append({
            "tool": "semgrep",
            "stage": "SAST",
            "asset": item.get("path"),
            "issue_type": item.get("check_id"),
            "id": item.get("check_id"),
            "severity": severity_to_score(
                item.get("extra", {}).get("severity")
            ),
            "evidence": item.get("extra", {}).get("message"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": {}
        })

    return results


# ==============================
# TRIVY NORMALIZATION
# ==============================

def normalize_trivy():

    path = FINDINGS_DIR / "trivy.json"
    if not path.exists():
        return []

    with open(path) as f:
        data = json.load(f)

    results = []

    for result in data.get("Results", []):

        for vuln in result.get("Vulnerabilities", []) or []:

            results.append({
                "tool": "trivy",
                "stage": "SCA",
                "asset": result.get("Target"),
                "issue_type": "CVE",
                "id": vuln.get("VulnerabilityID"),
                "severity": severity_to_score(
                    vuln.get("Severity")
                ),
                "evidence": vuln.get("Title"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metadata": {}
            })

    return results


# ==============================
# CHECKOV NORMALIZATION
# ==============================

def parse_checkov_file(file_name):

    path = FINDINGS_DIR / file_name

    if not path.exists():
        return []

    with open(path) as f:
        data = json.load(f)

    results = []

    # Some Checkov outputs return list
    if isinstance(data, list):

        for entry in data:
            failed = entry.get("results", {}).get("failed_checks", [])

            for check in failed:

                results.append({
                    "tool": "checkov",
                    "stage": "IaC",
                    "asset": check.get("file_path"),
                    "issue_type": check.get("check_name"),
                    "id": check.get("check_id"),
                    "severity": severity_to_score(
                        check.get("severity")
                    ),
                    "evidence": check.get("description")
                    or check.get("guideline"),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "metadata": {
                        "resource": check.get("resource"),
                        "file_line_range": check.get("file_line_range")
                    }
                })

    # Some outputs return dict
    elif isinstance(data, dict):

        failed = data.get("results", {}).get("failed_checks", [])

        for check in failed:

            results.append({
                "tool": "checkov",
                "stage": "IaC",
                "asset": check.get("file_path"),
                "issue_type": check.get("check_name"),
                "id": check.get("check_id"),
                "severity": severity_to_score(
                    check.get("severity")
                ),
                "evidence": check.get("description")
                or check.get("guideline"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metadata": {
                    "resource": check.get("resource"),
                    "file_line_range": check.get("file_line_range")
                }
            })

    return results


def normalize_checkov():

    results = []

    # existing checkov scan
    results.extend(parse_checkov_file("checkov.json"))

    # terraform checkov scan
    results.extend(parse_checkov_file("terraform_checkov.json"))

    return results


# ==============================
# MAIN NORMALIZATION PIPELINE
# ==============================

def main():

    all_findings = []

    all_findings.extend(normalize_semgrep())
    all_findings.extend(normalize_trivy())
    all_findings.extend(normalize_checkov())

    output_path = FINDINGS_DIR / "normalized_findings.json"

    with open(output_path, "w") as f:
        json.dump(all_findings, f, indent=2)

    print(f"\nNormalized {len(all_findings)} findings.")
    print(f"Output saved to {output_path}\n")


if __name__ == "__main__":
    main()