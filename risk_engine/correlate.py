import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone

FINDINGS_DIR = Path("findings")


def correlation_key(finding):
    """
    Generate correlation key for grouping related findings.
    """
    return (
        finding.get("id"),
        finding.get("asset"),
        finding.get("issue_type")
    )


def correlate_findings(findings):

    groups = defaultdict(list)

    for f in findings:
        key = correlation_key(f)
        groups[key].append(f)

    merged = []

    for key, items in groups.items():

        if len(items) == 1:
            merged.append(items[0])
            continue

        # Merge correlated findings
        base = dict(items[0])

        tools = {i["tool"] for i in items}

        base["metadata"] = base.get("metadata", {})
        base["metadata"]["correlated_tools"] = list(tools)
        base["metadata"]["correlation_count"] = len(items)

        # Increase severity slightly if multiple tools detected it
        base["severity"] = min(base["severity"] + 1, 9)

        base["metadata"]["correlation_boost"] = True

        merged.append(base)

    return merged


def main():

    input_path = FINDINGS_DIR / "normalized_findings.json"

    if not input_path.exists():
        raise FileNotFoundError("normalized_findings.json not found")

    findings = json.load(open(input_path))

    print(f"Original findings: {len(findings)}")

    correlated = correlate_findings(findings)

    output_path = FINDINGS_DIR / "correlated_findings.json"

    json.dump(correlated, open(output_path, "w"), indent=2)

    print(f"After correlation: {len(correlated)}")

    reduction = len(findings) - len(correlated)

    print(f"Duplicate reduction: {reduction}")
    print(f"Saved: {output_path}")


if __name__ == "__main__":
    main()
