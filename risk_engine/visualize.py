import json
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt

FINDINGS_DIR = Path("findings")

REPORT_FILE = FINDINGS_DIR / "risk_report.json"


def load_data():
    with open(REPORT_FILE) as f:
        data = json.load(f)

    findings = data["all_findings"]

    df = pd.DataFrame(findings)

    return df


def plot_risk_distribution(df):

    plt.figure()

    df["risk_score"].hist(bins=20)

    plt.title("Risk Score Distribution")
    plt.xlabel("Risk Score")
    plt.ylabel("Number of Findings")

    plt.savefig(FINDINGS_DIR / "risk_distribution.png")

    print("Saved risk_distribution.png")


def plot_top_assets(df):

    asset_risk = df.groupby("asset")["risk_score"].max().sort_values(ascending=False).head(10)

    plt.figure()

    asset_risk.plot(kind="bar")

    plt.title("Top Risky Assets")
    plt.ylabel("Max Risk Score")

    plt.xticks(rotation=45)

    plt.tight_layout()

    plt.savefig(FINDINGS_DIR / "top_risky_assets.png")

    print("Saved top_risky_assets.png")


def plot_tool_contribution(df):

    tool_counts = df["tool"].value_counts()

    plt.figure()

    tool_counts.plot(kind="bar")

    plt.title("Findings by Security Tool")

    plt.ylabel("Number of Findings")

    plt.savefig(FINDINGS_DIR / "tool_contribution.png")

    print("Saved tool_contribution.png")


def main():

    df = load_data()

    plot_risk_distribution(df)

    plot_top_assets(df)

    plot_tool_contribution(df)


if __name__ == "__main__":
    main()
