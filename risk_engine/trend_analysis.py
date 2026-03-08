import json
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import os

FINDINGS_DIR = Path("findings")

RISK_REPORT = FINDINGS_DIR / "risk_report.json"
HISTORY_FILE = FINDINGS_DIR / "risk_history.json"


def load_current_risk():

    if not RISK_REPORT.exists():
        raise FileNotFoundError("risk_report.json not found")

    with open(RISK_REPORT) as f:
        data = json.load(f)

    scores = [f["risk_score"] for f in data["all_findings"]]

    if not scores:
        return 0

    avg_risk = sum(scores) / len(scores)

    return round(avg_risk, 3)


def load_history():

    if not HISTORY_FILE.exists():
        return []

    with open(HISTORY_FILE) as f:
        return json.load(f)


def save_history(history):

    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)


def update_history(avg_risk):

    history = load_history()

    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "commit": os.getenv("GITHUB_SHA", "local"),
        "avg_risk": avg_risk
    }

    history.append(entry)

    save_history(history)

    return history


def generate_trend_plot(history):

    df = pd.DataFrame(history)

    if df.empty:
        return

    plt.figure()

    plt.plot(df["avg_risk"], marker="o")

    plt.title("Security Risk Trend Across Commits")
    plt.xlabel("Pipeline Run")
    plt.ylabel("Average Risk Score")

    plt.grid(True)

    plt.savefig(FINDINGS_DIR / "security_trend.png")

    print("Saved security_trend.png")


def main():

    avg_risk = load_current_risk()

    print("Current average risk:", avg_risk)

    history = update_history(avg_risk)

    generate_trend_plot(history)


if __name__ == "__main__":
    main()
