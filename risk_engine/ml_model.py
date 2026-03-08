import json
from pathlib import Path
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder

FINDINGS_DIR = Path("findings")

INPUT_FILE = FINDINGS_DIR / "risk_report.json"
OUTPUT_FILE = FINDINGS_DIR / "ml_risk_predictions.json"


def load_data():

    if not INPUT_FILE.exists():
        raise FileNotFoundError("risk_report.json not found")

    report = json.load(open(INPUT_FILE))

    findings = report["all_findings"]

    rows = []

    for f in findings:

        explanation = f.get("explanation", {})
        features = explanation.get("feature_values", {})

        rows.append({
            "severity": features.get("severity_norm", 0),
            "confidence": features.get("confidence", 0),
            "freshness": features.get("freshness_norm", 0),
            "exposure": features.get("exposure", "unknown"),
            "criticality": features.get("criticality", "unknown"),
            "stage": features.get("stage", "unknown"),
            "risk_score": f.get("risk_score", 0),
            "tool": f.get("tool")
        })

    df = pd.DataFrame(rows)

    return df


def preprocess(df):

    encoders = {}

    for col in ["exposure", "criticality", "stage", "tool"]:

        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])

        encoders[col] = le

    return df


def create_target(df):

    # label high risk findings
    df["high_risk"] = df["risk_score"].apply(lambda x: 1 if x >= 0.55 else 0)

    return df


def train_model(df):

    X = df.drop(columns=["risk_score", "high_risk"])
    y = df["high_risk"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.3,
        random_state=42
    )

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=6,
        random_state=42
    )

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("\nML Model Evaluation\n")
    print(classification_report(y_test, predictions))

    return model, X


def predict(model, X, df):

    probs = model.predict_proba(X)

    # If model trained with only one class
    if probs.shape[1] == 1:
        print("⚠ Only one class detected in training data")
        print("Using rule-based fallback probabilities")

        df["ml_risk_probability"] = df["risk_score"]

    else:
        df["ml_risk_probability"] = probs[:, 1]

    return df

def save_results(df):

    results = df.to_dict(orient="records")

    json.dump(results, open(OUTPUT_FILE, "w"), indent=2)

    print(f"\nSaved ML predictions to {OUTPUT_FILE}")


def main():

    print("\nLoading risk report...\n")

    df = load_data()

    df = preprocess(df)

    df = create_target(df)

    model, X = train_model(df)

    df = predict(model, X, df)

    save_results(df)


if __name__ == "__main__":
    main()
