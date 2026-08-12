"""
detect_fraud.py

Trains an Isolation Forest on engineered elder account activity features,
flags statistically anomalous events, classifies flagged events against
known elder fraud typologies, and can export SOAR-ready JSON alerts for
bank fraud teams or Adult Protective Services caseworkers.

Usage:
    python detect_fraud.py --input logs/sample.csv
    python detect_fraud.py --input logs/sample.csv --output results/scored.csv --json alerts.json
"""

import argparse
import json
import os

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from features import load_data, engineer_features, get_feature_matrix
from fraud_typology import annotate


def run_detection(input_path: str, contamination: float = 0.05, random_state: int = 42) -> pd.DataFrame:
    """Load account activity logs, engineer features, and score every event."""
    raw_df = load_data(input_path)
    featured_df = engineer_features(raw_df)
    X = get_feature_matrix(featured_df)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=random_state,
    )
    model.fit(X_scaled)

    featured_df["anomaly_score"] = model.decision_function(X_scaled)
    featured_df["is_anomaly"] = (model.predict(X_scaled) == -1).astype(int)

    result = annotate(featured_df)
    return result.sort_values("anomaly_score")


def summarize(result: pd.DataFrame) -> None:
    total = len(result)
    flagged = int(result["is_anomaly"].sum())
    print(f"Scored {total} events, flagged {flagged} as anomalous ({flagged / total:.1%}).")

    if flagged:
        print("\nTop flagged events:")
        cols = ["timestamp", "account_id", "event_type", "amount", "fraud_typologies", "anomaly_score"]
        cols = [c for c in cols if c in result.columns]
        print(result[result["is_anomaly"] == 1][cols].head(10).to_string(index=False))


def build_json_alerts(result: pd.DataFrame) -> list:
    """Build SOAR-ready alert objects for every flagged event."""
    flagged = result[result["is_anomaly"] == 1]
    alerts = []
    for _, row in flagged.iterrows():
        alerts.append({
            "timestamp": str(row["timestamp"]),
            "account_id": row["account_id"],
            "event_type": row["event_type"],
            "amount": float(row["amount"]),
            "anomaly_score": float(row["anomaly_score"]),
            "fraud_typologies": row["fraud_typologies"],
            "severity": "high" if row["anomaly_score"] < -0.05 else "medium",
            "recommended_action": (
                "Escalate to fraud team for account hold and customer verification call"
                if row["fraud_typologies"] != "Unclassified"
                else "Review for confirmation before escalation"
            ),
        })
    return alerts


def main():
    parser = argparse.ArgumentParser(description="Isolation Forest elder fraud detection pipeline")
    parser.add_argument("--input", required=True, help="Path to input CSV account activity log")
    parser.add_argument("--output", default=None, help="Path to write scored CSV output")
    parser.add_argument("--json", default=None, help="Path to write SOAR-ready JSON alerts")
    parser.add_argument("--contamination", type=float, default=0.05,
                         help="Expected proportion of anomalous events (default: 0.05)")
    args = parser.parse_args()

    result = run_detection(args.input, contamination=args.contamination)
    summarize(result)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        result.to_csv(args.output, index=False)
        print(f"\nFull scored output written to {args.output}")

    if args.json:
        alerts = build_json_alerts(result)
        os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
        with open(args.json, "w") as f:
            json.dump(alerts, f, indent=2)
        print(f"SOAR-ready JSON alerts written to {args.json} ({len(alerts)} alerts)")


if __name__ == "__main__":
    main()
