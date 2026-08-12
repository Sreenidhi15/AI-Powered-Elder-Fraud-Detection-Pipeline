"""
generate_sample_data.py

Generates a synthetic elder account activity log for testing the fraud
detection pipeline. Produces mostly normal account activity, plus a handful
of injected scam patterns: account takeover, romance/grandparent scam,
tech support scam, and phishing-enabled credential reset.

Usage:
    python generate_sample_data.py --output logs/sample.csv --n-accounts 25
"""

import argparse
import os
import uuid

import numpy as np
import pandas as pd


def _fake_device_id() -> str:
    return f"device-{uuid.uuid4().hex[:8]}"


def _fake_public_ip() -> str:
    return f"{np.random.randint(20, 223)}.{np.random.randint(0, 255)}.{np.random.randint(0, 255)}.{np.random.randint(1, 254)}"


def generate_normal_activity(accounts: list, n_events: int, start: pd.Timestamp) -> list:
    rows = []
    devices = {acct: f"device-{uuid.uuid4().hex[:8]}" for acct in accounts}
    ips = {acct: f"192.168.1.{np.random.randint(2, 50)}" for acct in accounts}

    for _ in range(n_events):
        acct = np.random.choice(accounts)
        ts = start + pd.Timedelta(
            hours=np.random.randint(8, 20),
            minutes=np.random.randint(0, 60),
            days=np.random.randint(0, 30),
        )
        event_type = np.random.choice(
            ["login", "login", "login", "transfer"], p=[0.5, 0.25, 0.15, 0.10]
        )
        amount = round(np.random.uniform(20, 300), 2) if event_type == "transfer" else 0.0

        rows.append({
            "timestamp": ts,
            "account_id": acct,
            "age_group": "65+",
            "event_type": event_type,
            "device_id": devices[acct],
            "source_ip": ips[acct],
            "amount": amount,
            "status": "success",
        })
    return rows


def inject_account_takeover(account: str, start: pd.Timestamp) -> list:
    rows = []
    for i in range(8):
        rows.append({
            "timestamp": start + pd.Timedelta(seconds=i * 20),
            "account_id": account,
            "age_group": "65+",
            "event_type": "login_failed",
            "device_id": f"device-{uuid.uuid4().hex[:8]}",
            "source_ip": _fake_public_ip(),
            "amount": 0.0,
            "status": "failure",
        })
    rows.append({
        "timestamp": start + pd.Timedelta(seconds=200),
        "account_id": account,
        "age_group": "65+",
        "event_type": "login",
        "device_id": f"device-{uuid.uuid4().hex[:8]}",
        "source_ip": _fake_public_ip(),
        "amount": 0.0,
        "status": "success",
    })
    return rows


def inject_romance_scam(account: str, start: pd.Timestamp) -> list:
    return [
        {
            "timestamp": start,
            "account_id": account, "age_group": "65+", "event_type": "add_payee",
            "device_id": "device-known", "source_ip": "192.168.1.10",
            "amount": 0.0, "status": "success",
        },
        {
            "timestamp": start + pd.Timedelta(minutes=10),
            "account_id": account, "age_group": "65+", "event_type": "transfer",
            "device_id": "device-known", "source_ip": "192.168.1.10",
            "amount": 4800.00, "status": "success",
        },
    ]


def inject_tech_support_scam(account: str, start: pd.Timestamp) -> list:
    rows = []
    events = ["password_reset", "contact_change", "add_payee", "transfer"]
    for i, etype in enumerate(events):
        rows.append({
            "timestamp": start + pd.Timedelta(minutes=i * 5),
            "account_id": account, "age_group": "65+", "event_type": etype,
            "device_id": "device-known", "source_ip": "192.168.1.10",
            "amount": 1200.00 if etype == "transfer" else 0.0,
            "status": "success",
        })
    return rows


def inject_phishing_reset(account: str, start: pd.Timestamp) -> list:
    return [
        {
            "timestamp": start,
            "account_id": account, "age_group": "65+", "event_type": "contact_change",
            "device_id": f"device-{uuid.uuid4().hex[:8]}", "source_ip": _fake_public_ip(),
            "amount": 0.0, "status": "success",
        },
        {
            "timestamp": start + pd.Timedelta(minutes=15),
            "account_id": account, "age_group": "65+", "event_type": "transfer",
            "device_id": f"device-{uuid.uuid4().hex[:8]}", "source_ip": _fake_public_ip(),
            "amount": 3500.00, "status": "success",
        },
    ]


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic elder account activity logs")
    parser.add_argument("--output", default="logs/sample.csv")
    parser.add_argument("--n-accounts", type=int, default=25)
    parser.add_argument("--n-events", type=int, default=400)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    np.random.seed(args.seed)

    accounts = [f"acct-{i:03d}" for i in range(args.n_accounts)]
    start = pd.Timestamp("2026-06-01")

    rows = generate_normal_activity(accounts, args.n_events, start)
    rows += inject_account_takeover(accounts[0], pd.Timestamp("2026-06-15 03:00:00"))
    rows += inject_romance_scam(accounts[1], pd.Timestamp("2026-06-18 14:00:00"))
    rows += inject_tech_support_scam(accounts[2], pd.Timestamp("2026-06-20 23:30:00"))
    rows += inject_phishing_reset(accounts[3], pd.Timestamp("2026-06-22 11:00:00"))

    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    df.to_csv(args.output, index=False)
    print(f"Generated {len(df)} events across {args.n_accounts} accounts -> {args.output}")
    print("Injected scam patterns: account takeover, romance scam, tech support scam, phishing reset")


if __name__ == "__main__":
    main()
