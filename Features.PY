"""
features.py

Feature engineering for elder account activity logs (bank / online account
access logs). Designed to surface behavioral patterns associated with elder
financial exploitation: account takeover, romance and grandparent scams,
tech support scams, and phishing enabled credential resets.

Expected input columns:
    timestamp, account_id, age_group, event_type, device_id,
    source_ip, amount, status

event_type values expected: login, login_failed, password_reset,
    contact_change, add_payee, transfer
"""

import pandas as pd
import numpy as np

REQUIRED_COLUMNS = [
    "timestamp", "account_id", "age_group", "event_type",
    "device_id", "source_ip", "amount", "status",
]

SENSITIVE_EVENTS = {"password_reset", "contact_change", "add_payee", "transfer"}


def load_data(path: str) -> pd.DataFrame:
    """Load an account activity log CSV and parse timestamps."""
    df = pd.read_csv(path)

    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Input file is missing required columns: {missing}")

    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["amount"] = pd.to_numeric(df["amount"], errors="coerce").fillna(0)
    df = df.sort_values(["account_id", "timestamp"]).reset_index(drop=True)
    return df


def engineer_features(df: pd.DataFrame, off_hours_start: int = 22, off_hours_end: int = 6,
                       sequence_window_minutes: int = 30) -> pd.DataFrame:
    """
    Build a row-level feature matrix from raw account activity logs.

    Features:
        hour                     - hour of day the event occurred
        is_off_hours             - 1 if event occurred outside normal hours
        new_device               - 1 if this device_id has not been seen for
                                    this account before
        new_source_ip            - 1 if this source_ip has not been seen for
                                    this account before
        is_sensitive_event       - 1 if event is password_reset, contact_change,
                                    add_payee, or transfer
        contact_change_then_transfer - 1 if a contact_change occurred for this
                                    account within the lookback window before
                                    this transfer (classic scam sequence)
        new_payee_then_transfer  - 1 if an add_payee occurred for this account
                                    within the lookback window before this
                                    transfer
        rapid_sensitive_actions  - count of sensitive events for this account
                                    within the lookback window (rapid succession
                                    is a strong scam-in-progress signal)
        amount_vs_history_ratio  - this transfer amount divided by the account's
                                    average prior transfer amount (large ratios
                                    flag transfers well outside normal behavior)
        login_fail_rate_recent   - fraction of this account's last 10 login
                                    attempts that failed (credential stuffing /
                                    takeover signal)

    Returns the original dataframe with feature columns appended.
    """
    df = df.copy()
    window = pd.Timedelta(minutes=sequence_window_minutes)

    df["hour"] = df["timestamp"].dt.hour
    df["is_off_hours"] = (
        (df["hour"] >= off_hours_start) | (df["hour"] < off_hours_end)
    ).astype(int)

    df["is_sensitive_event"] = df["event_type"].isin(SENSITIVE_EVENTS).astype(int)

    is_fail = df["status"].astype(str).str.lower().isin(["fail", "failure", "failed"]).astype(int)
    df["_is_fail"] = is_fail
    is_login_attempt = df["event_type"].isin(["login", "login_failed"]).astype(int)
    df["_is_login"] = is_login_attempt

    def _recent_login_fail_rate(group_df: pd.DataFrame) -> pd.Series:
        login_mask = group_df["_is_login"] == 1
        fails = group_df["_is_fail"].where(login_mask)
        return fails.rolling(window=10, min_periods=1).mean().ffill().fillna(0)

    df["login_fail_rate_recent"] = (
        df.groupby("account_id", group_keys=False).apply(_recent_login_fail_rate)
    )

    new_device_flags, new_ip_flags = [], []
    seen_devices, seen_ips = set(), set()
    for account, device, ip in zip(df["account_id"], df["device_id"], df["source_ip"]):
        dkey, ikey = (account, device), (account, ip)
        new_device_flags.append(0 if dkey in seen_devices else 1)
        new_ip_flags.append(0 if ikey in seen_ips else 1)
        seen_devices.add(dkey)
        seen_ips.add(ikey)
    df["new_device"] = new_device_flags
    df["new_source_ip"] = new_ip_flags

    contact_change_flags, new_payee_flags, rapid_counts = [], [], []
    amount_ratio = []
    per_account_history = {}

    for idx, row in df.iterrows():
        acct = row["account_id"]
        ts = row["timestamp"]
        etype = row["event_type"]
        history = per_account_history.setdefault(acct, {
            "events": [], "transfer_amounts": [],
        })

        recent = [e for e in history["events"] if ts - e["timestamp"] <= window]

        contact_change_flags.append(
            int(etype == "transfer" and any(e["event_type"] == "contact_change" for e in recent))
        )
        new_payee_flags.append(
            int(etype == "transfer" and any(e["event_type"] == "add_payee" for e in recent))
        )
        rapid_counts.append(sum(1 for e in recent if e["event_type"] in SENSITIVE_EVENTS))

        if etype == "transfer":
            prior_amounts = history["transfer_amounts"]
            avg_prior = np.mean(prior_amounts) if prior_amounts else row["amount"] or 1
            avg_prior = avg_prior if avg_prior > 0 else 1
            amount_ratio.append(row["amount"] / avg_prior)
            history["transfer_amounts"].append(row["amount"])
        else:
            amount_ratio.append(0.0)

        history["events"].append({"timestamp": ts, "event_type": etype})

    df["contact_change_then_transfer"] = contact_change_flags
    df["new_payee_then_transfer"] = new_payee_flags
    df["rapid_sensitive_actions"] = rapid_counts
    df["amount_vs_history_ratio"] = amount_ratio

    df = df.drop(columns=["_is_fail", "_is_login"])
    return df


FEATURE_COLUMNS = [
    "hour",
    "is_off_hours",
    "new_device",
    "new_source_ip",
    "is_sensitive_event",
    "contact_change_then_transfer",
    "new_payee_then_transfer",
    "rapid_sensitive_actions",
    "amount_vs_history_ratio",
    "login_fail_rate_recent",
]


def get_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """Return just the numeric feature columns used for model input."""
    return df[FEATURE_COLUMNS]
