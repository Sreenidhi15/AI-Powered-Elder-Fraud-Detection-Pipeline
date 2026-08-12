"""
fraud_typology.py

Maps flagged, feature-engineered account events to elder fraud typologies
recognized by bank fraud teams and Adult Protective Services caseworkers.
This is the elder fraud domain analogue of a MITRE ATT&CK mapping layer:
instead of adversary techniques, it labels consumer-facing scam patterns.
"""

import pandas as pd

TYPOLOGIES = {
    "ACCOUNT_TAKEOVER": {
        "name": "Account Takeover",
        "description": "Credential stuffing or stolen-credential access from a new device or IP",
    },
    "ROMANCE_GRANDPARENT_SCAM": {
        "name": "Romance / Grandparent Scam Transfer",
        "description": "A new payee added shortly before an unusually large transfer",
    },
    "TECH_SUPPORT_SCAM": {
        "name": "Tech Support Scam Remote Access Change",
        "description": "Off-hours sensitive account changes in rapid succession, consistent with a scammer walking a victim through account changes over the phone",
    },
    "PHISHING_CREDENTIAL_RESET": {
        "name": "Phishing-Enabled Credential Reset",
        "description": "A contact information change followed shortly by a large transfer, consistent with a scammer rerouting account recovery before draining funds",
    },
}


def classify_row(row: pd.Series) -> list:
    """Return a list of typology keys that apply to a single flagged row."""
    matches = []

    if row.get("login_fail_rate_recent", 0) > 0.3 and row.get("new_device", 0) == 1:
        matches.append("ACCOUNT_TAKEOVER")

    if row.get("new_payee_then_transfer", 0) == 1 and row.get("amount_vs_history_ratio", 0) > 3:
        matches.append("ROMANCE_GRANDPARENT_SCAM")

    if row.get("is_off_hours", 0) == 1 and row.get("rapid_sensitive_actions", 0) >= 2:
        matches.append("TECH_SUPPORT_SCAM")

    if row.get("contact_change_then_transfer", 0) == 1:
        matches.append("PHISHING_CREDENTIAL_RESET")

    return matches


def annotate(df: pd.DataFrame) -> pd.DataFrame:
    """Add a fraud_typologies column listing matched typology names for each row."""
    df = df.copy()
    df["fraud_typologies"] = df.apply(
        lambda r: ", ".join(TYPOLOGIES[k]["name"] for k in classify_row(r)) or "Unclassified",
        axis=1,
    )
    return df
