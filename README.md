# AI-Powered Elder Fraud Detection Pipeline

Detection pipeline for elder financial exploitation, using behavioral anomaly detection to flag account takeover, romance and grandparent scams, tech support scams, and phishing enabled credential resets before funds leave the account.

## Why

Elder financial exploitation costs older adults billions of dollars a year, and most cases go undetected until the money is already gone. Community banks, credit unions, and Adult Protective Services offices rarely have the enterprise fraud tooling that large banks use. This project applies the same class of unsupervised anomaly detection used in enterprise security operations centers to a domain where it can directly protect a vulnerable population.

## What it does

- **Log ingestion** — parses account activity logs (login, password reset, contact change, add payee, transfer)
- **Feature engineering** — new device or IP paired with sensitive actions, contact change followed by a transfer, new payee followed by a transfer, transfer amount relative to account history, rapid succession of sensitive actions, login failure bursts
- **Anomaly detection** — Isolation Forest (scikit-learn) flags statistically anomalous account activity
- **Fraud typology mapping** — classifies flagged events against four recognized elder fraud patterns: account takeover, romance or grandparent scam, tech support scam, phishing enabled credential reset
- **SOAR ready alert output** — structured JSON alerts with severity and recommended action, suitable for a fraud team queue or caseworker review
- **Visualization** — normal versus anomalous activity plotted over time with matplotlib

## Tech stack

scikit-learn, pandas, numpy, matplotlib

## Fraud typology coverage

| Typology | Signal |
|---|---|
| Account Takeover | Login failure burst followed by success from a new device |
| Romance / Grandparent Scam Transfer | New payee added shortly before an unusually large transfer |
| Tech Support Scam Remote Access Change | Off hours, rapid succession of sensitive account changes |
| Phishing-Enabled Credential Reset | Contact info change followed shortly by a large transfer |

## Quick start

```
git clone https://github.com/Sreenidhi15/AI-Powered-Elder-Fraud-Detection-Pipeline
cd AI-Powered-Elder-Fraud-Detection-Pipeline
pip install -r requirements.txt
python generate_sample_data.py --output logs/sample.csv
python detect_fraud.py --input logs/sample.csv --output results/scored.csv --json results/alerts.json
```

## Status

- [x] Project structure and data schema defined
- [x] Sample scam pattern data generator
- [x] Feature engineering pipeline
- [x] Isolation Forest model and scoring
- [x] Fraud typology mapping
- [x] JSON alert output
- [ ] Matplotlib visualization
