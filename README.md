
# log-anomaly-detector

ML-powered Windows Event Log anomaly detection with MITRE ATT&CK mapping and SOAR-ready JSON output

![Status](https://img.shields.io/badge/status-in%20progress-yellow)
![Python](https://img.shields.io/badge/python-3.10+-blue)

> 🚧 **Actively under development.** Core detection pipeline and sample data generator in progress. MITRE mapping and SOAR alert output coming next.

## What it does

- **Log Ingestion** — Parses Windows Event Log and Splunk CSV exports (timestamp, event_id, user, source_ip, process_name, action, status)
- **Feature Engineering** — Login frequency, off-hours access patterns, process execution trends, per-user fail counts
- **Anomaly Detection** — Isolation Forest (scikit-learn) flags statistically anomalous behavioral entries
- **MITRE ATT&CK Mapping** — Maps flagged events to T1110 (brute force), T1059 (scripting), T1021 (lateral movement)
- **SOAR Alert Output** — Structured JSON reports compatible with Splunk SOAR / Palo Alto XSOAR
- **Visualization** — Normal vs anomalous scores plotted over time with matplotlib

## Tech Stack

`scikit-learn` · `pandas` · `numpy` · `matplotlib` · `faker`

## MITRE ATT&CK Coverage

| Technique | Name | Detection Signal |
|---|---|---|
| T1110 | Brute Force | High failed login count, 3am spikes |
| T1059 | Command & Scripting Interpreter | Unusual process execution |
| T1021 | Remote Services | Lateral movement via new source IPs |

## Quick Start
```bash
git clone https://github.com/Sreenidhi15/log-anomaly-detector
cd log-anomaly-detector
pip install -r requirements.txt
python generate_sample_data.py
python detect_anomalies.py --input logs/sample.csv
```

## Status

- [x] Project structure and data schema defined
- [x] Sample attack data generator
- [ ] Feature engineering pipeline
- [ ] Isolation Forest model + scoring
- [ ] MITRE ATT&CK mapping
- [ ] JSON alert output
- [ ] Matplotlib visualization

---
