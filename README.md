# SessionSentry — Web Session Security Analyzer

**Day 20/100 · 100 Days • 100 Cybersecurity Projects**

SessionSentry is an offline-first defensive tool for reviewing supplied web-session configuration evidence. It checks cookie attributes and session lifecycle settings, explains findings, and exports JSON/CSV reports.

> It analyzes only the configuration file you provide. It does not connect to websites, collect credentials, hijack sessions, or prove live exploitability.

## Features
- Checks Secure, HttpOnly, and SameSite cookie attributes.
- Reviews session-ID rotation, logout invalidation, and timeouts.
- Transparent heuristic risk score and remediation guidance.
- JSON and CSV report export.
- Unit tests and GitHub Actions CI.

## Requirements
Python 3.10+ (standard library only).

## Run
```powershell
python sessionsentry.py examples/sample_assessment.json --json reports/findings.json --csv reports/findings.csv
python -m unittest discover -s tests -v
```

The score is a prioritization aid, not exploit probability or a compliance certification. Use only on systems you own or are authorized to assess.
