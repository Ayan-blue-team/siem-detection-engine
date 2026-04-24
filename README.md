# Siem-detection-engine

A centralized, version-controlled repository for high-fidelity detection rules. Automated deployment of MITRE ATT&CK® aligned content for Splunk (SPL) and IBM QRadar (AQL) using CI/CD pipelines.

---

# Detection-as-Code (DaC) Framework

This repository serves as a centralized hub for **Detection Engineering**. It hosts a library of professional-grade detection rules designed to identify advanced adversary behaviors (TTPs) within enterprise environments.

## Architecture & Workflow

The lifecycle of a detection rule in this environment follows the **Detection-as-Code** principles:

1. **Develop** — Rules are written in YAML (Sigma) or native SIEM languages (SPL/AQL).
2. **Version** — Every change is tracked via GitHub Commits and Pull Requests.
3. **Validate** — CI/CD checks for syntax and logic errors via `deploy_rules.yml`.
4. **Deploy** — Automated push to Splunk/QRadar via REST APIs using `siem_api_sync.py`.

## Coverage & Mapping

All detections are mapped to the **MITRE ATT&CK Framework** to ensure comprehensive visibility across the attack lifecycle.

| Tactic | Rules |
|---|---|
| Credential Access | 5 |
| Privilege Escalation | 4 |
| Persistence | 4 |
| Defense Evasion | 4 |
| Execution | 3 |
| Discovery | 3 |
| Lateral Movement | 2 |
| Exfiltration | 1 |
| Command & Control | 1 |
| Impact | 1 |

---

# Splunk (15 Rules)

- **Log Sources:** WinEventLog (Security, System), Sysmon, Network Traffic
- **Focus:** Privilege Escalation, Credential Access, Defense Evasion
- **Language:** SPL (Search Processing Language)

| Rule | Tactic | Severity |
|---|---|---|
| BloodHoundLDAPRecon | Credential Access | Critical |
| DCSyncAttack | Credential Access | Critical |
| DLLHijacking | Defense Evasion | High |
| Kerberoasting | Credential Access | Critical |
| LOLbinsabuse | Execution | High |
| PowerShellEncodedCommand | Execution | High |
| PrivilegedAccountOff-HoursLogin | Privilege Escalation | High |
| RansomwareBehavior | Impact | Critical |
| ScheduledTaskAbuse | Persistence | High |
| SuspiciousOutboundConnection | Command & Control | High |
| WMIPersistence | Persistence | High |
| WebShellDetection | Persistence | Critical |
| dnstunneling | Exfiltration | High |
| lsass | Credential Access | Critical |
| pass-the-hash | Lateral Movement | Critical |

---

# IBM QRadar (12 Rules)

- **Log Sources:** Windows Security Events, Sysmon, Network Flow, DNS Logs
- **Focus:** Lateral Movement, Credential Access, Network Anomalies
- **Language:** AQL (Ariel Query Language)

---

# Repository Structure

```
siem-detection-engine/
├── .github/workflows/
│   └── deploy_rules.yml        # CI/CD — syntax check + automated API push
├── splunk/
│   ├── security/               # High-severity SPL alerts (15 rules)
│   │   ├── BloodHoundLDAPRecon.spl
│   │   ├── DCSyncAttack.spl
│   │   ├── DLLHijacking.spl
│   │   ├── Kerberoasting.spl
│   │   ├── LOLbinsabuse.spl
│   │   ├── PowerShellEncodedCommand.spl
│   │   ├── PrivilegedAccountOff-HoursLogin.spl
│   │   ├── RansomwareBehavior.spl
│   │   ├── ScheduledTaskAbuse.spl
│   │   ├── SuspiciousOutboundConnection.spl
│   │   ├── WMIPersistence.spl
│   │   ├── WebShellDetection.spl
│   │   ├── dnstunneling.spl
│   │   ├── lsass.spl
│   │   └── pass-the-hash.spl
│   └── audit/                  # Compliance-related rules
├── qradar/
│   └── security/               # AQL rules (12 rules)
├── sigma/                      # Vendor-neutral Sigma YAML sources
│   └── *.yml
└── scripts/
    └── siem_api_sync.py        # Python engine for SIEM REST API integration
```

---

# CI/CD Pipeline

The `deploy_rules.yml` GitHub Actions workflow:

1. Triggers on push to `main` or `staging` branch
2. Validates SPL/AQL syntax
3. Runs logic checks against test datasets
4. On success — pushes rules to Splunk and QRadar via REST API

---

# Getting Started

```bash
# Clone the repository
git clone https://github.com/Ayan-blue-team/siem-detection-engine.git

# Install Python dependencies
pip install -r requirements.txt

# Run the API sync manually
python scripts/siem_api_sync.py --target splunk --env prod
```

---

# Contributing

1. Create a feature branch: `git checkout -b detection/new-rule-name`
2. Write the rule in SPL or Sigma YAML
3. Map it to a MITRE ATT&CK technique in the rule header
4. Open a Pull Request — CI will validate automatically
