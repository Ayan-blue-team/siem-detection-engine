# Siem-detection-engine
A centralized, version-controlled repository for high-fidelity detection rules. Automated deployment of MITRE ATT&amp;CK® aligned content for Splunk (SPL) and IBM QRadar (AQL) using CI/CD pipelines.

#  Detection-as-Code (DaC) Framework
This repository serves as a centralized hub for **Detection Engineering**. It hosts a library of professional-grade detection rules designed to identify advanced adversary behaviors (TTPs) within enterprise environments.


#Architecture & Workflow
The lifecycle of a detection rule in this environment follows the **Detection-as-Code** principles:
1. Develop: Rules are written in YAML (Sigma) or native SIEM languages (SPL).
2.Version: Every change is tracked via GitHub Commits.
3.Validate: CI/CD checks for syntax and logic errors.
4. **Deploy**: Automated push to Splunk/QRadar via REST APIs.




#Coverage & Mapping
All detections are mapped to the **MITRE ATT&CK Framework** to ensure comprehensive visibility across the attack lifecycle.

# Splunk (15 Rules)
--Log Sources: WinEventLog (Security, System), Sysmon, Network Traffic.
--Focus: Privilege Escalation, Credential Access, Defense Evasion.
--Languages: SPL (Search Processing Language).




 🛠️ Repository Structure
```text
├── .github/workflows/
│   └── deploy_rules.yml    # GitHub Actions for API Sync
├── splunk/
│   ├── security/           # High-severity alerts
│   └── audit/              # Compliance-related rules
└── scripts/
    └── siem_api_sync.py    # Python engine for SIEM integration
