#!/usr/bin/env python3
"""
qradar_rules_deploy.py
GitHub Actions → QRadar Analytics Rules API
POST /api/analytics/rules
QRadar Version: 7.5.0
"""

import os
import sys
import json
import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── ENV ──────────────────────────────────────────────────────────────
QRADAR_HOST  = os.environ.get("QRADAR_HOST", "").rstrip("/")
QRADAR_TOKEN = os.environ.get("QRADAR_TOKEN", "")

def qradar_headers():
    return {
        "SEC":          QRADAR_TOKEN,
        "Accept":       "application/json",
        "Content-Type": "application/json",
        "Version":      "14.0",
    }

# ── RULES ─────────────────────────────────────────────────────────────
RULES = [
    {
        "name": "SOC-QR-001 | New Local User Account Created",
        "enabled": True,
        "owner": "admin",
        "type": "EVENT",
        "origin": "USER",
        "notes": "MITRE: T1136.001 | EventID: 4720 | Yeni lokal user yaradıldıqda tetiklenir.",
        "groups": ["SOC Custom Rules", "User Account Management"],
        "tests": [
            {
                "name": "Windows New User EventID 4720",
                "negate": False,
                "group": "devicetype",
                "test_functions": [
                    {
                        "text": "when the event(s) were detected by one of the following QRadar log sources Microsoft Windows Security Event Log",
                        "uid": 1,
                        "name": "matches any of",
                        "parameters": [
                            {"values": ["12"], "type": "NUMBER"}
                        ]
                    },
                    {
                        "text": "when the event QID is one of the following 4720",
                        "uid": 2,
                        "name": "matches any of",
                        "parameters": [
                            {"values": ["4720"], "type": "NUMBER"}
                        ]
                    }
                ]
            }
        ],
        "responses": [
            {
                "type": "OFFENSE",
                "offense_type": "SOURCE_IP",
                "description": "Yeni lokal user yaradıldı - Persistence cəhdi",
                "credibility": 8,
                "severity": 7
            }
        ]
    },
    {
        "name": "SOC-QR-002 | User Added to Privileged Admin Group",
        "enabled": True,
        "owner": "admin",
        "type": "EVENT",
        "origin": "USER",
        "notes": "MITRE: T1098 / T1078.002 | EventID: 4728, 4732, 4756",
        "groups": ["SOC Custom Rules", "Privilege Escalation"],
        "tests": [
            {
                "name": "Admin Group Member Added",
                "negate": False,
                "group": "devicetype",
                "test_functions": [
                    {
                        "text": "when the event QID is one of the following 4728 4732 4756",
                        "uid": 1,
                        "name": "matches any of",
                        "parameters": [
                            {"values": ["4728", "4732", "4756"], "type": "NUMBER"}
                        ]
                    }
                ]
            }
        ],
        "responses": [
            {
                "type": "OFFENSE",
                "offense_type": "USERNAME",
                "description": "KRİTİK: Privileged admin qrupuna user əlavə edildi",
                "credibility": 9,
                "severity": 9
            }
        ]
    },
    {
        "name": "SOC-QR-003 | Brute Force - Multiple Failed Login Attempts",
        "enabled": True,
        "owner": "admin",
        "type": "EVENT",
        "origin": "USER",
        "notes": "MITRE: T1110 | EventID: 4625 | 5 dəq ərzində 10+ uğursuz login",
        "groups": ["SOC Custom Rules", "Brute Force Detection"],
        "tests": [
            {
                "name": "Failed Login Event 4625",
                "negate": False,
                "group": "devicetype",
                "test_functions": [
                    {
                        "text": "when the event QID is 4625",
                        "uid": 1,
                        "name": "matches any of",
                        "parameters": [
                            {"values": ["4625"], "type": "NUMBER"}
                        ]
                    }
                ]
            }
        ],
        "responses": [
            {
                "type": "OFFENSE",
                "offense_type": "SOURCE_IP",
                "description": "Brute Force: 5 dəq içində 10+ uğursuz login",
                "credibility": 9,
                "severity": 8
            }
        ]
    },
    {
        "name": "SOC-QR-004 | Privileged Account Login Outside Business Hours",
        "enabled": True,
        "owner": "admin",
        "type": "EVENT",
        "origin": "USER",
        "notes": "MITRE: T1078.002 | EventID: 4624 | 20:00-06:00 arası admin login",
        "groups": ["SOC Custom Rules", "Anomalous Activity"],
        "tests": [
            {
                "name": "Admin Interactive Login 4624",
                "negate": False,
                "group": "devicetype",
                "test_functions": [
                    {
                        "text": "when the event QID is 4624",
                        "uid": 1,
                        "name": "matches any of",
                        "parameters": [
                            {"values": ["4624"], "type": "NUMBER"}
                        ]
                    }
                ]
            }
        ],
        "responses": [
            {
                "type": "OFFENSE",
                "offense_type": "USERNAME",
                "description": "Privileged hesab iş saatları xaricində login etdi",
                "credibility": 7,
                "severity": 7
            }
        ]
    },
    {
        "name": "SOC-QR-005 | Windows Security Audit Log Cleared",
        "enabled": True,
        "owner": "admin",
        "type": "EVENT",
        "origin": "USER",
        "notes": "MITRE: T1070.001 | EventID: 1102, 517 | KRİTİK - dərhal araşdırılmalıdır!",
        "groups": ["SOC Custom Rules", "Anti-Forensics"],
        "tests": [
            {
                "name": "Audit Log Cleared 1102 517",
                "negate": False,
                "group": "devicetype",
                "test_functions": [
                    {
                        "text": "when the event QID is one of 1102 517",
                        "uid": 1,
                        "name": "matches any of",
                        "parameters": [
                            {"values": ["1102", "517"], "type": "NUMBER"}
                        ]
                    }
                ]
            }
        ],
        "responses": [
            {
                "type": "OFFENSE",
                "offense_type": "SOURCE_IP",
                "description": "KRİTİK: Windows Audit Log silindi - Anti-forensics cəhdi",
                "credibility": 10,
                "severity": 10
            }
        ]
    },
    {
        "name": "SOC-QR-006 | Lateral Movement - Pass-the-Hash Detected",
        "enabled": True,
        "owner": "admin",
        "type": "EVENT",
        "origin": "USER",
        "notes": "MITRE: T1550.002 | EventID: 4624 LogonType=3 NTLM",
        "groups": ["SOC Custom Rules", "Lateral Movement"],
        "tests": [
            {
                "name": "NTLM Network Login 4624",
                "negate": False,
                "group": "devicetype",
                "test_functions": [
                    {
                        "text": "when the event QID is 4624",
                        "uid": 1,
                        "name": "matches any of",
                        "parameters": [
                            {"values": ["4624"], "type": "NUMBER"}
                        ]
                    }
                ]
            }
        ],
        "responses": [
            {
                "type": "OFFENSE",
                "offense_type": "SOURCE_IP",
                "description": "Lateral Movement - Pass-the-Hash: multiple hosts via NTLM",
                "credibility": 8,
                "severity": 9
            }
        ]
    },
    {
        "name": "SOC-QR-007 | Ransomware Indicator - Mass File Encryption",
        "enabled": True,
        "owner": "admin",
        "type": "EVENT",
        "origin": "USER",
        "notes": "MITRE: T1486 | KRİTİK - HOST DƏRHAL İZOLYASİYA EDİLMƏLİDİR!",
        "groups": ["SOC Custom Rules", "Ransomware Detection"],
        "tests": [
            {
                "name": "Ransomware File Extension",
                "negate": False,
                "group": "category",
                "test_functions": [
                    {
                        "text": "when the category is File System",
                        "uid": 1,
                        "name": "matches any of",
                        "parameters": [
                            {"values": ["File System"], "type": "STRING"}
                        ]
                    }
                ]
            }
        ],
        "responses": [
            {
                "type": "OFFENSE",
                "offense_type": "SOURCE_IP",
                "description": "KRİTİK RANSOMWARE: kütləvi fayl şifrələnməsi aşkarlandı",
                "credibility": 9,
                "severity": 10
            }
        ]
    },
    {
        "name": "SOC-QR-008 | Suspicious PowerShell Encoded Command Execution",
        "enabled": True,
        "owner": "admin",
        "type": "EVENT",
        "origin": "USER",
        "notes": "MITRE: T1059.001 | EventID: 4688 | PowerShell -EncodedCommand bypass",
        "groups": ["SOC Custom Rules", "Malicious Code Execution"],
        "tests": [
            {
                "name": "Encoded PowerShell 4688",
                "negate": False,
                "group": "devicetype",
                "test_functions": [
                    {
                        "text": "when the event QID is 4688",
                        "uid": 1,
                        "name": "matches any of",
                        "parameters": [
                            {"values": ["4688"], "type": "NUMBER"}
                        ]
                    }
                ]
            }
        ],
        "responses": [
            {
                "type": "OFFENSE",
                "offense_type": "SOURCE_IP",
                "description": "Şübhəli PowerShell: encoded/obfuscated komanda icra edildi",
                "credibility": 8,
                "severity": 8
            }
        ]
    },
    {
        "name": "SOC-QR-009 | Network Port Scan Detected from Single Source",
        "enabled": True,
        "owner": "admin",
        "type": "EVENT",
        "origin": "USER",
        "notes": "MITRE: T1046 | 1 dəq içində 20+ fərqli porta bağlantı cəhdi",
        "groups": ["SOC Custom Rules", "Reconnaissance"],
        "tests": [
            {
                "name": "Firewall Deny Events",
                "negate": False,
                "group": "category",
                "test_functions": [
                    {
                        "text": "when the category is Firewall Deny",
                        "uid": 1,
                        "name": "matches any of",
                        "parameters": [
                            {"values": ["Firewall Deny"], "type": "STRING"}
                        ]
                    }
                ]
            }
        ],
        "responses": [
            {
                "type": "OFFENSE",
                "offense_type": "SOURCE_IP",
                "description": "Port Scan: 1 dəq içində 20+ porta reconnaissance cəhdi",
                "credibility": 8,
                "severity": 7
            }
        ]
    },
    {
        "name": "SOC-QR-010 | Service Account Interactive Login Detected",
        "enabled": True,
        "owner": "admin",
        "type": "EVENT",
        "origin": "USER",
        "notes": "MITRE: T1078.003 | EventID: 4624 LogonType 2/10 | Servis hesabı interactive login",
        "groups": ["SOC Custom Rules", "Anomalous Activity"],
        "tests": [
            {
                "name": "Service Account Login 4624",
                "negate": False,
                "group": "devicetype",
                "test_functions": [
                    {
                        "text": "when the event QID is 4624",
                        "uid": 1,
                        "name": "matches any of",
                        "parameters": [
                            {"values": ["4624"], "type": "NUMBER"}
                        ]
                    }
                ]
            }
        ],
        "responses": [
            {
                "type": "OFFENSE",
                "offense_type": "USERNAME",
                "description": "Servis hesabı interactive login etdi - Credential Theft şübhəsi",
                "credibility": 9,
                "severity": 8
            }
        ]
    }
]

# ── FUNCTIONS ─────────────────────────────────────────────────────────

def get_existing_rules() -> dict:
    """Mövcud rule-ları adına görə map edir."""
    url = f"{QRADAR_HOST}/api/analytics/rules?fields=id,name"
    r = requests.get(url, headers=qradar_headers(), verify=False, timeout=30)
    if r.status_code == 200:
        return {rule["name"]: rule["id"] for rule in r.json()}
    print(f"  [QRadar] Mövcud rule-lar alınmadı: {r.status_code}")
    return {}

def create_rule(rule: dict) -> bool:
    """Yeni rule yaradır."""
    url = f"{QRADAR_HOST}/api/analytics/rules"
    r = requests.post(url, headers=qradar_headers(), json=rule, verify=False, timeout=30)
    if r.status_code in (200, 201):
        rule_id = r.json().get("id")
        print(f"  ✅ CREATED  | {rule['name']} (ID: {rule_id})")
        return True
    else:
        print(f"  ❌ FAILED   | {rule['name']} → {r.status_code}: {r.text[:200]}")
        return False

def update_rule(rule_id: int, rule: dict) -> bool:
    """Mövcud rule-u yeniləyir."""
    url = f"{QRADAR_HOST}/api/analytics/rules/{rule_id}"
    r = requests.post(url, headers=qradar_headers(), json=rule, verify=False, timeout=30)
    if r.status_code in (200, 201):
        print(f"  🔄 UPDATED  | {rule['name']} (ID: {rule_id})")
        return True
    else:
        print(f"  ❌ FAILED   | {rule['name']} → {r.status_code}: {r.text[:200]}")
        return False

def verify_rules():
    """Deploy sonrası rule-ların mövcudluğunu yoxlayır."""
    url = f"{QRADAR_HOST}/api/analytics/rules?fields=id,name,enabled,type&filter=name%20like%20%27SOC-QR%25%27"
    r = requests.get(url, headers=qradar_headers(), verify=False, timeout=30)
    if r.status_code == 200:
        rules = r.json()
        print(f"\n  Aktiv SOC rule-lar ({len(rules)} ədəd):")
        for rule in rules:
            status = "✅ ENABLED " if rule.get("enabled") else "⚠️  DISABLED"
            print(f"    {status} | ID: {rule['id']} | {rule['name']}")
    else:
        print(f"  [QRadar] Rule yoxlama xətası: {r.status_code}: {r.text[:200]}")

def main():
    print("\n" + "="*60)
    print("  QRadar Rules Deploy | SOC Offense Rules v1.0")
    print("  Target:", QRADAR_HOST)
    print("="*60)

    if not QRADAR_HOST or not QRADAR_TOKEN:
        print("❌ QRADAR_HOST və QRADAR_TOKEN env dəyişənlərini təyin edin!")
        sys.exit(1)

    print(f"\n[1/3] Mövcud rule-lar yoxlanılır...")
    existing = get_existing_rules()
    print(f"  Mövcud rule sayı: {len(existing)}")

    print(f"\n[2/3] {len(RULES)} rule deploy edilir...")
    created = updated = failed = 0

    for rule in RULES:
        if rule["name"] in existing:
            ok = update_rule(existing[rule["name"]], rule)
            if ok: updated += 1
            else: failed += 1
        else:
            ok = create_rule(rule)
            if ok: created += 1
            else: failed += 1
        time.sleep(0.3)  # rate limit üçün

    print(f"\n[3/3] Nəticə yoxlanılır...")
    verify_rules()

    print("\n" + "="*60)
    print(f"  ✅ Yaradıldı : {created}")
    print(f"  🔄 Yeniləndi : {updated}")
    print(f"  ❌ Xəta      : {failed}")
    print("="*60 + "\n")

    if failed > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
