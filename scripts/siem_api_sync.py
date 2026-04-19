import requests
import base64
import os
import json

# ENV dəyişənləri
GH_TOKEN      = os.environ.get("GH_TOKEN")
GH_REPO_OWNER = os.environ.get("GH_REPO_OWNER")
GH_REPO_NAME  = os.environ.get("GH_REPO_NAME")
GH_BRANCH     = os.environ.get("GH_BRANCH", "main")
QRADAR_HOST   = os.environ.get("QRADAR_HOST")
QRADAR_TOKEN  = os.environ.get("QRADAR_TOKEN")

def qradar_headers():
    return {
        "SEC": QRADAR_TOKEN,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Version": "14.0",
    }

def qradar_deploy(name, aql_text):
    # QRadar Offense yaradan payload strukturu
    rule_data = {
        "name": name,
        "type": "EVENT",
        "enabled": True,
        "origin": "USER",
        "owner": "admin",
        "rule_type": "COMMON",
        "rule_contexts": ["EV"],
        "magnitude": 5,
        "severity": 5,
        "responses": [
            {
                "type": "dispatchNewOffense",
                "parameters": [
                    { "name": "offenseName", "value": f"Alert: {name}" },
                    { "name": "offenseType", "value": "event" }
                ]
            }
        ],
        "text": aql_text
    }

    url = f"{QRADAR_HOST}/api/analytics/rules"
    r = requests.post(
        url, headers=qradar_headers(),
        json=rule_data, verify=False
    )

    if r.status_code in (200, 201):
        print(f"  [QRadar] Uğurla yaradıldı (Offense aktivdir): {name}")
    else:
        print(f"  [QRadar] XƏTA {r.status_code}: {name} - {r.text[:300]}")

# ... (Digər funksiyalarınız olduğu kimi qalır)
