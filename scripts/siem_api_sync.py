# qradar/deploy_qradar.py
import requests
import json
import os
import glob

QRADAR_HOST = os.environ['QRADAR_URL']  # GitHub Secret
QRADAR_TOKEN = os.environ['QRADAR_TOKEN']  # GitHub Secret

headers = {
    'SEC': QRADAR_TOKEN,
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Version': '17.0'
}

BASE_URL = f"https://{QRADAR_HOST}/api"

def get_existing_rules():
    """Mövcud rule-ları gətir"""
    r = requests.get(f"{BASE_URL}/analytics/rules", headers=headers, verify=False)
    return {rule['name']: rule['id'] for rule in r.json()}

def create_or_update_rule(rule_data, existing_rules):
    """Rule yarat və ya güncəllə"""
    name = rule_data['name']
    if name in existing_rules:
        rule_id = existing_rules[name]
        r = requests.post(
            f"{BASE_URL}/analytics/rules/{rule_id}",
            headers=headers,
            json=rule_data,
            verify=False
        )
        print(f"✅ UPDATED: {name} (ID: {rule_id})")
    else:
        r = requests.post(
            f"{BASE_URL}/analytics/rules",
            headers=headers,
            json=rule_data,
            verify=False
        )
        print(f"✅ CREATED: {name}")
    return r.status_code

# 10 rule-u deploy et
existing = get_existing_rules()

rules = [
    {
        "name": "SIEM-RULE-001: New User Account Created",
        "type": "EVENT",
        "enabled": True,
        "owner": "admin",
        "origin": "USER",
        "base_host_id": 0,
        "average_capacity": 0,
        "capacity_timestamp": 0
    },
    # ... digər rule-lar eyni strukturda
]

for rule in rules:
    status = create_or_update_rule(rule, existing)
    if status not in [200, 201]:
        print(f"❌ FAILED: {rule['name']} - Status: {status}")
