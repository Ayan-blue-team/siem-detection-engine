import os
import requests
import json

# QRadar API parametrləri
API_URL = "https://18.212.3.25//api/analytics/rules"
TOKEN = "12622cc0-bc6c-4e07-becb-884ccada0deb" # Authorized Service tokeni [cite: 3]

headers = {
    "SEC": TOKEN,
    "Content-Type": "application/json",
    "Version": "12.0"
}

# Faylları oxuyub göndərmək
rules_dir = os.path.join(os.path.dirname(__file__), '..', 'rules')
for filename in os.listdir(rules_dir):
    if filename.endswith(".json"):
        with open(os.path.join(rules_dir, filename), 'r') as f:
            rule_content = json.load(f)
            response = requests.post(API_URL, headers=headers, json=rule_content, verify=False)
            print(f"{filename} yükləndi. Status: {response.status_code}")
