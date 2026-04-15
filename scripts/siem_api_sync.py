import os
import glob
import requests
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Fayl yolları
QRADAR_PATH = "qradar/aql_queries/*.json"
SPLUNK_PATH = "splunk/security/*.spl"

def sync_qradar():
    print("--- 🔵 QRadar API Sync Başladı ---")
    host = os.environ.get('QRADAR_URL')
    token = os.environ.get('QRADAR_TOKEN')

    if not host or not token:
        print(f"❌ Xəta: QRadar məlumatları çatışmır!")
        return

    files = glob.glob(QRADAR_PATH)
    headers = {
        "SEC": token, 
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Version": "17.0"
    }

    for file_path in files:
        try:
            with open(file_path, 'r') as f:
                rule_data = json.load(f)
            
            rule_name = rule_data.get('name', os.path.basename(file_path))
            url = f"https://{host}/api/analytics/rules"
            
            # 1. Mövcud qaydanı axtar (Duplicate olmasın deyə)
            search_url = f"{url}?filter=name%3D%22{rule_name}%22"
            existing = requests.get(search_url, headers=headers, verify=False).json()

            if existing:
                rule_id = existing[0]['id']
                # UPDATE (POST ilə həyata keçirilir)
                response = requests.post(f"{url}/{rule_id}", headers=headers, json=rule_data, verify=False)
                action = "UPDATED"
            else:
                # CREATE
                response = requests.post(url, headers=headers, json=rule_data, verify=False)
                action = "CREATED"

            print(f"Rule: {rule_name} | Action: {action} | Status: {response.status_code}")
            
            # Əgər uğursuz olarsa, cavabı çap et
            if response.status_code not in [200, 201]:
                print(f"⚠️ Detallar: {response.text}")

        except Exception as e:
            print(f"❌ {file_path} xətası: {e}")

def sync_splunk():
    print("\n--- 🟢 Splunk API Sync Başladı ---")
    host = os.environ.get('SPLUNK_URL')
    token = os.environ.get('SPLUNK_TOKEN')

    if not host or not token:
        print(f"❌ Xəta: Splunk məlumatları çatışmır!")
        return

    files = glob.glob(SPLUNK_PATH)
    headers = {"Authorization": f"Bearer {token}"}

    for file_path in files:
        try:
            with open(file_path, 'r') as f:
                query = f.read()
            
            rule_name = os.path.basename(file_path).split('.')[0]
            url = f"https://{host}:8089/servicesNS/admin/search/saved/searches"
            
            data = {
                "name": rule_name,
                "search": query,
                "is_scheduled": 1,
                "cron_schedule": "*/5 * * * *",
                "alert_type": "number of events",
                "alert_comparator": "greater than",
                "alert_threshold": 0
            }
            
            response = requests.post(url, headers=headers, data=data, verify=False)
            
            if response.status_code == 409:
                requests.post(f"{url}/{rule_name}", headers=headers, data=data, verify=False)
                print(f"Alert: {rule_name} | Status: Updated")
            else:
                print(f"Alert: {rule_name} | Status: {response.status_code}")
        except Exception as e:
            print(f"❌ {file_path} xətası: {e}")

if __name__ == "__main__":
    sync_qradar()
    sync_splunk()
